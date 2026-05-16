// Package hubcorrelate is the multi-host alert correlator that
// runs on `xhub`. It turns per-host alerts into fleet-wide
// signals — "this domain was newly contacted by 17 hosts in the
// last hour" tells the operator something a single-host alert
// stream never could.
//
// Data model:
//
//   Hosts push (host_id, rule_id, key, time) tuples. The key is
//   whatever the host has already aggregated to — a domain, an
//   exe SHA, a destination ASN, a rule fingerprint. The correlator
//   buckets by (rule_id, key) and fires a Cluster event when the
//   distinct-host count in a sliding window crosses a per-rule
//   threshold.
//
// Three canonical signal shapes the host emits:
//
//   - rule_id="domain.newly_contacted", key=<registrable root>
//   - rule_id="exe.first_seen",         key=<exe_sha256>
//   - rule_id="rule.fired",             key=<rule_id_from_host>
//
// The correlator itself is rule-agnostic: any (rule_id, key) the
// hub receives is bucketed. Threshold + window are per-rule via
// SetRulePolicy.
//
// Pure-Go, goroutine-safe, deterministic for replay. No external
// dependencies.
package hubcorrelate

import (
	"sort"
	"sync"
	"time"
)

// DefaultWindow — when no per-rule policy is set.
const DefaultWindow = 1 * time.Hour

// DefaultThreshold — when no per-rule policy is set.
const DefaultThreshold = 5

// Observation is one host-side alert tuple.
type Observation struct {
	HostID string
	RuleID string
	Key    string
	At     time.Time
	// Reason is the host's free-form reason string (carried
	// through into the resulting Cluster for the analyst UI).
	Reason string
}

// Cluster is the engine output — a fired multi-host correlation.
type Cluster struct {
	RuleID       string
	Key          string
	FirstSeen    time.Time
	LastSeen     time.Time
	HostCount    int
	Hosts        []string // sorted, distinct
	Observations int
	SampleReason string // one of the contributing reasons
}

// Policy parameterises a single rule's correlation behaviour.
type Policy struct {
	Window    time.Duration
	Threshold int
	// MaxHostsTracked caps memory growth — once exceeded, the
	// engine still counts but stops storing host IDs. <=0 uses 1024.
	MaxHostsTracked int
}

// Engine is the correlator.
type Engine struct {
	defaultPolicy Policy

	mu       sync.Mutex
	rulePolicy map[string]Policy
	buckets  map[bucketKey]*bucket
	fired    map[bucketKey]time.Time // last fire time, for re-fire damper
	now      func() time.Time
}

type bucketKey struct {
	ruleID, key string
}

type bucket struct {
	first       time.Time
	last        time.Time
	hosts       map[string]struct{}
	hostList    []string // bounded by MaxHostsTracked
	obsCount    int
	sampleRsn   string
}

// New returns an Engine with sensible defaults.
func New() *Engine {
	return &Engine{
		defaultPolicy: Policy{Window: DefaultWindow, Threshold: DefaultThreshold, MaxHostsTracked: 1024},
		rulePolicy:    map[string]Policy{},
		buckets:       map[bucketKey]*bucket{},
		fired:         map[bucketKey]time.Time{},
		now:           time.Now,
	}
}

// SetDefaultPolicy replaces the policy used when a rule has no
// specific policy.
func (e *Engine) SetDefaultPolicy(p Policy) {
	if p.Window <= 0 {
		p.Window = DefaultWindow
	}
	if p.Threshold <= 0 {
		p.Threshold = DefaultThreshold
	}
	if p.MaxHostsTracked <= 0 {
		p.MaxHostsTracked = 1024
	}
	e.mu.Lock()
	e.defaultPolicy = p
	e.mu.Unlock()
}

// SetRulePolicy registers a per-rule override.
func (e *Engine) SetRulePolicy(ruleID string, p Policy) {
	if ruleID == "" {
		return
	}
	if p.Window <= 0 {
		p.Window = DefaultWindow
	}
	if p.Threshold <= 0 {
		p.Threshold = DefaultThreshold
	}
	if p.MaxHostsTracked <= 0 {
		p.MaxHostsTracked = 1024
	}
	e.mu.Lock()
	e.rulePolicy[ruleID] = p
	e.mu.Unlock()
}

// Observe ingests one Observation. Returns a non-nil *Cluster when
// the observation pushed the bucket across its threshold for the
// first time within the window.
func (e *Engine) Observe(o Observation) *Cluster {
	if o.HostID == "" || o.RuleID == "" || o.Key == "" {
		return nil
	}
	now := o.At
	if now.IsZero() {
		now = e.now()
	}
	key := bucketKey{ruleID: o.RuleID, key: o.Key}
	pol := e.policyFor(o.RuleID)
	cutoff := now.Add(-pol.Window)

	e.mu.Lock()
	defer e.mu.Unlock()

	b, ok := e.buckets[key]
	if !ok {
		b = &bucket{hosts: map[string]struct{}{}, first: now}
		e.buckets[key] = b
	}
	// Evict if the bucket's first sample is now outside the window —
	// reset and start fresh.
	if b.first.Before(cutoff) {
		b.hosts = map[string]struct{}{}
		b.hostList = b.hostList[:0]
		b.obsCount = 0
		b.first = now
		b.sampleRsn = ""
	}
	b.last = now
	if _, seen := b.hosts[o.HostID]; !seen {
		b.hosts[o.HostID] = struct{}{}
		if len(b.hostList) < pol.MaxHostsTracked {
			b.hostList = append(b.hostList, o.HostID)
		}
	}
	b.obsCount++
	if b.sampleRsn == "" && o.Reason != "" {
		b.sampleRsn = o.Reason
	}

	if len(b.hosts) < pol.Threshold {
		return nil
	}
	// Re-fire damper: don't fire more than once per Window for the
	// same bucket. Operators can still see the bucket continue to
	// grow via Snapshot().
	if last, prior := e.fired[key]; prior && now.Sub(last) < pol.Window {
		return nil
	}
	e.fired[key] = now
	cp := *b
	cp.hosts = nil // don't leak the internal map
	hosts := append([]string(nil), b.hostList...)
	sort.Strings(hosts)
	return &Cluster{
		RuleID:       o.RuleID,
		Key:          o.Key,
		FirstSeen:    cp.first,
		LastSeen:     cp.last,
		HostCount:    len(b.hosts),
		Hosts:        hosts,
		Observations: cp.obsCount,
		SampleReason: cp.sampleRsn,
	}
}

// Sweep evicts buckets whose last sample is older than the
// per-rule window. Returns the count of buckets removed.
func (e *Engine) Sweep(now time.Time) int {
	if now.IsZero() {
		now = e.now()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	removed := 0
	for k, b := range e.buckets {
		pol := e.policyFor(k.ruleID)
		if b.last.Before(now.Add(-pol.Window)) {
			delete(e.buckets, k)
			delete(e.fired, k)
			removed++
		}
	}
	return removed
}

// Snapshot returns all currently-active buckets as Cluster
// records (whether or not they've fired). Sorted by HostCount
// desc, then by RuleID, then by Key.
func (e *Engine) Snapshot() []Cluster {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Cluster, 0, len(e.buckets))
	for k, b := range e.buckets {
		hosts := append([]string(nil), b.hostList...)
		sort.Strings(hosts)
		out = append(out, Cluster{
			RuleID:       k.ruleID,
			Key:          k.key,
			FirstSeen:    b.first,
			LastSeen:     b.last,
			HostCount:    len(b.hosts),
			Hosts:        hosts,
			Observations: b.obsCount,
			SampleReason: b.sampleRsn,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].HostCount != out[j].HostCount {
			return out[i].HostCount > out[j].HostCount
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// Top returns the n hottest buckets (highest distinct-host count).
func (e *Engine) Top(n int) []Cluster {
	if n <= 0 {
		return nil
	}
	s := e.Snapshot()
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// Reset drops all state. Mostly useful in tests.
func (e *Engine) Reset() {
	e.mu.Lock()
	e.buckets = map[bucketKey]*bucket{}
	e.fired = map[bucketKey]time.Time{}
	e.mu.Unlock()
}

// Stats is a brief inventory for status reporting.
type Stats struct {
	Buckets int
	Fired   int
}

// Stats returns counts.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Stats{Buckets: len(e.buckets), Fired: len(e.fired)}
}

func (e *Engine) policyFor(rule string) Policy {
	if p, ok := e.rulePolicy[rule]; ok {
		return p
	}
	return e.defaultPolicy
}

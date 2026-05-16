// Package alertdedupe collapses related alerts into clusters
// and computes a time-decayed composite score per cluster.
//
// Why it exists: every working EDR has this, most OSS does not.
// Without dedupe, a single noisy beacon-pattern misclassification
// can fire 1000 alerts in an hour and analyst attention dies.
//
// Cluster key by default: (rule_id, exe_sha, dst_ip). Operators
// can configure to widen (just rule_id+exe) or narrow (add pid).
// Each rule has a weight; the cluster score is the time-decayed
// sum of its members' weights. A cluster crosses Threshold when
// the operator should be paged.
//
// Pure-Go, no I/O, no goroutines. Caller drives Observe() and
// reads back via Promote() / Buckets() at convenient cadences.
package alertdedupe

import (
	"sort"
	"sync"
	"time"
)

// Severity classifies a cluster's promoted state.
type Severity uint8

const (
	SeverityNone     Severity = 0
	SeverityInfo     Severity = 1
	SeverityNotice   Severity = 2
	SeverityWarn     Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

// String returns a stable lowercase token.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityNotice:
		return "notice"
	case SeverityWarn:
		return "warn"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "none"
}

// Alert is the input — one rule firing.
type Alert struct {
	At      time.Time
	RuleID  string
	Weight  float64 // intrinsic rule weight; if 0, Engine.DefaultWeight
	PID     uint32
	Exe     string
	ExeSHA  string
	DstIP   string
	DstPort uint16
	Reason  string
	Tags    map[string]string
}

// Cluster is an aggregated group of related alerts.
type Cluster struct {
	Key       string
	RuleID    string
	Exe       string
	ExeSHA    string
	DstIP     string
	DstPort   uint16
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int
	Score     float64
	Severity  Severity
	// Sample reasons up to N most recent (kept for the UI hover).
	Reasons []string
}

// Engine is the dedupe + scoring core.
type Engine struct {
	// DecayHalfLife — how long for one alert's contribution to
	// halve. <=0 selects 5 minutes.
	DecayHalfLife time.Duration

	// WindowDrop — discard clusters with no new alerts older than
	// this. <=0 selects 1 hour.
	WindowDrop time.Duration

	// MaxReasons — bounded sample. <=0 selects 5.
	MaxReasons int

	// DefaultWeight when Alert.Weight is 0. <=0 selects 1.0.
	DefaultWeight float64

	// Thresholds maps the cluster Score → Severity. Sorted by
	// Score ascending. Default: 1→info, 5→notice, 15→warn,
	// 40→high, 80→critical.
	Thresholds []Threshold

	// KeyFunc lets operators override the cluster-key recipe.
	// Default: rule_id + exe_sha + dst_ip.
	KeyFunc func(Alert) string

	mu       sync.Mutex
	clusters map[string]*Cluster
	now      func() time.Time
}

// Threshold pairs a Score cutoff with the Severity bucket.
type Threshold struct {
	Score    float64
	Severity Severity
}

// NewEngine builds an Engine with default tuning. Field overrides
// are applied to the returned pointer; defaults fill in zero values.
func NewEngine() *Engine {
	return &Engine{
		DecayHalfLife: 5 * time.Minute,
		WindowDrop:    time.Hour,
		MaxReasons:    5,
		DefaultWeight: 1.0,
		Thresholds: []Threshold{
			{1, SeverityInfo},
			{5, SeverityNotice},
			{15, SeverityWarn},
			{40, SeverityHigh},
			{80, SeverityCritical},
		},
		clusters: make(map[string]*Cluster, 128),
		now:      time.Now,
	}
}

// Observe ingests one alert and returns the cluster it landed in
// (always non-nil, fields up to date as of `now`).
func (e *Engine) Observe(a Alert) *Cluster {
	e.mu.Lock()
	defer e.mu.Unlock()

	if a.At.IsZero() {
		a.At = e.nowFn()()
	}
	w := a.Weight
	if w <= 0 {
		w = e.DefaultWeight
		if w <= 0 {
			w = 1.0
		}
	}
	keyFn := e.KeyFunc
	if keyFn == nil {
		keyFn = defaultKey
	}
	key := keyFn(a)

	c, ok := e.clusters[key]
	if !ok {
		c = &Cluster{
			Key:       key,
			RuleID:    a.RuleID,
			Exe:       a.Exe,
			ExeSHA:    a.ExeSHA,
			DstIP:     a.DstIP,
			DstPort:   a.DstPort,
			FirstSeen: a.At,
		}
		e.clusters[key] = c
	}

	// Decay the existing score forward to a.At, then add w.
	c.Score = decay(c.Score, c.LastSeen, a.At, e.halflife()) + w
	c.LastSeen = a.At
	c.Count++
	c.Severity = e.severityFor(c.Score)
	if a.Reason != "" {
		maxR := e.MaxReasons
		if maxR <= 0 {
			maxR = 5
		}
		// Keep last-N — prepend, trim tail.
		c.Reasons = append([]string{a.Reason}, c.Reasons...)
		if len(c.Reasons) > maxR {
			c.Reasons = c.Reasons[:maxR]
		}
	}
	cp := *c
	return &cp
}

// Promote returns all clusters whose current decayed Score puts
// them at severity >= min. Clusters older than WindowDrop are
// dropped first.
func (e *Engine) Promote(now time.Time, min Severity) []Cluster {
	e.mu.Lock()
	defer e.mu.Unlock()
	if now.IsZero() {
		now = e.nowFn()()
	}
	e.dropStaleLocked(now)

	out := make([]Cluster, 0, len(e.clusters))
	for _, c := range e.clusters {
		dec := decay(c.Score, c.LastSeen, now, e.halflife())
		sev := e.severityFor(dec)
		if sev >= min {
			cp := *c
			cp.Score = dec
			cp.Severity = sev
			out = append(out, cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// Buckets returns clusters grouped by Severity. Useful for UI.
func (e *Engine) Buckets(now time.Time) map[Severity][]Cluster {
	out := map[Severity][]Cluster{}
	for _, c := range e.Promote(now, SeverityNone) {
		out[c.Severity] = append(out[c.Severity], c)
	}
	return out
}

// Reset clears all clusters. Mostly useful in tests.
func (e *Engine) Reset() {
	e.mu.Lock()
	e.clusters = make(map[string]*Cluster, 128)
	e.mu.Unlock()
}

// ── internals ──────────────────────────────────────────────────

func (e *Engine) halflife() time.Duration {
	if e.DecayHalfLife > 0 {
		return e.DecayHalfLife
	}
	return 5 * time.Minute
}

func (e *Engine) severityFor(score float64) Severity {
	sev := SeverityNone
	for _, t := range e.Thresholds {
		if score >= t.Score {
			sev = t.Severity
		}
	}
	return sev
}

func (e *Engine) dropStaleLocked(now time.Time) {
	w := e.WindowDrop
	if w <= 0 {
		w = time.Hour
	}
	for k, c := range e.clusters {
		if now.Sub(c.LastSeen) > w {
			delete(e.clusters, k)
		}
	}
}

func (e *Engine) nowFn() func() time.Time {
	if e.now != nil {
		return e.now
	}
	return time.Now
}

// defaultKey: rule_id|exe_sha|dst_ip.
func defaultKey(a Alert) string {
	sha := a.ExeSHA
	if sha == "" {
		sha = a.Exe
	}
	return a.RuleID + "|" + sha + "|" + a.DstIP
}

// decay halves score every half-life. Pure-arithmetic
// implementation avoids math.Exp for stable cross-platform output.
func decay(score float64, lastSeen, now time.Time, halflife time.Duration) float64 {
	if score == 0 || lastSeen.IsZero() {
		return score
	}
	dt := now.Sub(lastSeen)
	if dt <= 0 || halflife <= 0 {
		return score
	}
	// Half-life formula: score * 0.5^(dt/halflife).
	// We approximate via successive halvings + linear remainder,
	// adequate for alert scoring.
	halves := dt / halflife
	remainder := dt - halves*halflife
	out := score
	for i := time.Duration(0); i < halves && out > 0; i++ {
		out *= 0.5
	}
	if remainder > 0 && halflife > 0 {
		out *= (1.0 - 0.5*float64(remainder)/float64(halflife))
	}
	if out < 0 {
		out = 0
	}
	return out
}

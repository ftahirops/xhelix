// Package providers defines the pluggable verdict-source interface
// for xhelix's intel layer. Multiple providers (static blocklists,
// XGenGuardian, Quad9, NextDNS, custom HTTP) can be registered;
// the Aggregator queries them in parallel and merges according to
// a configurable policy.
//
// This package intentionally has no external dependencies and no
// I/O. Each provider lives in its own sub-package (providers/static,
// providers/xgg, etc.) and implements the Provider interface.
//
// Design constraint: Lookup must be safe to call on the connect
// hot path. Implementations are expected to be in-memory after
// warmup; cold lookups should fall back to a permissive verdict
// rather than blocking the caller.
package providers

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Class is the verdict bucket.
type Class uint8

const (
	ClassUnknown Class = 0
	ClassClean   Class = 1
	ClassAdvise  Class = 2 // suspicious but not blocked — show banner
	ClassDeny    Class = 3 // known bad — high-confidence
)

// String returns a stable lowercase token.
func (c Class) String() string {
	switch c {
	case ClassClean:
		return "clean"
	case ClassAdvise:
		return "advise"
	case ClassDeny:
		return "deny"
	}
	return "unknown"
}

// Verdict is the result of a Lookup.
type Verdict struct {
	Class    Class
	Reasons  []string  // human-readable signals contributing to the verdict
	Provider string    // name of the provider that produced this
	TTL      time.Duration
}

// Query is the input to Lookup. At least one of Domain or IP must
// be non-empty.
type Query struct {
	Domain string
	IP     string
}

// Provider is the interface every verdict source implements.
//
// Name returns a stable identifier (used in alert dedupe and in
// Verdict.Provider). Lookup must respect ctx; it must not block
// the caller for more than the configured timeout.
type Provider interface {
	Name() string
	Lookup(ctx context.Context, q Query) (Verdict, error)
}

// Weight controls aggregation. A provider with Weight=0 is
// advisory only — its verdict cannot push the aggregate above
// ClassAdvise. Default weight is 1.
type Weight uint8

// Entry binds a Provider to its weight + per-lookup timeout.
type Entry struct {
	Provider Provider
	Weight   Weight
	Timeout  time.Duration
}

// Policy controls how the Aggregator merges per-provider verdicts.
type Policy uint8

const (
	// PolicyDenyIfAny — any Provider returning ClassDeny wins.
	// Most permissive blocking policy.
	PolicyDenyIfAny Policy = 0

	// PolicyMajority — strict majority of weighted providers must
	// agree on ClassDeny for the aggregate to be ClassDeny.
	PolicyMajority Policy = 1

	// PolicyUnanimous — every provider must agree on ClassDeny.
	// Most cautious; rarely used in practice.
	PolicyUnanimous Policy = 2
)

// Aggregator queries multiple providers in parallel and merges
// their verdicts per Policy.
type Aggregator struct {
	mu      sync.RWMutex
	entries []Entry
	policy  Policy
	// Default per-lookup timeout when Entry.Timeout is zero.
	defaultTimeout time.Duration
}

// NewAggregator constructs an empty aggregator with the given
// policy. defaultTimeout < 1ms is silently raised to 200ms.
func NewAggregator(policy Policy, defaultTimeout time.Duration) *Aggregator {
	if defaultTimeout < time.Millisecond {
		defaultTimeout = 200 * time.Millisecond
	}
	return &Aggregator{policy: policy, defaultTimeout: defaultTimeout}
}

// Register adds an entry. Safe to call after Lookup; takes effect
// on the next call.
func (a *Aggregator) Register(e Entry) {
	if e.Provider == nil {
		return
	}
	if e.Weight == 0 {
		e.Weight = 1
	}
	a.mu.Lock()
	a.entries = append(a.entries, e)
	a.mu.Unlock()
}

// Names returns the names of currently-registered providers, in
// registration order.
func (a *Aggregator) Names() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, len(a.entries))
	for i, e := range a.entries {
		out[i] = e.Provider.Name()
	}
	return out
}

// Lookup queries every registered provider in parallel under the
// per-entry timeout and returns the merged Verdict plus the
// per-provider verdicts (in registration order, errors mapped to
// ClassUnknown).
func (a *Aggregator) Lookup(ctx context.Context, q Query) (Verdict, []Verdict) {
	a.mu.RLock()
	entries := make([]Entry, len(a.entries))
	copy(entries, a.entries)
	policy := a.policy
	defaultTO := a.defaultTimeout
	a.mu.RUnlock()

	if len(entries) == 0 {
		return Verdict{Class: ClassUnknown, Provider: "aggregator"}, nil
	}

	results := make([]Verdict, len(entries))
	var wg sync.WaitGroup
	for i, e := range entries {
		wg.Add(1)
		go func(i int, e Entry) {
			defer wg.Done()
			to := e.Timeout
			if to == 0 {
				to = defaultTO
			}
			cctx, cancel := context.WithTimeout(ctx, to)
			defer cancel()
			v, err := e.Provider.Lookup(cctx, q)
			if err != nil {
				results[i] = Verdict{Class: ClassUnknown, Provider: e.Provider.Name(), Reasons: []string{"lookup_error:" + err.Error()}}
				return
			}
			if v.Provider == "" {
				v.Provider = e.Provider.Name()
			}
			results[i] = v
		}(i, e)
	}
	wg.Wait()

	merged := merge(entries, results, policy)
	return merged, results
}

// merge applies the policy to per-provider verdicts.
func merge(entries []Entry, results []Verdict, policy Policy) Verdict {
	var (
		totalWeight    int
		denyWeight     int
		adviseWeight   int
		allReasons     []string
		anyDeny        bool
		allHaveAnswer  = true
	)
	for i, r := range results {
		w := int(entries[i].Weight)
		switch r.Class {
		case ClassDeny:
			anyDeny = true
			denyWeight += w
			totalWeight += w
		case ClassAdvise:
			adviseWeight += w
			totalWeight += w
		case ClassClean:
			totalWeight += w
		case ClassUnknown:
			allHaveAnswer = false
		}
		for _, reason := range r.Reasons {
			allReasons = append(allReasons, r.Provider+":"+reason)
		}
	}
	sort.Strings(allReasons)

	out := Verdict{Provider: "aggregator", Reasons: allReasons}

	switch policy {
	case PolicyDenyIfAny:
		switch {
		case anyDeny:
			out.Class = ClassDeny
		case adviseWeight > 0:
			out.Class = ClassAdvise
		case totalWeight > 0:
			out.Class = ClassClean
		default:
			out.Class = ClassUnknown
		}

	case PolicyMajority:
		switch {
		case denyWeight*2 > totalWeight && totalWeight > 0:
			out.Class = ClassDeny
		case (denyWeight+adviseWeight)*2 > totalWeight && totalWeight > 0:
			out.Class = ClassAdvise
		case totalWeight > 0:
			out.Class = ClassClean
		default:
			out.Class = ClassUnknown
		}

	case PolicyUnanimous:
		switch {
		case anyDeny && denyWeight == totalWeight && allHaveAnswer:
			out.Class = ClassDeny
		case adviseWeight > 0 || anyDeny:
			out.Class = ClassAdvise
		case totalWeight > 0:
			out.Class = ClassClean
		default:
			out.Class = ClassUnknown
		}
	}
	return out
}

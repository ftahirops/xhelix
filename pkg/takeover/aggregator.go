package takeover

import (
	"sort"
	"sync"
	"time"
)

// Aggregator keeps per-lineage rolling signal lists with TTL eviction.
// Thread-safe. One Aggregator per daemon.
//
// The TTL bounds memory and time-bounds the score: stale signals
// stop contributing. Default 30 min — long enough for multi-step
// attack chains, short enough that one transient anomaly doesn't
// haunt a lineage forever.
type Aggregator struct {
	mu       sync.Mutex
	ttl      time.Duration
	signals  map[uint64][]Signal     // by LineageID
	remoteIP map[uint64]map[string]struct{} // distinct IPs per lineage
}

// Default TTL for signals in the aggregator.
const DefaultSignalTTL = 30 * time.Minute

// NewAggregator returns an Aggregator with ttl signal retention.
// Pass 0 for DefaultSignalTTL.
func NewAggregator(ttl time.Duration) *Aggregator {
	if ttl <= 0 {
		ttl = DefaultSignalTTL
	}
	return &Aggregator{
		ttl:      ttl,
		signals:  map[uint64][]Signal{},
		remoteIP: map[uint64]map[string]struct{}{},
	}
}

// Record adds a signal to the lineage's rolling list. Stamps At if
// the caller left it zero. Evicts older-than-TTL signals
// opportunistically on each Record call (amortized; no goroutine).
func (a *Aggregator) Record(s Signal) {
	if s.At.IsZero() {
		s.At = time.Now().UTC()
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := s.At.Add(-a.ttl)
	a.signals[s.LineageID] = evictOlder(a.signals[s.LineageID], cutoff)
	a.signals[s.LineageID] = append(a.signals[s.LineageID], s)

	if s.RemoteIP != "" {
		ipset, ok := a.remoteIP[s.LineageID]
		if !ok {
			ipset = map[string]struct{}{}
			a.remoteIP[s.LineageID] = ipset
		}
		ipset[s.RemoteIP] = struct{}{}
	}
}

// Snapshot returns a copy of the live (non-expired) signals for a
// lineage at the given moment. Empty slice if no signals.
func (a *Aggregator) Snapshot(lineageID uint64, now time.Time) []Signal {
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := now.Add(-a.ttl)
	a.signals[lineageID] = evictOlder(a.signals[lineageID], cutoff)
	src := a.signals[lineageID]
	if len(src) == 0 {
		return nil
	}
	out := make([]Signal, len(src))
	copy(out, src)
	return out
}

// AttributedIPs returns the distinct remote IPs attached to signals
// for a lineage, sorted ascending. Used to populate
// decision.Input.AttributedIPs.
func (a *Aggregator) AttributedIPs(lineageID uint64) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	ipset := a.remoteIP[lineageID]
	if len(ipset) == 0 {
		return nil
	}
	out := make([]string, 0, len(ipset))
	for ip := range ipset {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// Forget drops all state for a lineage. Called when actionlog
// transitions to StateReleased or StateTerminated.
func (a *Aggregator) Forget(lineageID uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.signals, lineageID)
	delete(a.remoteIP, lineageID)
}

// Lineages returns the lineage IDs with any live signals, sorted.
// Used by the planner's tick loop.
func (a *Aggregator) Lineages(now time.Time) []uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := now.Add(-a.ttl)
	out := make([]uint64, 0, len(a.signals))
	for id, sigs := range a.signals {
		sigs = evictOlder(sigs, cutoff)
		a.signals[id] = sigs
		if len(sigs) > 0 {
			out = append(out, id)
		} else {
			delete(a.signals, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func evictOlder(sigs []Signal, cutoff time.Time) []Signal {
	if len(sigs) == 0 {
		return sigs
	}
	// Signals come in roughly time-ordered; find the first one ≥ cutoff.
	i := 0
	for ; i < len(sigs); i++ {
		if !sigs[i].At.Before(cutoff) {
			break
		}
	}
	if i == 0 {
		return sigs
	}
	// Shift remainder to front to release the head slab.
	rem := sigs[i:]
	out := make([]Signal, len(rem))
	copy(out, rem)
	return out
}

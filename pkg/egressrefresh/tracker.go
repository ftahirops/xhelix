// Package egressrefresh periodically re-resolves declared egress FQDNs and
// maintains a grace-windowed view of their IPs, so a live egress allowlist
// can be kept current without cutting in-flight connections on IP rotation
// or shrinking on a transient DNS failure (SP-1b.2b). This package applies
// nothing by itself — it computes the desired allow-set and hands it to an
// Applier (shadow LogApplier by default).
package egressrefresh

import (
	"sort"
	"sync"
	"time"
)

// Tracker holds, per unit, the last time each resolved IP CIDR was seen.
// Concurrency-safe.
type Tracker struct {
	mu    sync.Mutex
	units map[string]map[string]time.Time // unit -> cidr -> lastSeen
}

// NewTracker returns an empty Tracker.
func NewTracker() *Tracker {
	return &Tracker{units: map[string]map[string]time.Time{}}
}

// Observe records that each cidr in ips was seen for unit at now.
func (t *Tracker) Observe(unit string, ips []string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.units[unit]
	if m == nil {
		m = map[string]time.Time{}
		t.units[unit] = m
	}
	for _, ip := range ips {
		if ip != "" {
			m[ip] = now
		}
	}
}

// WithinGrace returns unit's CIDRs whose lastSeen is within grace of now,
// sorted and de-duplicated. Entries older than grace are also pruned from
// the tracker as a side effect.
func (t *Tracker) WithinGrace(unit string, now time.Time, grace time.Duration) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.units[unit]
	if m == nil {
		return nil
	}
	cutoff := now.Add(-grace)
	var out []string
	for cidr, seen := range m {
		if seen.Before(cutoff) {
			delete(m, cidr)
			continue
		}
		out = append(out, cidr)
	}
	sort.Strings(out)
	return out
}

// Forget drops a unit's state (called when a unit stops opting in).
func (t *Tracker) Forget(unit string) {
	t.mu.Lock()
	delete(t.units, unit)
	t.mu.Unlock()
}

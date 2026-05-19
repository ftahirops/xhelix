// Package budget tracks cumulative sensitivity-point totals per key
// over sliding 1-hour and 24-hour windows, plus a per-key lifetime
// total useful for ephemeral keys (e.g. "request:req-id"). It is the
// enforcement counter for the Data Leak Containment Fabric described
// in DATA_LEAK_FABRIC.md §4.
//
// Keys are opaque strings — typically structured as
// "kind:identifier" (e.g. "user:8821", "lineage:42",
// "route:/admin/export/orders"). The caller is responsible for
// composing the key; this package just counts.
//
// Per-key memory: ~11.5 KB (1440 uint64 minute buckets + scalars).
// Per Add: O(1) when within the same minute; O(60) on minute
// rollover for the hour-total recompute. Both under 1 µs in
// benchmarks.
package budget

import (
	"sync"
	"time"
)

// Caps describes the enforcement limits for a single tracked key.
// A zero value for any field disables that particular check; this
// lets a Budget enforce only the dimensions the operator cares about.
type Caps struct {
	MaxPerOperation uint64 // lifetime total since the key was first added
	MaxPerHour      uint64 // rolling 60-minute total
	MaxPerDay       uint64 // rolling 24-hour total
}

// AddResult is the outcome of a single Add call. The total fields
// reflect the cumulative state *after* the add. The Exceeded fields
// are true when the corresponding cap is set (non-zero) and the
// total has gone strictly above it.
type AddResult struct {
	OperationTotal uint64
	HourTotal      uint64
	DayTotal       uint64

	OperationExceeded bool
	HourExceeded      bool
	DayExceeded       bool
}

// AnyExceeded reports whether any configured cap was exceeded.
func (r AddResult) AnyExceeded() bool {
	return r.OperationExceeded || r.HourExceeded || r.DayExceeded
}

// Budget tracks one key's running totals.
type Budget struct {
	caps Caps

	mu             sync.Mutex
	minuteRing     [1440]uint64 // unix-minute % 1440 → points accumulated that minute
	lastMinute     int64        // unix-minute of the most-recent Add (or 0 if never)
	hourTotal      uint64       // running sum of the last 60 minute buckets
	dayTotal       uint64       // running sum of all 1440 minute buckets
	operationTotal uint64       // lifetime total since first add
	lastActivity   time.Time    // wall-clock of most recent Add, for sweeps
}

// NewBudget constructs a Budget with the given caps. The internal
// ring is zero-initialised; the first Add primes lastMinute.
func NewBudget(caps Caps) *Budget {
	return &Budget{caps: caps}
}

// Add atomically merges points into the budget and returns the
// post-add totals plus cap-exceeded flags. Safe for concurrent use.
func (b *Budget) Add(now time.Time, points uint64) AddResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	nowMin := now.Unix() / 60

	if b.lastMinute == 0 {
		b.lastMinute = nowMin
	}

	if advance := nowMin - b.lastMinute; advance > 0 {
		if advance >= 1440 {
			// Entire ring is stale.
			b.minuteRing = [1440]uint64{}
			b.hourTotal = 0
			b.dayTotal = 0
		} else {
			// Zero buckets the ring is now sweeping into (they hold
			// data from 24 h ago) and reduce dayTotal accordingly.
			for i := int64(1); i <= advance; i++ {
				idx := (b.lastMinute + i) % 1440
				b.dayTotal -= b.minuteRing[idx]
				b.minuteRing[idx] = 0
			}
			// Recompute hourTotal from scratch — only 60 iterations.
			// Cheaper and less error-prone than maintaining it
			// incrementally across rollovers.
			b.hourTotal = 0
			for i := int64(0); i < 60; i++ {
				b.hourTotal += b.minuteRing[((nowMin-i)+1440)%1440]
			}
		}
	}

	b.lastMinute = nowMin
	idx := nowMin % 1440
	b.minuteRing[idx] += points
	b.hourTotal += points
	b.dayTotal += points
	b.operationTotal += points
	b.lastActivity = now

	return AddResult{
		OperationTotal:    b.operationTotal,
		HourTotal:         b.hourTotal,
		DayTotal:          b.dayTotal,
		OperationExceeded: b.caps.MaxPerOperation > 0 && b.operationTotal > b.caps.MaxPerOperation,
		HourExceeded:      b.caps.MaxPerHour > 0 && b.hourTotal > b.caps.MaxPerHour,
		DayExceeded:       b.caps.MaxPerDay > 0 && b.dayTotal > b.caps.MaxPerDay,
	}
}

// Snapshot returns a point-in-time view of the budget without
// mutating it.
func (b *Budget) Snapshot() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Snapshot{
		Caps:           b.caps,
		OperationTotal: b.operationTotal,
		HourTotal:      b.hourTotal,
		DayTotal:       b.dayTotal,
		LastActivity:   b.lastActivity,
	}
}

// Snapshot is the immutable view returned by Budget.Snapshot.
type Snapshot struct {
	Caps           Caps      `json:"caps"`
	OperationTotal uint64    `json:"operation_total"`
	HourTotal      uint64    `json:"hour_total"`
	DayTotal       uint64    `json:"day_total"`
	LastActivity   time.Time `json:"last_activity"`
}

// Tracker maps opaque keys to Budgets. The Default caps are applied
// to any key not given an explicit Register call. Safe for concurrent
// use; the per-key path is fast (single map lookup + per-Budget mutex).
type Tracker struct {
	mu       sync.RWMutex
	budgets  map[string]*Budget
	default_ Caps
}

// NewTracker constructs an empty Tracker. defaultCaps applies to
// keys that haven't been explicitly Register'd; pass the zero value
// to make unregistered keys count-only (no enforcement).
func NewTracker(defaultCaps Caps) *Tracker {
	return &Tracker{
		budgets:  make(map[string]*Budget),
		default_: defaultCaps,
	}
}

// Register associates explicit caps with a key. Replaces any existing
// budget for that key (the running totals are reset). Typically
// called from configuration load.
func (t *Tracker) Register(key string, caps Caps) {
	t.mu.Lock()
	t.budgets[key] = NewBudget(caps)
	t.mu.Unlock()
}

// Add merges points into the budget for key, creating it on first
// reference using the Tracker's default caps. Returns the post-add
// totals and exceeded flags.
func (t *Tracker) Add(now time.Time, key string, points uint64) AddResult {
	t.mu.RLock()
	b, ok := t.budgets[key]
	t.mu.RUnlock()
	if !ok {
		// Upgrade to write lock and recheck.
		t.mu.Lock()
		b, ok = t.budgets[key]
		if !ok {
			b = NewBudget(t.default_)
			t.budgets[key] = b
		}
		t.mu.Unlock()
	}
	return b.Add(now, points)
}

// Snapshot returns a copy of the named key's snapshot, plus ok=false
// if no budget exists for that key.
func (t *Tracker) Snapshot(key string) (Snapshot, bool) {
	t.mu.RLock()
	b, ok := t.budgets[key]
	t.mu.RUnlock()
	if !ok {
		return Snapshot{}, false
	}
	return b.Snapshot(), true
}

// Drop removes the budget for a key. Used at the end of an ephemeral
// scope (e.g. when an HTTP request completes and its per-request
// budget is no longer relevant).
func (t *Tracker) Drop(key string) {
	t.mu.Lock()
	delete(t.budgets, key)
	t.mu.Unlock()
}

// SweepInactive drops budgets whose last activity is older than
// cutoff. Returns the number removed. Bounds memory in long-running
// daemons.
func (t *Tracker) SweepInactive(cutoff time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for k, b := range t.budgets {
		// Inspect lastActivity through the budget's own lock to
		// avoid a torn read on a 64-bit time value.
		b.mu.Lock()
		la := b.lastActivity
		b.mu.Unlock()
		if !la.IsZero() && la.Before(cutoff) {
			delete(t.budgets, k)
			n++
		}
	}
	return n
}

// Size returns the number of tracked keys.
func (t *Tracker) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.budgets)
}

// Keys returns a snapshot of the currently tracked keys, in
// arbitrary order. Useful for the LocalAPI surface.
func (t *Tracker) Keys() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, 0, len(t.budgets))
	for k := range t.budgets {
		out = append(out, k)
	}
	return out
}

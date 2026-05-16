// Package firerate is a per-rule sliding-window counter. Each
// Increment(rule_id) adds one fire to the current bucket; Rate
// returns fires-per-second over the configured window. Snapshot
// returns all rule rates sorted by rate descending.
//
// Why a sliding window rather than a simple counter: the operator
// surface that needs this — "which rules are noisy right now?" —
// must reflect recent activity, not historical sum. A static
// counter says rule X fired a million times; the operator wants
// "rule X is firing 40/s in the last minute, suppress it."
//
// Implementation: a per-rule ring of N buckets covering Window.
// Increment writes to the current bucket; Rate sums all buckets
// and divides by the window seconds. O(buckets) per Rate call.
// Goroutine-safe.
package firerate

import (
	"sort"
	"sync"
	"time"
)

// Tracker is the per-rule sliding-window counter.
type Tracker struct {
	window  time.Duration
	buckets int
	now     func() time.Time

	mu    sync.Mutex
	rules map[string]*counter
}

type counter struct {
	// ring holds bucket counts. Index = (timestamp/bucketDur) % buckets.
	ring     []int64
	// lastIdx is the most recently written bucket index.
	lastIdx  int
	// lastSlot is the absolute slot number for lastIdx, so we
	// know how many buckets have rotated since.
	lastSlot int64
}

// New returns a Tracker with the given window. buckets <=0 selects
// 60 (one-second resolution over a 60-second window). window <=0
// selects 60s.
func New(window time.Duration, buckets int) *Tracker {
	if window <= 0 {
		window = 60 * time.Second
	}
	if buckets <= 0 {
		buckets = 60
	}
	return &Tracker{
		window:  window,
		buckets: buckets,
		now:     time.Now,
		rules:   map[string]*counter{},
	}
}

// Increment adds one fire to the given rule's current bucket.
func (t *Tracker) Increment(ruleID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	c, ok := t.rules[ruleID]
	if !ok {
		c = &counter{ring: make([]int64, t.buckets)}
		t.rules[ruleID] = c
	}
	t.advanceLocked(c, t.now())
	c.ring[c.lastIdx]++
}

// Rate returns the current fires-per-second for ruleID, evaluated
// at `now`. Returns 0 for unknown rules.
func (t *Tracker) Rate(ruleID string) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.rules[ruleID]
	if !ok {
		return 0
	}
	t.advanceLocked(c, t.now())
	return rateOf(c.ring, t.window)
}

// Count returns the total fires in the window for ruleID.
func (t *Tracker) Count(ruleID string) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.rules[ruleID]
	if !ok {
		return 0
	}
	t.advanceLocked(c, t.now())
	var sum int64
	for _, v := range c.ring {
		sum += v
	}
	return sum
}

// Sample is one rule's current rate.
type Sample struct {
	RuleID string
	Rate   float64 // per-second
	Count  int64   // total in window
}

// Snapshot returns a Sample for every known rule, sorted by Rate
// descending (noisiest first).
func (t *Tracker) Snapshot() []Sample {
	t.mu.Lock()
	now := t.now()
	out := make([]Sample, 0, len(t.rules))
	for id, c := range t.rules {
		t.advanceLocked(c, now)
		var sum int64
		for _, v := range c.ring {
			sum += v
		}
		out = append(out, Sample{
			RuleID: id,
			Rate:   rateOf(c.ring, t.window),
			Count:  sum,
		})
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rate != out[j].Rate {
			return out[i].Rate > out[j].Rate
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// Top returns the n noisiest rules.
func (t *Tracker) Top(n int) []Sample {
	if n <= 0 {
		return nil
	}
	s := t.Snapshot()
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// Reset drops all per-rule counters. Mostly useful in tests.
func (t *Tracker) Reset() {
	t.mu.Lock()
	t.rules = map[string]*counter{}
	t.mu.Unlock()
}

// advanceLocked rotates the ring forward to `now`, zeroing buckets
// that have aged out since lastSlot.
func (t *Tracker) advanceLocked(c *counter, now time.Time) {
	bucketDur := t.window / time.Duration(t.buckets)
	if bucketDur <= 0 {
		bucketDur = time.Second
	}
	slot := now.UnixNano() / int64(bucketDur)
	if c.lastSlot == 0 {
		c.lastSlot = slot
		c.lastIdx = int(slot) % t.buckets
		if c.lastIdx < 0 {
			c.lastIdx += t.buckets
		}
		return
	}
	delta := slot - c.lastSlot
	if delta <= 0 {
		return
	}
	if delta >= int64(t.buckets) {
		// Full rotation — entire ring expires.
		for i := range c.ring {
			c.ring[i] = 0
		}
		c.lastSlot = slot
		c.lastIdx = int(slot) % t.buckets
		if c.lastIdx < 0 {
			c.lastIdx += t.buckets
		}
		return
	}
	for i := int64(1); i <= delta; i++ {
		idx := (c.lastIdx + int(i)) % t.buckets
		c.ring[idx] = 0
	}
	c.lastSlot = slot
	c.lastIdx = int(slot) % t.buckets
	if c.lastIdx < 0 {
		c.lastIdx += t.buckets
	}
}

func rateOf(ring []int64, window time.Duration) float64 {
	if window <= 0 {
		return 0
	}
	var sum int64
	for _, v := range ring {
		sum += v
	}
	return float64(sum) / window.Seconds()
}

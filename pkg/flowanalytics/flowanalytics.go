// Package flowanalytics computes per-binary fan-out and burst
// signals over a sliding window of connection observations.
//
// Two anomaly families:
//
//   - Fan-out: a binary that normally talks to 5 destinations per
//     minute suddenly talks to 200 — port scan, mass C2 dial-out,
//     supply-chain compromise pulling many new SDKs.
//   - Burst: connection rate (count, not bytes) spikes far above
//     the binary's recent average — scanning, worming, brute force.
//
// Pure-Go, goroutine-safe, sliding-window sketches. Memory bounded
// per-binary by MaxDistinct.
package flowanalytics

import (
	"sort"
	"sync"
	"time"
)

// DefaultWindow is the sliding-window horizon.
const DefaultWindow = 60 * time.Second

// DefaultMaxDistinct caps per-binary distinct destinations
// retained.
const DefaultMaxDistinct = 4096

// Tracker tracks per-binary flow statistics.
type Tracker struct {
	// Window is how long an observation contributes to the
	// fan-out / burst signal. <=0 selects DefaultWindow.
	Window time.Duration

	// MaxDistinct caps the per-binary destination set size. <=0
	// selects DefaultMaxDistinct.
	MaxDistinct int

	// FanoutMultiplier is the threshold over the rolling mean for
	// "fan-out spike." Default 5.0.
	FanoutMultiplier float64

	// BurstMultiplier is the threshold for connection-rate spike.
	// Default 5.0.
	BurstMultiplier float64

	mu       sync.Mutex
	binaries map[string]*state
	now      func() time.Time
}

// state holds one binary's rolling samples.
type state struct {
	// connections is the list of (dst, time) tuples in the window.
	connections []conn
	// distinctMeans tracks past-window distinct counts (one per
	// minute of history). Used as the fan-out baseline.
	distinctMeans []int
	// rateMeans tracks past-window connection rates (per second).
	rateMeans []float64

	lastEvictAt time.Time
}

type conn struct {
	dst  string
	when time.Time
}

// Anomaly is returned by Observe.
type Anomaly struct {
	// Distinct is the count of unique destinations in the current
	// window for this binary.
	Distinct int
	// Rate is the current connections-per-second over the window.
	Rate float64
	// FanoutBaseline / RateBaseline are the rolling means.
	FanoutBaseline float64
	RateBaseline   float64
	// Fanout / Burst flags fire when current >= baseline*multiplier.
	Fanout bool
	Burst  bool
}

// New returns a Tracker with default knobs.
func New() *Tracker {
	return &Tracker{
		Window:           DefaultWindow,
		MaxDistinct:      DefaultMaxDistinct,
		FanoutMultiplier: 5.0,
		BurstMultiplier:  5.0,
		binaries:         map[string]*state{},
		now:              time.Now,
	}
}

// Observe records one outbound connection by binary `key` to
// destination `dst`. Returns the current Anomaly snapshot.
func (t *Tracker) Observe(key, dst string) Anomaly {
	if key == "" {
		return Anomaly{}
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.binaries[key]
	if !ok {
		s = &state{}
		t.binaries[key] = s
	}

	// Evict events outside the window.
	window := t.window()
	cutoff := now.Add(-window)
	s.evictBefore(cutoff)

	// Roll the previous window's mean before adding new sample,
	// once per `window` interval.
	if now.Sub(s.lastEvictAt) >= window {
		distinct := s.distinctCount()
		rate := float64(len(s.connections)) / window.Seconds()
		s.distinctMeans = appendCapped(s.distinctMeans, distinct, 10)
		s.rateMeans = appendCappedF(s.rateMeans, rate, 10)
		s.lastEvictAt = now
	}

	// Append the new connection if it fits.
	if dst != "" && (len(s.connections) < t.maxDistinctCap()*4) {
		s.connections = append(s.connections, conn{dst: dst, when: now})
	}

	distinct := s.distinctCount()
	rate := float64(len(s.connections)) / window.Seconds()

	a := Anomaly{
		Distinct:       distinct,
		Rate:           rate,
		FanoutBaseline: meanInt(s.distinctMeans),
		RateBaseline:   meanFloat(s.rateMeans),
	}
	// Need at least 3 prior windows to have a baseline.
	if len(s.distinctMeans) >= 3 && a.FanoutBaseline > 0 &&
		float64(distinct) >= a.FanoutBaseline*t.fanoutMul() {
		a.Fanout = true
	}
	if len(s.rateMeans) >= 3 && a.RateBaseline > 0 &&
		rate >= a.RateBaseline*t.burstMul() {
		a.Burst = true
	}
	return a
}

// Snapshot returns the per-binary stats sorted by current distinct
// destination count, descending. Useful for the operator's "who's
// fanning out right now?" UI.
type Sample struct {
	Key      string
	Distinct int
	Rate     float64
}

// Snapshot returns one Sample per known binary.
func (t *Tracker) Snapshot() []Sample {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	cutoff := now.Add(-t.window())
	out := make([]Sample, 0, len(t.binaries))
	for k, s := range t.binaries {
		s.evictBefore(cutoff)
		out = append(out, Sample{
			Key:      k,
			Distinct: s.distinctCount(),
			Rate:     float64(len(s.connections)) / t.window().Seconds(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Distinct != out[j].Distinct {
			return out[i].Distinct > out[j].Distinct
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// Top returns the n binaries with the highest current fan-out.
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

// Reset clears all state. Mostly useful in tests.
func (t *Tracker) Reset() {
	t.mu.Lock()
	t.binaries = map[string]*state{}
	t.mu.Unlock()
}

// ── per-binary helpers ────────────────────────────────────────

func (s *state) evictBefore(cutoff time.Time) {
	// Linear scan; connections are appended in time order so
	// truncate at the first in-window entry.
	keep := 0
	for ; keep < len(s.connections); keep++ {
		if !s.connections[keep].when.Before(cutoff) {
			break
		}
	}
	if keep > 0 {
		s.connections = s.connections[keep:]
	}
}

func (s *state) distinctCount() int {
	seen := make(map[string]struct{}, len(s.connections))
	for _, c := range s.connections {
		seen[c.dst] = struct{}{}
	}
	return len(seen)
}

// ── tracker-level helpers ────────────────────────────────────

func (t *Tracker) window() time.Duration {
	if t.Window <= 0 {
		return DefaultWindow
	}
	return t.Window
}

func (t *Tracker) maxDistinctCap() int {
	if t.MaxDistinct <= 0 {
		return DefaultMaxDistinct
	}
	return t.MaxDistinct
}

func (t *Tracker) fanoutMul() float64 {
	if t.FanoutMultiplier <= 0 {
		return 5.0
	}
	return t.FanoutMultiplier
}

func (t *Tracker) burstMul() float64 {
	if t.BurstMultiplier <= 0 {
		return 5.0
	}
	return t.BurstMultiplier
}

func appendCapped(s []int, v, cap int) []int {
	s = append(s, v)
	if len(s) > cap {
		s = s[len(s)-cap:]
	}
	return s
}

func appendCappedF(s []float64, v float64, cap int) []float64 {
	s = append(s, v)
	if len(s) > cap {
		s = s[len(s)-cap:]
	}
	return s
}

func meanInt(s []int) float64 {
	if len(s) == 0 {
		return 0
	}
	sum := 0
	for _, v := range s {
		sum += v
	}
	return float64(sum) / float64(len(s))
}

func meanFloat(s []float64) float64 {
	if len(s) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range s {
		sum += v
	}
	return sum / float64(len(s))
}

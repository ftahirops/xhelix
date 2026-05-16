package netids

import (
	"math"
	"sync"
	"time"
)

// BeaconDetector flags low-volume periodic outbound traffic by
// computing a coefficient of variation over recent connect intervals
// per-flow. Score 0 = irregular, 1 = perfectly periodic.
type BeaconDetector struct {
	MinSamples int     // need this many before scoring (default 16)
	BeaconCV   float64 // CV below this is "very regular" (default 0.20)

	mu    sync.Mutex
	flows map[string]*flowProfile
}

type flowProfile struct {
	last      time.Time
	intervals []time.Duration
}

// NewBeaconDetector returns a detector with safe defaults.
func NewBeaconDetector() *BeaconDetector {
	return &BeaconDetector{
		MinSamples: 16,
		BeaconCV:   0.20,
		flows:      map[string]*flowProfile{},
	}
}

// Observe records a connect from src to dst at time t.
// Returns the current beacon score [0,1] for that flow. The score
// is meaningful only once MinSamples observations exist; before
// then it returns 0.
func (b *BeaconDetector) Observe(src, dst string, t time.Time) float64 {
	key := src + "->" + dst

	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.flows[key]
	if !ok {
		b.flows[key] = &flowProfile{last: t}
		return 0
	}
	delta := t.Sub(p.last)
	if delta < 0 {
		delta = 0
	}
	p.intervals = append(p.intervals, delta)
	p.last = t
	if len(p.intervals) > 64 {
		p.intervals = p.intervals[len(p.intervals)-64:]
	}
	if len(p.intervals) < b.MinSamples {
		return 0
	}
	cv := coefficientOfVariation(p.intervals)
	if cv < 0 || math.IsNaN(cv) {
		return 0
	}
	// Map CV -> score: at BeaconCV, score = 1; at 2*BeaconCV, score = 0.
	score := 1 - (cv-b.BeaconCV)/b.BeaconCV
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

// Flows returns the current number of tracked flows. Useful for
// metrics and TUI status.
func (b *BeaconDetector) Flows() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.flows)
}

// Reset drops state. Used by tests.
func (b *BeaconDetector) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flows = map[string]*flowProfile{}
}

func coefficientOfVariation(d []time.Duration) float64 {
	if len(d) == 0 {
		return 0
	}
	var sum float64
	for _, x := range d {
		sum += float64(x)
	}
	mean := sum / float64(len(d))
	if mean == 0 {
		return 0
	}
	var sq float64
	for _, x := range d {
		diff := float64(x) - mean
		sq += diff * diff
	}
	std := math.Sqrt(sq / float64(len(d)))
	return std / mean
}

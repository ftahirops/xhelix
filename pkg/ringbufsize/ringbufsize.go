// Package ringbufsize is the Go-side adaptive sizer for the eBPF
// ringbuf. The kernel-side ringbuf is allocated at load time and
// can't be resized in place, so "adaptive" here means: track drop
// rate + queue occupancy over a sliding window, recommend a new
// size, and let the loader recreate the map on rotation events.
//
// The package is pure-logic. Caller observes drops and occupancy
// each polling tick via Observe(); the Sizer reports back whether
// to grow, shrink, or hold, and what the new size should be.
//
// Pure-Go, no external deps.
package ringbufsize

import (
	"sync"
	"time"
)

// Action is what the sizer recommends on the current tick.
type Action uint8

const (
	ActionHold   Action = 0
	ActionGrow   Action = 1
	ActionShrink Action = 2
)

func (a Action) String() string {
	switch a {
	case ActionGrow:
		return "grow"
	case ActionShrink:
		return "shrink"
	}
	return "hold"
}

// Config tunes the sizer.
type Config struct {
	// MinSize is the smallest ringbuf the sizer will recommend
	// (bytes). <=0 selects 1 MB.
	MinSize uint64
	// MaxSize is the largest ringbuf the sizer will recommend
	// (bytes). <=0 selects 64 MB.
	MaxSize uint64
	// GrowFactor multiplies on grow events. <=1 selects 2.0.
	GrowFactor float64
	// ShrinkFactor divides on shrink events. <=1 selects 2.0.
	ShrinkFactor float64
	// DropRateGrow — fraction of recent samples carrying any drop.
	// Above this, sizer recommends Grow. <=0 selects 0.05 (5%).
	DropRateGrow float64
	// IdleFractionShrink — fraction of recent samples with
	// occupancy < OccupancyIdle. Above this and no drops:
	// recommend Shrink. <=0 selects 0.95.
	IdleFractionShrink float64
	// OccupancyIdle — occupancy threshold below which a sample
	// counts as "idle." Fraction 0..1. <=0 selects 0.1 (10%).
	OccupancyIdle float64
	// Window — how many recent samples to keep. <=0 selects 30.
	Window int
	// Cooldown — minimum gap between size-change recommendations.
	// <=0 selects 60 seconds.
	Cooldown time.Duration
}

// Sample is one observation point.
type Sample struct {
	At         time.Time
	Drops      uint64  // cumulative drop counter at this tick
	Occupancy  float64 // current occupancy fraction 0..1
	BufferSize uint64  // current ringbuf size in bytes
}

// Sizer maintains the recent-history window and computes
// recommendations.
type Sizer struct {
	cfg Config

	mu       sync.Mutex
	samples  []Sample
	lastDrop uint64
	lastSize uint64
	lastChange time.Time
}

// New returns a Sizer with the given config (zeros filled in).
func New(cfg Config) *Sizer {
	if cfg.MinSize == 0 {
		cfg.MinSize = 1 << 20
	}
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 64 << 20
	}
	if cfg.GrowFactor <= 1 {
		cfg.GrowFactor = 2.0
	}
	if cfg.ShrinkFactor <= 1 {
		cfg.ShrinkFactor = 2.0
	}
	if cfg.DropRateGrow <= 0 {
		cfg.DropRateGrow = 0.05
	}
	if cfg.IdleFractionShrink <= 0 {
		cfg.IdleFractionShrink = 0.95
	}
	if cfg.OccupancyIdle <= 0 {
		cfg.OccupancyIdle = 0.1
	}
	if cfg.Window <= 0 {
		cfg.Window = 30
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 60 * time.Second
	}
	return &Sizer{cfg: cfg}
}

// Recommendation is the sizer's response to an Observe call.
type Recommendation struct {
	Action     Action
	NewSize    uint64 // identical to current when Action == Hold
	Reason     string
	DropRate   float64 // fraction of recent samples with drops
	IdleFrac   float64 // fraction of recent samples below OccupancyIdle
}

// Observe ingests one sample. Returns a Recommendation that may
// be Hold (default), Grow, or Shrink. Cooldown enforces a minimum
// gap between size-change recommendations regardless of pressure.
func (s *Sizer) Observe(sample Sample) Recommendation {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lastSize == 0 {
		s.lastSize = sample.BufferSize
		s.lastDrop = sample.Drops
	}
	// Record the *delta* in drops, not the cumulative — that's
	// what gives "any drops since last tick = pressure."
	deltaDrops := uint64(0)
	if sample.Drops >= s.lastDrop {
		deltaDrops = sample.Drops - s.lastDrop
	}
	s.lastDrop = sample.Drops

	rec := Sample{
		At:         sample.At,
		Drops:      deltaDrops, // store delta
		Occupancy:  sample.Occupancy,
		BufferSize: sample.BufferSize,
	}
	s.samples = append(s.samples, rec)
	if len(s.samples) > s.cfg.Window {
		s.samples = s.samples[len(s.samples)-s.cfg.Window:]
	}

	out := Recommendation{Action: ActionHold, NewSize: sample.BufferSize}
	if len(s.samples) < s.cfg.Window/2 {
		// Not enough history yet.
		out.Reason = "warming up"
		return out
	}

	dropSamples := 0
	idleSamples := 0
	for _, sm := range s.samples {
		if sm.Drops > 0 {
			dropSamples++
		}
		if sm.Occupancy < s.cfg.OccupancyIdle {
			idleSamples++
		}
	}
	out.DropRate = float64(dropSamples) / float64(len(s.samples))
	out.IdleFrac = float64(idleSamples) / float64(len(s.samples))

	if !s.lastChange.IsZero() && sample.At.Sub(s.lastChange) < s.cfg.Cooldown {
		out.Reason = "cooldown"
		return out
	}

	switch {
	case out.DropRate >= s.cfg.DropRateGrow:
		next := uint64(float64(sample.BufferSize) * s.cfg.GrowFactor)
		if next > s.cfg.MaxSize {
			next = s.cfg.MaxSize
		}
		if next > sample.BufferSize {
			out.Action = ActionGrow
			out.NewSize = next
			out.Reason = "drop pressure"
			s.lastChange = sample.At
		} else {
			out.Reason = "already at MaxSize"
		}
	case out.DropRate == 0 && out.IdleFrac >= s.cfg.IdleFractionShrink:
		next := uint64(float64(sample.BufferSize) / s.cfg.ShrinkFactor)
		if next < s.cfg.MinSize {
			next = s.cfg.MinSize
		}
		if next < sample.BufferSize {
			out.Action = ActionShrink
			out.NewSize = next
			out.Reason = "sustained idle"
			s.lastChange = sample.At
		} else {
			out.Reason = "already at MinSize"
		}
	default:
		out.Reason = "steady"
	}
	return out
}

// Reset clears history. Useful in tests.
func (s *Sizer) Reset() {
	s.mu.Lock()
	s.samples = nil
	s.lastDrop = 0
	s.lastSize = 0
	s.lastChange = time.Time{}
	s.mu.Unlock()
}

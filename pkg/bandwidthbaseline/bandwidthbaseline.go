// Package bandwidthbaseline learns per-binary egress-rate
// distributions and flags spikes. The substrate for the
// "user idle, 10 MB/s leaving the box" exfil red alert.
//
// Algorithm: per-binary EWMA of bytes_out per second plus a
// running max over a rolling window. Anomaly = current rate > N×
// EWMA AND current rate > recentMax. The N multiplier is the
// operator-tunable sensitivity knob.
//
// Pure-Go, goroutine-safe, persistence-agnostic.
package bandwidthbaseline

import (
	"math"
	"sort"
	"sync"
	"time"
)

// Defaults for the detector.
const (
	DefaultAlpha             = 0.2  // EWMA smoothing factor
	DefaultMultiplier        = 10.0 // anomaly threshold over EWMA
	DefaultMinSampleBytes    = 4096 // ignore tiny observations
	DefaultConfidenceWindow  = 7 * 24 * time.Hour
	DefaultMaxHistorySamples = 100
)

// Detector maintains per-binary egress-rate baselines.
type Detector struct {
	Alpha              float64       // EWMA smoothing (0..1); <=0 uses DefaultAlpha
	Multiplier         float64       // anomaly threshold; <=0 uses DefaultMultiplier
	MinSampleBytes     uint64        // ignore samples smaller than this
	ConfidenceWindow   time.Duration // alerts gated by binary maturity
	MaxHistorySamples  int           // rolling max size

	mu       sync.RWMutex
	binaries map[string]*Baseline
	now      func() time.Time
}

// Baseline is the per-binary record.
type Baseline struct {
	Key       string
	FirstSeen time.Time
	LastSeen  time.Time
	Samples   uint64
	EWMA      float64    // bytes/sec
	History   []float64  // rolling recent rates
	RecentMax float64    // max within MaxHistorySamples window
}

// Anomaly is the per-observation evaluation.
type Anomaly struct {
	Rate      float64       // bytes/sec for this observation
	EWMA      float64       // current EWMA after update
	Ratio     float64       // Rate / EWMA (∞ when EWMA=0)
	IsSpike   bool          // exceeded threshold
	BinaryAge time.Duration
}

// New returns a Detector with sane defaults.
func New() *Detector {
	return &Detector{
		Alpha:             DefaultAlpha,
		Multiplier:        DefaultMultiplier,
		MinSampleBytes:    DefaultMinSampleBytes,
		ConfidenceWindow:  DefaultConfidenceWindow,
		MaxHistorySamples: DefaultMaxHistorySamples,
		binaries:          map[string]*Baseline{},
		now:               time.Now,
	}
}

// Observe records one (key, bytesOut, duration) measurement and
// returns the Anomaly evaluation. Duration is the wall-time
// window the bytes were observed over (e.g. the lifetime of a
// flow or a 1-minute aggregation bucket).
func (d *Detector) Observe(key string, bytesOut uint64, dur time.Duration) Anomaly {
	if key == "" || dur <= 0 {
		return Anomaly{}
	}
	if bytesOut < d.minBytes() {
		return Anomaly{}
	}
	rate := float64(bytesOut) / dur.Seconds()
	now := d.now()

	d.mu.Lock()
	defer d.mu.Unlock()

	b, ok := d.binaries[key]
	if !ok {
		b = &Baseline{Key: key, FirstSeen: now, EWMA: rate}
		d.binaries[key] = b
	}
	b.LastSeen = now
	b.Samples++

	alpha := d.Alpha
	if alpha <= 0 || alpha > 1 {
		alpha = DefaultAlpha
	}

	// Anomaly decision uses the *pre-update* EWMA so a single
	// huge sample doesn't drag the threshold up to meet itself.
	prevEWMA := b.EWMA
	prevMax := b.RecentMax

	// Standard EWMA: new = alpha*current + (1-alpha)*old.
	// Skip blending on the very first sample (already seeded).
	if b.Samples > 1 {
		b.EWMA = alpha*rate + (1-alpha)*b.EWMA
	}

	// History + recent-max
	maxSamples := d.MaxHistorySamples
	if maxSamples <= 0 {
		maxSamples = DefaultMaxHistorySamples
	}
	b.History = append(b.History, rate)
	if len(b.History) > maxSamples {
		b.History = b.History[len(b.History)-maxSamples:]
	}
	b.RecentMax = 0
	for _, r := range b.History {
		if r > b.RecentMax {
			b.RecentMax = r
		}
	}

	mul := d.Multiplier
	if mul <= 0 {
		mul = DefaultMultiplier
	}

	a := Anomaly{Rate: rate, EWMA: b.EWMA, BinaryAge: now.Sub(b.FirstSeen)}
	if prevEWMA <= 0 {
		a.Ratio = math.Inf(1)
	} else {
		a.Ratio = rate / prevEWMA
	}
	// Spike when ratio over threshold AND we exceeded the
	// rolling recentMax (compared against the snapshot *before*
	// this sample was added).
	if b.Samples > 5 && a.Ratio >= mul && rate >= prevMax {
		a.IsSpike = true
	}
	return a
}

// IsConfident reports whether the baseline is mature enough for
// spike alerts to be trusted.
func (d *Detector) IsConfident(key string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	b, ok := d.binaries[key]
	if !ok {
		return false
	}
	w := d.ConfidenceWindow
	if w <= 0 {
		w = DefaultConfidenceWindow
	}
	return d.now().Sub(b.FirstSeen) >= w
}

// Stats returns a brief inventory.
type Stats struct {
	Binaries int
}

// Stats returns counts.
func (d *Detector) Stats() Stats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return Stats{Binaries: len(d.binaries)}
}

// Snapshot returns a deep-copy snapshot.
func (d *Detector) Snapshot() []Baseline {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Baseline, 0, len(d.binaries))
	for _, b := range d.binaries {
		cp := *b
		cp.History = append([]float64(nil), b.History...)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Load restores in-memory state from a Snapshot.
func (d *Detector) Load(snap []Baseline) {
	m := make(map[string]*Baseline, len(snap))
	for _, b := range snap {
		cp := b
		cp.History = append([]float64(nil), b.History...)
		m[b.Key] = &cp
	}
	d.mu.Lock()
	d.binaries = m
	d.mu.Unlock()
}

// Forget drops a binary's baseline.
func (d *Detector) Forget(key string) {
	d.mu.Lock()
	delete(d.binaries, key)
	d.mu.Unlock()
}

func (d *Detector) minBytes() uint64 {
	if d.MinSampleBytes == 0 {
		return DefaultMinSampleBytes
	}
	return d.MinSampleBytes
}

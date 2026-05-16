package baseline

import (
	"math"
	"sort"
	"sync"
	"time"
)

// RateDetector flags binaries whose hourly event rate has spiked far
// above their normal level. Pure exponentially-weighted moving
// average + simple sigma threshold — no ML.
//
// This is the "binary suddenly doing 100× more work than it has all
// week" detector. Catches:
//
//   - exfil bursts (a normally-quiet daemon suddenly produces
//     thousands of events)
//   - log floods (which often mean an attacker is making a daemon
//     loop on errors)
//   - crypto miner installs (CPU-bound process suddenly very chatty)
//
// Why EWMA and not a fixed window: makes the detector adapt to slowly
// rising legitimate baselines (e.g., gradually growing traffic) without
// false-firing. Sigma threshold makes it self-tuning — a noisy binary
// has a high stddev and needs a bigger spike to fire.
type RateDetector struct {
	cfg RateConfig

	mu     sync.Mutex
	tracks map[string]*rateTrack
}

// RateConfig tunes the detector.
type RateConfig struct {
	// Alpha is the EWMA smoothing factor for the mean and variance.
	// 0.1 = "remember roughly the last 10 windows". Default 0.1.
	Alpha float64
	// SigmaThreshold is how many standard deviations above the EWMA
	// mean a window must be to fire. Default 5 — set high; rate
	// alerts are easy false positives.
	SigmaThreshold float64
	// MinHistory is the number of warmup windows before scoring.
	// Default 24 (one full daily cycle).
	MinHistory int
	// MinAbsoluteEvents is a floor — windows with fewer than this many
	// events never fire even if statistically anomalous, because tiny
	// counts have noisy variance. Default 100.
	MinAbsoluteEvents uint64
}

type rateTrack struct {
	binary  string
	count   int     // windows seen
	mean    float64 // EWMA mean of events-per-window
	varEW   float64 // EWMA variance proxy
	last    time.Time
	allHist []uint64 // bounded history for percentile reporting
}

// RateVerdict is what the detector returns when a window crosses the
// sigma threshold. Reported numbers (current, mean, stddev) help the
// operator triage.
type RateVerdict struct {
	Binary       string    `json:"binary"`
	Hour         time.Time `json:"hour"`
	CurrentEvents uint64   `json:"current_events"`
	BaselineMean float64   `json:"baseline_mean"`
	BaselineStdDev float64 `json:"baseline_stddev"`
	SigmaAbove   float64   `json:"sigma_above"`
	HistoryWindows int     `json:"history_windows"`
	P95          uint64    `json:"p95,omitempty"`
}

// NewRateDetector returns a fresh detector with sane defaults.
func NewRateDetector(cfg RateConfig) *RateDetector {
	if cfg.Alpha <= 0 || cfg.Alpha > 1 {
		cfg.Alpha = 0.1
	}
	if cfg.SigmaThreshold <= 0 {
		cfg.SigmaThreshold = 5
	}
	if cfg.MinHistory <= 0 {
		cfg.MinHistory = 24
	}
	if cfg.MinAbsoluteEvents == 0 {
		cfg.MinAbsoluteEvents = 100
	}
	return &RateDetector{
		cfg:    cfg,
		tracks: map[string]*rateTrack{},
	}
}

// Observe folds a window's event count into the EWMA. Returns a
// non-nil RateVerdict when the window is more than SigmaThreshold
// stddevs above the mean, MinHistory has accumulated, and the
// MinAbsoluteEvents floor is met.
//
// Observe must be called once per (binary, hour) tuple.
func (d *RateDetector) Observe(w *Window) *RateVerdict {
	if w == nil || w.Binary == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	t, ok := d.tracks[w.Binary]
	if !ok {
		t = &rateTrack{
			binary: w.Binary,
			mean:   float64(w.Events),
			last:   w.Hour,
		}
		d.tracks[w.Binary] = t
		t.count = 1
		t.allHist = append(t.allHist, w.Events)
		return nil // no baseline yet
	}
	x := float64(w.Events)

	// CRITICAL: compute sigmas BEFORE folding this observation into
	// the EWMA. Otherwise a 100x spike inflates the variance enough
	// that the same spike's z-score collapses to small. (This is a
	// classic online-stats footgun.)
	prevMean := t.mean
	prevStdDev := math.Sqrt(t.varEW)
	if prevStdDev < 1 {
		prevStdDev = 1 // avoid divide-by-zero on flat baselines
	}
	sigmas := (x - prevMean) / prevStdDev

	// Now update the EWMA + variance proxy for future observations.
	residual := x - t.mean
	t.mean += d.cfg.Alpha * residual
	t.varEW = (1-d.cfg.Alpha)*(t.varEW + d.cfg.Alpha*residual*residual)
	t.count++
	t.last = w.Hour
	t.allHist = append(t.allHist, w.Events)
	if len(t.allHist) > 1024 {
		t.allHist = t.allHist[len(t.allHist)-1024:]
	}

	if t.count <= d.cfg.MinHistory {
		return nil
	}
	if w.Events < d.cfg.MinAbsoluteEvents {
		return nil
	}
	if sigmas < d.cfg.SigmaThreshold {
		return nil
	}
	v := &RateVerdict{
		Binary:         w.Binary,
		Hour:           w.Hour,
		CurrentEvents:  w.Events,
		BaselineMean:   prevMean,
		BaselineStdDev: prevStdDev,
		SigmaAbove:     sigmas,
		HistoryWindows: t.count - 1,
	}
	v.P95 = percentile(t.allHist, 95)
	return v
}

// Stats reports per-binary state.
type RateDetectorStats struct {
	Binaries int
	Warmed   int
}

func (d *RateDetector) Stats() RateDetectorStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := RateDetectorStats{Binaries: len(d.tracks)}
	for _, t := range d.tracks {
		if t.count >= d.cfg.MinHistory {
			out.Warmed++
		}
	}
	return out
}

// percentile returns the requested percentile from a slice (sorted
// internally; original is not mutated). Cheap because the buffer is
// bounded to 1024.
func percentile(vals []uint64, p int) uint64 {
	if len(vals) == 0 {
		return 0
	}
	cpy := make([]uint64, len(vals))
	copy(cpy, vals)
	sort.Slice(cpy, func(i, j int) bool { return cpy[i] < cpy[j] })
	idx := (p * len(cpy)) / 100
	if idx >= len(cpy) {
		idx = len(cpy) - 1
	}
	return cpy[idx]
}

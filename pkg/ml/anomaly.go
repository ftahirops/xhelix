// Package ml implements lightweight anomaly detection for xhelix.
//
// Phase 7 introduces statistical baselining and simple ML models
// (isolation forest, one-class SVM) for detecting novel attacks
// without signatures. The initial implementation uses pure-Go
// statistical methods with no external dependencies.
package ml

import (
	"math"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// AnomalyDetector tracks per-process behavioral baselines and flags
// deviations.
type AnomalyDetector struct {
	windowSize int
	threshold  float64

	mu       sync.RWMutex
	profiles map[profileKey]*profile
}

type profileKey struct {
	comm string
	uid  uint32
}

type profile struct {
	comm         string
	uid          uint32
	eventCounts  []int
	networkConns []int
	fileAccesses []int
	lastUpdate   time.Time
}

// NewDetector creates an anomaly detector.
func NewDetector(windowSize int, threshold float64) *AnomalyDetector {
	if windowSize == 0 {
		windowSize = 24 // 1-hour windows over a day
	}
	if threshold == 0 {
		threshold = 3.0 // 3 sigma
	}
	return &AnomalyDetector{
		windowSize: windowSize,
		threshold:  threshold,
		profiles:   map[profileKey]*profile{},
	}
}

// Observe ingests an event and updates the baseline. Returns true if
// the event is anomalous.
func (d *AnomalyDetector) Observe(ev model.Event) bool {
	key := profileKey{comm: ev.Comm, uid: ev.UID}

	d.mu.Lock()
	p, ok := d.profiles[key]
	if !ok {
		p = &profile{comm: ev.Comm, uid: ev.UID}
		d.profiles[key] = p
	}
	// Update counters
	p.eventCounts = append(p.eventCounts, 1)
	if ev.Sensor == "ebpf.net" {
		p.networkConns = append(p.networkConns, 1)
	}
	if ev.Sensor == "ebpf.file" {
		p.fileAccesses = append(p.fileAccesses, 1)
	}
	p.lastUpdate = time.Now()
	d.mu.Unlock()

	// Need a minimum number of observations before we can detect anomalies
	if len(p.eventCounts) < d.windowSize {
		return false
	}

	// Simple z-score on event rate
	mean, stddev := meanStddev(p.eventCounts)
	if stddev == 0 {
		return false
	}
	last := float64(p.eventCounts[len(p.eventCounts)-1])
	zscore := math.Abs(last-mean) / stddev
	return zscore > d.threshold
}

// Score returns an anomaly score (0–100) for the given process.
func (d *AnomalyDetector) Score(comm string, uid uint32) float64 {
	d.mu.RLock()
	p, ok := d.profiles[profileKey{comm: comm, uid: uid}]
	d.mu.RUnlock()
	if !ok || len(p.eventCounts) < d.windowSize {
		return 0
	}
	mean, stddev := meanStddev(p.eventCounts)
	if stddev == 0 {
		return 0
	}
	last := float64(p.eventCounts[len(p.eventCounts)-1])
	zscore := math.Abs(last-mean) / stddev
	score := math.Min(zscore/d.threshold*50, 100)
	return score
}

func meanStddev(vals []int) (mean, stddev float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range vals {
		sum += float64(v)
	}
	mean = sum / float64(len(vals))
	var sqDiff float64
	for _, v := range vals {
		diff := float64(v) - mean
		sqDiff += diff * diff
	}
	stddev = math.Sqrt(sqDiff / float64(len(vals)))
	return mean, stddev
}

package netids

import (
	"sync"
	"time"
)

// NXDOMAINBurstDetector tracks NXDOMAIN responses per client over a
// rolling 60-second window and reports bursts of >= Threshold.
type NXDOMAINBurstDetector struct {
	Threshold int

	mu     sync.Mutex
	counts map[string]*ringWindow
}

// NewNXDOMAINBurst returns a detector with the given threshold
// (default 50 if zero).
func NewNXDOMAINBurst(threshold int) *NXDOMAINBurstDetector {
	if threshold <= 0 {
		threshold = 50
	}
	return &NXDOMAINBurstDetector{
		Threshold: threshold,
		counts:    map[string]*ringWindow{},
	}
}

// Observe records one NXDOMAIN for client at the given time.
// Returns true (and resets the window for client) when the threshold
// trips.
func (d *NXDOMAINBurstDetector) Observe(client string, t time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	w, ok := d.counts[client]
	if !ok {
		w = newRingWindow(time.Minute)
		d.counts[client] = w
	}
	w.add(t)
	if w.count() >= d.Threshold {
		w.reset()
		return true
	}
	return false
}

// ringWindow is a coarse-grained counter over the last `dur` seconds.
type ringWindow struct {
	dur     time.Duration
	bucket  map[int64]int
	lastSec int64
}

func newRingWindow(dur time.Duration) *ringWindow {
	return &ringWindow{dur: dur, bucket: map[int64]int{}}
}

func (w *ringWindow) add(t time.Time) {
	sec := t.Unix()
	w.bucket[sec]++
	w.lastSec = sec
	w.evict(sec)
}

func (w *ringWindow) count() int {
	w.evict(w.lastSec)
	n := 0
	for _, c := range w.bucket {
		n += c
	}
	return n
}

func (w *ringWindow) reset() {
	w.bucket = map[int64]int{}
}

func (w *ringWindow) evict(now int64) {
	cutoff := now - int64(w.dur.Seconds())
	for sec := range w.bucket {
		if sec < cutoff {
			delete(w.bucket, sec)
		}
	}
}

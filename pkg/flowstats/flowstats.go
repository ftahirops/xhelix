// Package flowstats maintains per-image rolling byte counters
// (Phase H.1).
//
// The sensor already emits per-flow net_bytes events that land in
// the conn-state table. That's per-connection granularity, but
// detection wants per-process aggregates: "is this image moving
// more bytes outbound right now than its baseline?" / "did a
// short-lived dropper just exfiltrate 100MB?".
//
// Counters keeps a small ring of bytes per (image, direction) so
// the pipeline can stamp recent in/out totals on every net_connect
// event. CEL rules then fire on volume thresholds (e.g. > 50MB
// outbound in last minute from a non-egress-budgeted image).
//
// Honest non-promise: counters reset on daemon restart and bound at
// `windowBuckets * tickInterval`. Long-horizon byte aggregates
// belong in pkg/longwindow's threshold poller; flowstats is the
// fast-path (sub-minute) view.
package flowstats

import (
	"sort"
	"sync"
	"time"
)

// Direction is "in" or "out".
type Direction string

const (
	DirIn  Direction = "in"
	DirOut Direction = "out"
)

// Counters tracks rolling per-image byte totals with one bucket per
// `bucket` interval over `window`. Goroutine-safe.
type Counters struct {
	mu sync.Mutex

	window  time.Duration
	bucket  time.Duration
	nBucks  int
	entries map[key]*ring
}

type key struct {
	image string
	dir   Direction
}

type ring struct {
	buckets []uint64   // bytes per bucket
	last    time.Time  // bucket-aligned timestamp of buckets[0]
}

// New returns a Counters with the given total window split into
// `bucket`-sized cells. Defaults: 1m window / 5s buckets if either
// is zero.
func New(window, bucket time.Duration) *Counters {
	if window <= 0 {
		window = time.Minute
	}
	if bucket <= 0 {
		bucket = 5 * time.Second
	}
	n := int(window / bucket)
	if n < 1 {
		n = 1
	}
	return &Counters{
		window:  window,
		bucket:  bucket,
		nBucks:  n,
		entries: map[key]*ring{},
	}
}

// Window returns the rolling window length.
func (c *Counters) Window() time.Duration { return c.window }

// Add records `bytes` for image in direction at time `at`.
func (c *Counters) Add(image string, dir Direction, bytes uint64, at time.Time) {
	if c == nil || image == "" || bytes == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := key{image: image, dir: dir}
	r := c.entries[k]
	if r == nil {
		r = &ring{buckets: make([]uint64, c.nBucks), last: c.align(at)}
		c.entries[k] = r
	}
	c.advance(r, at)
	r.buckets[0] += bytes
}

// Sum returns the rolling total bytes for (image, dir) ending at `at`.
func (c *Counters) Sum(image string, dir Direction, at time.Time) uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.entries[key{image: image, dir: dir}]
	if r == nil {
		return 0
	}
	c.advance(r, at)
	var s uint64
	for _, b := range r.buckets {
		s += b
	}
	return s
}

// Sweep prunes images that have been idle for at least one full
// window. Run periodically to bound memory.
func (c *Counters) Sweep(now time.Time) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := c.align(now.Add(-c.window))
	dropped := 0
	for k, r := range c.entries {
		if r.last.Before(cutoff) {
			delete(c.entries, k)
			dropped++
		}
	}
	return dropped
}

// Size returns the number of tracked (image, dir) entries.
func (c *Counters) Size() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// TopOut returns up to `n` images by outbound bytes over the window
// ending at `at`. For `xhelixctl flowstats top`.
func (c *Counters) TopOut(n int, at time.Time) []ImageBytes {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]ImageBytes, 0)
	for k, r := range c.entries {
		if k.dir != DirOut {
			continue
		}
		c.advance(r, at)
		var s uint64
		for _, b := range r.buckets {
			s += b
		}
		out = append(out, ImageBytes{Image: k.image, Bytes: s})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// ImageBytes is one row in TopOut.
type ImageBytes struct {
	Image string
	Bytes uint64
}

// advance shifts the ring forward so buckets[0] represents the
// current bucket aligned to `at`. Caller holds c.mu.
func (c *Counters) advance(r *ring, at time.Time) {
	cur := c.align(at)
	delta := cur.Sub(r.last)
	if delta <= 0 {
		return
	}
	steps := int(delta / c.bucket)
	if steps >= c.nBucks {
		for i := range r.buckets {
			r.buckets[i] = 0
		}
		r.last = cur
		return
	}
	// Shift right by `steps`, zeroing the newly-current cell.
	for i := c.nBucks - 1; i >= steps; i-- {
		r.buckets[i] = r.buckets[i-steps]
	}
	for i := 0; i < steps; i++ {
		r.buckets[i] = 0
	}
	r.last = cur
}

func (c *Counters) align(t time.Time) time.Time {
	return t.Truncate(c.bucket)
}

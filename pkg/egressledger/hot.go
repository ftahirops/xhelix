package egressledger

import (
	"sync"
	"time"
)

// hotRing holds bucket -> key -> metrics for the last HotWindow.
type hotRing struct {
	mu      sync.RWMutex
	bucket  time.Duration
	window  time.Duration
	rows    map[int64]map[FlowKey]*FlowMetrics
}

func newHotRing(bucket, window time.Duration) *hotRing {
	return &hotRing{
		bucket: bucket,
		window: window,
		rows:   make(map[int64]map[FlowKey]*FlowMetrics),
	}
}

// truncate returns the bucket-aligned unix-nano timestamp for t.
func (h *hotRing) truncate(t time.Time) int64 {
	return t.Truncate(h.bucket).UnixNano()
}

// observe merges metrics m into the bucket for key. Must NOT be called with
// h.mu held.
func (h *hotRing) observe(t time.Time, key FlowKey, ev *Event) {
	b := h.truncate(t)
	h.mu.Lock()
	defer h.mu.Unlock()
	bucket, ok := h.rows[b]
	if !ok {
		bucket = make(map[FlowKey]*FlowMetrics)
		h.rows[b] = bucket
	}
	m, ok := bucket[key]
	if !ok {
		m = &FlowMetrics{FirstSeen: t, LastSeen: t}
		bucket[key] = m
	}
	if t.Before(m.FirstSeen) {
		m.FirstSeen = t
	}
	if t.After(m.LastSeen) {
		m.LastSeen = t
	}
	if ev.Connect {
		m.Connects++
	}
	m.BytesOut += ev.BytesOut
	m.BytesIn += ev.BytesIn
	if ev.Deny {
		m.DenyEvents++
	}
	if ev.Verify {
		m.VerifyEvents++
	}
}

// slide removes buckets older than (now - window) and returns the evicted
// rows as FlowRecords.
func (h *hotRing) slide(now time.Time) []FlowRecord {
	cutoff := now.Add(-h.window).Truncate(h.bucket).UnixNano()
	var out []FlowRecord
	h.mu.Lock()
	for b, m := range h.rows {
		if b < cutoff {
			bt := time.Unix(0, b)
			for k, v := range m {
				out = append(out, FlowRecord{Key: k, Metrics: *v, Bucket: bt})
			}
			delete(h.rows, b)
		}
	}
	h.mu.Unlock()
	return out
}

// snapshot returns all live rows. Caller may filter.
func (h *hotRing) snapshot() []FlowRecord {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []FlowRecord
	for b, m := range h.rows {
		bt := time.Unix(0, b)
		for k, v := range m {
			out = append(out, FlowRecord{Key: k, Metrics: *v, Bucket: bt})
		}
	}
	return out
}

// snapshotRange returns rows whose bucket falls within [start, end].
func (h *hotRing) snapshotRange(start, end time.Time) []FlowRecord {
	s, e := start.UnixNano(), end.UnixNano()
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []FlowRecord
	for b, m := range h.rows {
		if b < s || b > e {
			continue
		}
		bt := time.Unix(0, b)
		for k, v := range m {
			out = append(out, FlowRecord{Key: k, Metrics: *v, Bucket: bt})
		}
	}
	return out
}

// rowsCount returns the total number of (bucket, key) pairs.
func (h *hotRing) rowsCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	n := 0
	for _, m := range h.rows {
		n += len(m)
	}
	return n
}

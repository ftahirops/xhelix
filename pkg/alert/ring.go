package alert

import (
	"context"
	"sync"

	"github.com/xhelix/xhelix/pkg/model"
)

// RingSink is an in-memory ring buffer of recent alerts. Used by the
// TUI Alerts view to render a live timeline without re-reading the
// daily JSONL file. Independent of file/stdout/webhook sinks; safe
// to enable always.
//
// Capacity defaults to 1024. Newer alerts evict the oldest.
type RingSink struct {
	mu  sync.RWMutex
	buf []model.Alert
	cap int
}

// NewRingSink returns a sink with the given capacity (≤0 → 1024).
func NewRingSink(capacity int) *RingSink {
	if capacity <= 0 {
		capacity = 1024
	}
	return &RingSink{cap: capacity, buf: make([]model.Alert, 0, capacity)}
}

// Name implements model.Sink.
func (r *RingSink) Name() string { return "ring" }

// Close is a no-op; in-memory only.
func (r *RingSink) Close() error { return nil }

// Send pushes onto the ring, evicting the oldest when full.
func (r *RingSink) Send(_ context.Context, a model.Alert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) < r.cap {
		r.buf = append(r.buf, a)
		return nil
	}
	// Slide left by one, append new.
	copy(r.buf, r.buf[1:])
	r.buf[len(r.buf)-1] = a
	return nil
}

// Snapshot returns a copy of the ring, newest last. Caller-owned.
func (r *RingSink) Snapshot() []model.Alert {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]model.Alert, len(r.buf))
	copy(out, r.buf)
	return out
}

// Count returns the number of alerts currently held.
func (r *RingSink) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.buf)
}

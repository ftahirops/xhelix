package alert

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/xhelix/xhelix/pkg/model"
)

// Bus is a bounded fan-out channel into one or more sinks.
//
// Send is non-blocking: when the queue is full the alert is dropped
// and the drop counter is incremented. Sensors must never block on
// alert delivery.
type Bus struct {
	sinks       []model.Sink
	queue       chan model.Alert
	dropped     atomic.Uint64
	suppressed  atomic.Uint64
	sinkDropped atomic.Uint64
	gate        func(model.Alert) bool
	router      func(model.Alert) (emit bool, synth *model.Alert)
	wg          sync.WaitGroup
	log         *slog.Logger
}

// NewBus creates a bus with the given sinks and a queue capacity.
//
// A capacity of 0 selects the default (4096).
func NewBus(sinks []model.Sink, capacity int, log *slog.Logger) *Bus {
	if capacity <= 0 {
		capacity = 4096
	}
	if log == nil {
		log = slog.Default()
	}
	return &Bus{
		sinks: sinks,
		queue: make(chan model.Alert, capacity),
		log:   log,
	}
}

// SetGate installs an emission predicate. When set, Send drops any
// alert for which gate returns false, incrementing the suppressed
// counter instead of enqueuing. A nil gate (the default) emits
// everything. Safe to call once during startup before Run.
func (b *Bus) SetGate(gate func(model.Alert) bool) { b.gate = gate }

// SetRouter installs a routing function richer than SetGate: it returns
// whether to emit the original alert AND an optional synthesized alert
// to ALSO enqueue (e.g. a verdict.incident produced by correlating
// several signals). The synthesized alert is enqueued directly, NOT
// re-routed (no recursion). A router takes precedence over a gate.
func (b *Bus) SetRouter(r func(model.Alert) (bool, *model.Alert)) { b.router = r }

// Send enqueues an alert. Returns true if accepted, false if dropped.
//
// CRITICAL: callers continue to mutate event.Tags after this returns
// (downstream pipeline enrichment runs in the same goroutine). The
// bus must take a SNAPSHOT of the tags map here, otherwise sinks
// JSON-marshalling the event will race with pipeline writes —
// observed crashes "fatal error: concurrent map iteration and map
// write" during attack-sim runs on prod (2026-05-23).
func (b *Bus) Send(a model.Alert) bool {
	if b.router != nil {
		emit, synth := b.router(a)
		if synth != nil {
			b.enqueue(*synth) // direct; never re-routed
		}
		if !emit {
			b.suppressed.Add(1)
			return false
		}
		return b.enqueue(a)
	}
	if b.gate != nil && !b.gate(a) {
		b.suppressed.Add(1)
		return false
	}
	return b.enqueue(a)
}

// enqueue snapshots tags and does the non-blocking channel send. Returns
// true if accepted, false if dropped (queue full).
func (b *Bus) enqueue(a model.Alert) bool {
	if a.Event.Tags != nil {
		snap := make(map[string]string, len(a.Event.Tags))
		for k, v := range a.Event.Tags {
			snap[k] = v
		}
		a.Event.Tags = snap
	}
	select {
	case b.queue <- a:
		return true
	default:
		b.dropped.Add(1)
		return false
	}
}

// Dropped returns the running count of dropped alerts.
func (b *Bus) Dropped() uint64 { return b.dropped.Load() }

// Suppressed returns the running count of alerts dropped by the gate
// (distinct from Dropped, which counts queue-full drops).
func (b *Bus) Suppressed() uint64 { return b.suppressed.Load() }

// Run pumps the queue into every sink until ctx is cancelled.
//
// Each sink gets its own worker goroutine and bounded buffer, so a slow
// sink (e.g. a webhook POST blocking on a 5s timeout) backs up only its
// own buffer and cannot stall the pump or the other sinks. When a sink's
// buffer is full its alert is dropped and sinkDropped is incremented —
// the bus does not block, by design; sinks that need durability layer it
// themselves.
//
// Sink errors are logged at warn level; the bus does not retry.
func (b *Bus) Run(ctx context.Context) {
	b.wg.Add(1)
	defer b.wg.Done()

	// Per-sink buffered queue + worker. Buffer matches the main queue so a
	// transient sink stall is absorbed rather than immediately lossy.
	sinkChans := make([]chan model.Alert, len(b.sinks))
	var workers sync.WaitGroup
	for i, s := range b.sinks {
		ch := make(chan model.Alert, cap(b.queue))
		sinkChans[i] = ch
		workers.Add(1)
		go func(s model.Sink, ch chan model.Alert) {
			defer workers.Done()
			for a := range ch {
				if err := s.Send(ctx, a); err != nil {
					b.log.Warn("sink send failed", "sink", s.Name(), "err", err)
				}
			}
		}(s, ch)
	}

	drain := func() {
		for _, ch := range sinkChans {
			close(ch)
		}
		workers.Wait()
	}

	for {
		select {
		case <-ctx.Done():
			drain()
			return
		case a := <-b.queue:
			for _, ch := range sinkChans {
				select {
				case ch <- a:
				default:
					b.sinkDropped.Add(1)
				}
			}
		}
	}
}

// SinkDropped returns the running count of alerts dropped because a
// sink's own buffer was full (a slow/stalled sink), distinct from the
// queue-full Dropped and gate Suppressed counters.
func (b *Bus) SinkDropped() uint64 { return b.sinkDropped.Load() }

// Wait blocks until Run returns. Useful in tests.
func (b *Bus) Wait() { b.wg.Wait() }

// Close drains pending alerts and closes every sink.
//
// Caller is responsible for cancelling the context that drives Run
// before calling Close.
func (b *Bus) Close() {
	for _, s := range b.sinks {
		_ = s.Close()
	}
}

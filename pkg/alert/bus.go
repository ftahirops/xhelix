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
	sinks   []model.Sink
	queue   chan model.Alert
	dropped atomic.Uint64
	wg      sync.WaitGroup
	log     *slog.Logger
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

// Send enqueues an alert. Returns true if accepted, false if dropped.
func (b *Bus) Send(a model.Alert) bool {
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

// Run pumps the queue into every sink until ctx is cancelled.
//
// Sink errors are logged at warn level; the bus does not retry, by
// design — sinks that need durability layer it themselves.
func (b *Bus) Run(ctx context.Context) {
	b.wg.Add(1)
	defer b.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-b.queue:
			for _, s := range b.sinks {
				if err := s.Send(ctx, a); err != nil {
					b.log.Warn("sink send failed", "sink", s.Name(), "err", err)
				}
			}
		}
	}
}

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

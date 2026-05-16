package alert

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

type captureSink struct {
	count atomic.Uint64
}

func (c *captureSink) Name() string { return "capture" }
func (c *captureSink) Send(ctx context.Context, a model.Alert) error {
	c.count.Add(1)
	return nil
}
func (c *captureSink) Close() error { return nil }

func TestBusFanOut(t *testing.T) {
	cs := &captureSink{}
	bus := NewBus([]model.Sink{cs}, 16, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bus.Run(ctx)

	for i := 0; i < 10; i++ {
		a := model.Alert{
			Event:  model.NewEvent("test", model.SeverityInfo),
			RuleID: "test",
		}
		if !bus.Send(a) {
			t.Errorf("alert %d unexpectedly dropped", i)
		}
	}

	// Allow the goroutine time to drain.
	time.Sleep(50 * time.Millisecond)
	if got := cs.count.Load(); got != 10 {
		t.Errorf("sink received %d alerts, want 10", got)
	}
}

func TestBusDropsWhenFull(t *testing.T) {
	cs := &captureSink{}
	bus := NewBus([]model.Sink{cs}, 1, nil)
	// Don't run the consumer; the queue stays full.

	if !bus.Send(model.Alert{}) {
		t.Error("first send should succeed")
	}
	if bus.Send(model.Alert{}) {
		t.Error("second send should be dropped")
	}
	if got := bus.Dropped(); got != 1 {
		t.Errorf("dropped = %d, want 1", got)
	}
}

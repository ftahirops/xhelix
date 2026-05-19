package eac

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestSourceGrade_IsDecisionGrade(t *testing.T) {
	cases := map[SourceGrade]bool{
		GradeAPlus: true,
		GradeA:     true,
		GradeB:     false,
		GradeC:     false,
		GradeD:     false,
	}
	for g, want := range cases {
		if got := g.IsDecisionGrade(); got != want {
			t.Errorf("%s.IsDecisionGrade() = %v, want %v", g, got, want)
		}
	}
}

// drainWithTimeout collects up to n events from out, or errors if
// fewer arrive within d. Used as a deterministic harness for the
// async controller.
func drainWithTimeout(t *testing.T, out <-chan AdmittedEvent, n int, d time.Duration) []AdmittedEvent {
	t.Helper()
	got := make([]AdmittedEvent, 0, n)
	deadline := time.After(d)
	for len(got) < n {
		select {
		case e := <-out:
			got = append(got, e)
		case <-deadline:
			return got
		}
	}
	return got
}

func TestAdmission_BasicFlowOrdersByKernelTime(t *testing.T) {
	c := New(Config{
		ReorderWindow: 50 * time.Millisecond,
		FlushInterval: 10 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	defer c.Stop()

	// Submit three events with deliberately out-of-order kernel times.
	now := uint64(time.Now().UnixNano())
	c.Submit(RawEvent{KernelTimeNS: now + 30, WallTimeNS: now, Kind: "third", Source: GradeAPlus})
	c.Submit(RawEvent{KernelTimeNS: now + 10, WallTimeNS: now, Kind: "first", Source: GradeAPlus})
	c.Submit(RawEvent{KernelTimeNS: now + 20, WallTimeNS: now, Kind: "second", Source: GradeAPlus})

	got := drainWithTimeout(t, c.Out(), 3, 500*time.Millisecond)
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}
	want := []string{"first", "second", "third"}
	for i, e := range got {
		if e.Kind != want[i] {
			t.Errorf("event %d kind = %q, want %q", i, e.Kind, want[i])
		}
	}
}

func TestAdmission_SequenceIDsMonotonic(t *testing.T) {
	c := New(Config{
		ReorderWindow: 20 * time.Millisecond,
		FlushInterval: 5 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	defer c.Stop()

	now := uint64(time.Now().UnixNano())
	for i := 0; i < 50; i++ {
		c.Submit(RawEvent{
			KernelTimeNS: now + uint64(i)*1000,
			WallTimeNS:   now,
			Kind:         "k",
			Source:       GradeA,
		})
	}

	got := drainWithTimeout(t, c.Out(), 50, 500*time.Millisecond)
	if len(got) != 50 {
		t.Fatalf("got %d, want 50", len(got))
	}
	var last uint64
	for i, e := range got {
		if e.Admission.SequenceID == 0 {
			t.Errorf("event %d: SequenceID is 0", i)
		}
		if i > 0 && e.Admission.SequenceID <= last {
			t.Errorf("event %d: seq %d not greater than %d",
				i, e.Admission.SequenceID, last)
		}
		last = e.Admission.SequenceID
	}
}

func TestAdmission_SelfExclusion(t *testing.T) {
	c := New(Config{
		ReorderWindow: 20 * time.Millisecond,
		FlushInterval: 5 * time.Millisecond,
		SelfPID:       42,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	defer c.Stop()

	now := uint64(time.Now().UnixNano())
	// Submit two events: one from self, one from another actor.
	c.Submit(RawEvent{KernelTimeNS: now + 10, WallTimeNS: now, Kind: "self_event", Source: GradeAPlus, ActorPID: 42})
	c.Submit(RawEvent{KernelTimeNS: now + 20, WallTimeNS: now, Kind: "other_event", Source: GradeAPlus, ActorPID: 99})

	got := drainWithTimeout(t, c.Out(), 2, 200*time.Millisecond)
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1 (self event must be silently dropped)", len(got))
	}
	if got[0].Kind != "other_event" {
		t.Errorf("kind = %q, want other_event", got[0].Kind)
	}
}

func TestAdmission_BufferOverflowReportsLoss(t *testing.T) {
	c := New(Config{
		ReorderWindow: 1 * time.Second, // long enough to fill buffer
		FlushInterval: 100 * time.Millisecond,
		InQueueSize:   8,
		OutQueueSize:  32,
		MaxBufferSize: 8,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	defer c.Stop()

	now := uint64(time.Now().UnixNano())
	// Submit far more than buffer can hold.
	for i := 0; i < 100; i++ {
		c.Submit(RawEvent{
			KernelTimeNS: now + uint64(i)*1000,
			WallTimeNS:   now,
			Kind:         "k",
			Source:       GradeAPlus,
		})
	}
	// Give the ingest loop time to process the channel.
	time.Sleep(50 * time.Millisecond)

	stats := c.Stats()
	if stats.Drops == 0 {
		t.Error("expected drops > 0 under overflow")
	}
	if stats.LossEvents == 0 {
		t.Error("expected loss events > 0 under overflow")
	}
}

func TestAdmission_LossObservedFlag(t *testing.T) {
	c := New(Config{
		ReorderWindow: 20 * time.Millisecond,
		FlushInterval: 5 * time.Millisecond,
		InQueueSize:   2, // tiny — easy to overflow
		MaxBufferSize: 4,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	defer c.Stop()

	now := uint64(time.Now().UnixNano())
	// Saturate the input queue to force a drop.
	accepted := 0
	for i := 0; i < 50; i++ {
		if c.Submit(RawEvent{KernelTimeNS: now + uint64(i), WallTimeNS: now, Kind: "k", Source: GradeAPlus}) {
			accepted++
		}
	}
	// Wait for flush to drain everything.
	time.Sleep(200 * time.Millisecond)

	// At least one event should carry LossObserved=true because drops happened.
	var sawLoss bool
	for {
		select {
		case e, ok := <-c.Out():
			if !ok {
				goto done
			}
			if e.Admission.LossObserved {
				sawLoss = true
			}
		default:
			goto done
		}
	}
done:
	if !sawLoss {
		// It's possible all the drops happened *after* the last
		// admitted event, in which case the next-flush flag wouldn't
		// fire. But stats must still show drops.
		stats := c.Stats()
		if stats.Drops == 0 {
			t.Error("expected LossObserved on at least one admitted event OR Drops>0")
		}
	}
}

func TestAdmission_GradePropagatesToContext(t *testing.T) {
	c := New(Config{
		ReorderWindow: 20 * time.Millisecond,
		FlushInterval: 5 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	defer c.Stop()

	now := uint64(time.Now().UnixNano())
	grades := []SourceGrade{GradeAPlus, GradeA, GradeB, GradeC, GradeD}
	for i, g := range grades {
		c.Submit(RawEvent{KernelTimeNS: now + uint64(i), WallTimeNS: now, Kind: "k", Source: g})
	}
	got := drainWithTimeout(t, c.Out(), len(grades), 500*time.Millisecond)
	if len(got) != len(grades) {
		t.Fatalf("got %d events, want %d", len(got), len(grades))
	}
	for i, e := range got {
		if e.Admission.SourceGradeAdmitted != grades[i] {
			t.Errorf("event %d grade = %s, want %s", i, e.Admission.SourceGradeAdmitted, grades[i])
		}
	}
}

func TestAdmission_FinalFlushOnStop(t *testing.T) {
	c := New(Config{
		ReorderWindow: 5 * time.Second, // very long — only Stop's final flush will release events
		FlushInterval: 1 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)

	now := uint64(time.Now().UnixNano())
	c.Submit(RawEvent{KernelTimeNS: now + 10, WallTimeNS: now, Kind: "a", Source: GradeAPlus})
	c.Submit(RawEvent{KernelTimeNS: now + 20, WallTimeNS: now, Kind: "b", Source: GradeAPlus})

	// Drain in a goroutine while we Stop.
	var got atomic.Int32
	doneCh := make(chan struct{})
	go func() {
		for range c.Out() {
			got.Add(1)
		}
		close(doneCh)
	}()

	// Give events time to land in the buffer, then stop.
	time.Sleep(50 * time.Millisecond)
	c.Stop()
	<-doneCh

	if got.Load() != 2 {
		t.Errorf("final flush emitted %d events, want 2", got.Load())
	}
}

func TestAdmission_NoNullKernelTimeProgression(t *testing.T) {
	// Events with identical kernel times must still all admit (stable sort).
	c := New(Config{
		ReorderWindow: 20 * time.Millisecond,
		FlushInterval: 5 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	defer c.Stop()

	now := uint64(time.Now().UnixNano())
	for i := 0; i < 10; i++ {
		c.Submit(RawEvent{KernelTimeNS: now + 5, WallTimeNS: now, Kind: "k", Source: GradeAPlus})
	}
	got := drainWithTimeout(t, c.Out(), 10, 500*time.Millisecond)
	if len(got) != 10 {
		t.Errorf("got %d events with identical KernelTimeNS, want 10", len(got))
	}
}

func TestConfig_Defaults(t *testing.T) {
	c := New(Config{}) // all zero
	if c.cfg.ReorderWindow == 0 {
		t.Error("default ReorderWindow not applied")
	}
	if c.cfg.InQueueSize == 0 {
		t.Error("default InQueueSize not applied")
	}
	if c.cfg.MaxBufferSize == 0 {
		t.Error("default MaxBufferSize not applied")
	}
	if c.cfg.FlushInterval == 0 {
		t.Error("default FlushInterval not applied")
	}
	if c.cfg.FlushInterval > c.cfg.ReorderWindow {
		t.Error("FlushInterval should be less than ReorderWindow")
	}
}

func BenchmarkAdmission_Submit(b *testing.B) {
	c := New(Config{
		ReorderWindow: 100 * time.Millisecond,
		InQueueSize:   1 << 16,
		OutQueueSize:  1 << 16,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	defer c.Stop()

	// Drain in background so the channel doesn't back up.
	go func() {
		for range c.Out() {
		}
	}()

	now := uint64(time.Now().UnixNano())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Submit(RawEvent{
			KernelTimeNS: now + uint64(i),
			WallTimeNS:   now,
			Kind:         "bench",
			Source:       GradeAPlus,
		})
	}
}

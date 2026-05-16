package ringbufsize

import (
	"testing"
	"time"
)

func steady(s *Sizer, occupancy float64, startSize uint64, n int) Recommendation {
	t0 := time.Unix(1000, 0)
	var rec Recommendation
	for i := 0; i < n; i++ {
		rec = s.Observe(Sample{
			At: t0.Add(time.Duration(i) * time.Second),
			Drops: 0, Occupancy: occupancy, BufferSize: startSize,
		})
	}
	return rec
}

func TestHoldDuringWarmup(t *testing.T) {
	s := New(Config{Window: 10})
	rec := s.Observe(Sample{Drops: 0, Occupancy: 0.5, BufferSize: 1 << 20})
	if rec.Action != ActionHold {
		t.Fatalf("warmup should hold; got %s", rec.Action)
	}
}

func TestGrowOnDropPressure(t *testing.T) {
	s := New(Config{Window: 10, MaxSize: 16 << 20, GrowFactor: 2.0, Cooldown: time.Second})
	t0 := time.Unix(1000, 0)
	// First fill with no drops, then sustain droppy samples.
	for i := 0; i < 5; i++ {
		s.Observe(Sample{At: t0.Add(time.Duration(i) * time.Second), Drops: 0, Occupancy: 0.5, BufferSize: 1 << 20})
	}
	drops := uint64(0)
	var rec Recommendation
	for i := 5; i < 15; i++ {
		drops += 100
		rec = s.Observe(Sample{
			At: t0.Add(time.Duration(i) * time.Second),
			Drops: drops, Occupancy: 0.9, BufferSize: 1 << 20,
		})
	}
	if rec.Action != ActionGrow {
		t.Fatalf("expected Grow under drop pressure; got %s reason=%s droprate=%f",
			rec.Action, rec.Reason, rec.DropRate)
	}
	if rec.NewSize != 2<<20 {
		t.Errorf("new_size = %d, want 2MB", rec.NewSize)
	}
}

func TestGrowClampedAtMaxSize(t *testing.T) {
	s := New(Config{Window: 6, MaxSize: 2 << 20, GrowFactor: 4.0, Cooldown: time.Second})
	t0 := time.Unix(1000, 0)
	drops := uint64(0)
	for i := 0; i < 10; i++ {
		drops += 10
		s.Observe(Sample{
			At: t0.Add(time.Duration(i) * time.Second),
			Drops: drops, Occupancy: 0.9, BufferSize: 2 << 20,
		})
	}
	// We're already at MaxSize — should not grow.
	rec := s.Observe(Sample{At: t0.Add(time.Hour), Drops: drops + 1, Occupancy: 0.9, BufferSize: 2 << 20})
	if rec.Action == ActionGrow {
		t.Fatalf("should not grow past MaxSize; got %+v", rec)
	}
}

func TestShrinkOnSustainedIdle(t *testing.T) {
	s := New(Config{Window: 10, MinSize: 1 << 20, ShrinkFactor: 2.0, Cooldown: time.Second})
	steady(s, 0.05, 16<<20, 12)
	t0 := time.Unix(2000, 0)
	rec := s.Observe(Sample{At: t0, Drops: 0, Occupancy: 0.05, BufferSize: 16 << 20})
	if rec.Action != ActionShrink {
		t.Fatalf("expected Shrink on sustained idle; got %s reason=%s", rec.Action, rec.Reason)
	}
	if rec.NewSize != 8<<20 {
		t.Errorf("new_size = %d, want 8MB", rec.NewSize)
	}
}

func TestShrinkClampedAtMinSize(t *testing.T) {
	s := New(Config{Window: 6, MinSize: 1 << 20, ShrinkFactor: 4.0, Cooldown: time.Second})
	steady(s, 0.05, 1<<20, 10)
	t0 := time.Unix(2000, 0)
	rec := s.Observe(Sample{At: t0, Drops: 0, Occupancy: 0.05, BufferSize: 1 << 20})
	if rec.Action == ActionShrink {
		t.Fatalf("should not shrink below MinSize; got %+v", rec)
	}
}

func TestCooldownRespected(t *testing.T) {
	s := New(Config{Window: 6, MaxSize: 16 << 20, Cooldown: time.Hour})
	t0 := time.Unix(1000, 0)
	drops := uint64(0)
	// First, trigger a Grow.
	for i := 0; i < 10; i++ {
		drops += 100
		s.Observe(Sample{
			At: t0.Add(time.Duration(i) * time.Second),
			Drops: drops, Occupancy: 0.9, BufferSize: 1 << 20,
		})
	}
	// Even with continued pressure, the next recommendation should
	// be Hold ("cooldown") until the Cooldown elapses.
	rec := s.Observe(Sample{At: t0.Add(11 * time.Second), Drops: drops + 100, Occupancy: 0.9, BufferSize: 2 << 20})
	if rec.Action != ActionHold || rec.Reason != "cooldown" {
		t.Fatalf("expected cooldown hold; got %+v", rec)
	}
}

func TestHoldOnSteadyState(t *testing.T) {
	s := New(Config{Window: 8, Cooldown: time.Second})
	t0 := time.Unix(1000, 0)
	for i := 0; i < 12; i++ {
		s.Observe(Sample{
			At: t0.Add(time.Duration(i) * time.Second),
			Drops: 0, Occupancy: 0.4, BufferSize: 4 << 20,
		})
	}
	rec := s.Observe(Sample{
		At: t0.Add(15 * time.Second),
		Drops: 0, Occupancy: 0.4, BufferSize: 4 << 20,
	})
	if rec.Action != ActionHold {
		t.Fatalf("steady state should hold; got %+v", rec)
	}
}

func TestDropDeltaCorrect(t *testing.T) {
	s := New(Config{Window: 4, Cooldown: time.Second, DropRateGrow: 0.5})
	t0 := time.Unix(1000, 0)
	// Drops counter only increases; the package should reduce
	// "any drops *this tick*" by deltas.
	for i := 0; i < 5; i++ {
		s.Observe(Sample{
			At: t0.Add(time.Duration(i) * time.Second),
			Drops: uint64(i * 10), Occupancy: 0.5, BufferSize: 1 << 20,
		})
	}
	// All 5 ticks had non-zero delta → drop rate should be high.
	rec := s.Observe(Sample{
		At: t0.Add(10 * time.Second),
		Drops: 100, Occupancy: 0.5, BufferSize: 1 << 20,
	})
	if rec.DropRate < 0.5 {
		t.Fatalf("DropRate = %f, want >= 0.5", rec.DropRate)
	}
}

func TestResetClearsHistory(t *testing.T) {
	s := New(Config{Window: 4})
	steady(s, 0.5, 1<<20, 10)
	s.Reset()
	rec := s.Observe(Sample{Drops: 0, Occupancy: 0.5, BufferSize: 1 << 20})
	if rec.Reason != "warming up" {
		t.Fatalf("after Reset, first sample should be warming; got %+v", rec)
	}
}

func TestDefaultsClampedSensibly(t *testing.T) {
	s := New(Config{}) // all zeros
	if s.cfg.MinSize == 0 || s.cfg.MaxSize == 0 || s.cfg.Window == 0 {
		t.Fatal("New(zero Config) failed to fill defaults")
	}
}

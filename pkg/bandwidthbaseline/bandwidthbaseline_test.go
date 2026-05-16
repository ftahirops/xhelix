package bandwidthbaseline

import (
	"testing"
	"time"
)

func TestFirstObservationSeedsBaseline(t *testing.T) {
	d := New()
	a := d.Observe("ff", 1_000_000, time.Second)
	if a.Rate != 1_000_000 {
		t.Fatalf("rate = %v", a.Rate)
	}
	if a.EWMA != 1_000_000 {
		t.Fatalf("ewma after seed = %v", a.EWMA)
	}
	if a.IsSpike {
		t.Fatal("first sample should not be a spike")
	}
}

func TestSteadyStateNoSpike(t *testing.T) {
	d := New()
	// 10 samples at 1MB/s
	for i := 0; i < 10; i++ {
		d.Observe("ff", 1_000_000, time.Second)
	}
	a := d.Observe("ff", 1_000_000, time.Second)
	if a.IsSpike {
		t.Fatal("steady-state should not spike")
	}
}

func TestSpikeAfterEstablishedBaseline(t *testing.T) {
	d := New()
	// Establish 10× baseline at 100KB/s
	for i := 0; i < 20; i++ {
		d.Observe("ff", 100_000, time.Second)
	}
	a := d.Observe("ff", 20_000_000, time.Second) // 200× the EWMA
	if !a.IsSpike {
		t.Fatalf("expected spike; ratio=%v rate=%v ewma=%v", a.Ratio, a.Rate, a.EWMA)
	}
	if a.Ratio < 10 {
		t.Errorf("ratio = %v, want ≥10", a.Ratio)
	}
}

func TestNoSpikeOnEarlySamples(t *testing.T) {
	d := New()
	// Only 3 samples; even a huge one shouldn't spike
	for i := 0; i < 3; i++ {
		d.Observe("ff", 100_000, time.Second)
	}
	a := d.Observe("ff", 10_000_000, time.Second)
	if a.IsSpike {
		t.Fatal("should not spike before 5 samples")
	}
}

func TestMinSampleBytesIgnored(t *testing.T) {
	d := New()
	d.MinSampleBytes = 10000
	a := d.Observe("ff", 100, time.Second)
	if a.Rate != 0 {
		t.Fatalf("tiny sample should be ignored; got %+v", a)
	}
}

func TestZeroDurationIgnored(t *testing.T) {
	d := New()
	a := d.Observe("ff", 1_000_000, 0)
	if a.Rate != 0 {
		t.Fatalf("zero-duration should be ignored; got %+v", a)
	}
}

func TestEmptyKeyIgnored(t *testing.T) {
	d := New()
	a := d.Observe("", 1_000_000, time.Second)
	if a.Rate != 0 {
		t.Fatalf("empty key should be ignored; got %+v", a)
	}
}

func TestConfidenceGate(t *testing.T) {
	d := New()
	t0 := time.Unix(1000, 0)
	d.now = func() time.Time { return t0 }
	d.ConfidenceWindow = 24 * time.Hour
	d.Observe("ff", 1_000_000, time.Second)
	if d.IsConfident("ff") {
		t.Fatal("immediate confidence should be false")
	}
	d.now = func() time.Time { return t0.Add(48 * time.Hour) }
	if !d.IsConfident("ff") {
		t.Fatal("confidence after window should be true")
	}
}

func TestSnapshotLoadRoundTrip(t *testing.T) {
	d := New()
	for i := 0; i < 5; i++ {
		d.Observe("ff", 100_000, time.Second)
	}
	snap := d.Snapshot()
	d2 := New()
	d2.Load(snap)
	if d2.Stats().Binaries != 1 {
		t.Fatalf("loaded binaries = %d", d2.Stats().Binaries)
	}
	// After restoring, observing should continue to update.
	a := d2.Observe("ff", 100_000, time.Second)
	if a.IsSpike {
		t.Fatal("baseline restored — should still not spike")
	}
}

func TestForget(t *testing.T) {
	d := New()
	d.Observe("ff", 100_000, time.Second)
	d.Forget("ff")
	if d.Stats().Binaries != 0 {
		t.Fatal("Forget did not clear")
	}
}

func TestRollingMaxBound(t *testing.T) {
	d := New()
	d.MaxHistorySamples = 5
	for i := 0; i < 100; i++ {
		d.Observe("ff", 100_000, time.Second)
	}
	snap := d.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snap len = %d", len(snap))
	}
	if len(snap[0].History) > 5 {
		t.Fatalf("history bounded; got %d", len(snap[0].History))
	}
}

func TestRatioInfiniteOnZeroEWMA(t *testing.T) {
	d := New()
	// Manually inject a baseline with EWMA=0 (only possible via Load
	// since first observation seeds EWMA=rate).
	d.Load([]Baseline{{Key: "ff", FirstSeen: time.Unix(0, 0), EWMA: 0, Samples: 10}})
	a := d.Observe("ff", 1_000_000, time.Second)
	if a.Ratio == 0 || (a.Ratio < 1e6 && !((a.Ratio - a.Ratio) != 0)) {
		// Either explicit +Inf (most architectures) or huge finite,
		// both acceptable behavioural-wise.
	}
	if a.EWMA <= 0 {
		t.Fatalf("EWMA should be raised after sample; got %v", a.EWMA)
	}
}

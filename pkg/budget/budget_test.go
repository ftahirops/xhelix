package budget

import (
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)

func TestBudget_SingleAdd_NoCapsNotExceeded(t *testing.T) {
	b := NewBudget(Caps{})
	r := b.Add(t0, 50)
	if r.OperationTotal != 50 || r.HourTotal != 50 || r.DayTotal != 50 {
		t.Errorf("totals = (op=%d hr=%d day=%d), want 50/50/50",
			r.OperationTotal, r.HourTotal, r.DayTotal)
	}
	if r.AnyExceeded() {
		t.Error("no caps configured → nothing should be exceeded")
	}
}

func TestBudget_AccumulatesAcrossAdds(t *testing.T) {
	b := NewBudget(Caps{})
	for i := 0; i < 5; i++ {
		b.Add(t0.Add(time.Duration(i)*time.Second), 10)
	}
	snap := b.Snapshot()
	if snap.OperationTotal != 50 || snap.HourTotal != 50 || snap.DayTotal != 50 {
		t.Errorf("snap = %+v, want 50/50/50", snap)
	}
}

func TestBudget_OperationCapExceeded(t *testing.T) {
	b := NewBudget(Caps{MaxPerOperation: 100})
	r := b.Add(t0, 50)
	if r.OperationExceeded {
		t.Error("50 ≤ 100 should not exceed")
	}
	r = b.Add(t0, 60)
	if !r.OperationExceeded {
		t.Errorf("110 > 100 should exceed, got %+v", r)
	}
}

func TestBudget_HourCap_SlidingWindow(t *testing.T) {
	b := NewBudget(Caps{MaxPerHour: 100})

	// Add 80 at t0.
	r := b.Add(t0, 80)
	if r.HourExceeded {
		t.Fatal("80 ≤ 100, should not exceed")
	}

	// Add 30 a minute later — total within the hour = 110, should exceed.
	r = b.Add(t0.Add(1*time.Minute), 30)
	if !r.HourExceeded || r.HourTotal != 110 {
		t.Errorf("110 > 100 within 1h: got %+v", r)
	}

	// Jump so far ahead that BOTH prior adds (at t0 and t0+1) have
	// aged out of the rolling hour. Add 10 fresh.
	r = b.Add(t0.Add(62*time.Minute), 10)
	if r.HourTotal != 10 {
		t.Errorf("after 62-min advance both adds aged out, hour total = %d, want 10", r.HourTotal)
	}
	if r.HourExceeded {
		t.Errorf("10 ≤ 100 should not exceed: %+v", r)
	}

	// And a case where one of two prior adds is still inside the
	// hour: add 25 at t0+30, jump to t0+45, the 25 should still
	// count.
	b2 := NewBudget(Caps{MaxPerHour: 100})
	b2.Add(t0, 50)
	b2.Add(t0.Add(30*time.Minute), 25)
	r = b2.Add(t0.Add(45*time.Minute), 5)
	// At t0+45: t0 is 45 min ago (in-hour), t0+30 is 15 min ago
	// (in-hour), so total = 50+25+5 = 80.
	if r.HourTotal != 80 {
		t.Errorf("partial in-hour: total = %d, want 80", r.HourTotal)
	}
}

func TestBudget_DayCap_SlidingWindow(t *testing.T) {
	b := NewBudget(Caps{MaxPerDay: 100})

	b.Add(t0, 50)
	r := b.Add(t0.Add(12*time.Hour), 40)
	if r.DayTotal != 90 || r.DayExceeded {
		t.Errorf("within day: total=%d exceeded=%v, want 90 false", r.DayTotal, r.DayExceeded)
	}

	// 25 hours later: the original 50 has aged out.
	r = b.Add(t0.Add(25*time.Hour), 20)
	if r.DayTotal != 60 {
		t.Errorf("after 25h, day total = %d, want 60", r.DayTotal)
	}
}

func TestBudget_LongIdle_ClearsEntireRing(t *testing.T) {
	b := NewBudget(Caps{})
	b.Add(t0, 500)

	// 2 days later — the whole ring should be stale.
	r := b.Add(t0.Add(48*time.Hour), 10)
	if r.HourTotal != 10 || r.DayTotal != 10 {
		t.Errorf("after 48h: hour=%d day=%d, want 10/10", r.HourTotal, r.DayTotal)
	}
}

func TestBudget_ConcurrentAdds_Race(t *testing.T) {
	// -race in CI catches torn updates inside the ring.
	b := NewBudget(Caps{MaxPerHour: 1_000_000})
	var wg sync.WaitGroup
	const goroutines = 50
	const each = 200
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				b.Add(t0.Add(time.Duration(j)*time.Second), 1)
			}
		}()
	}
	wg.Wait()
	snap := b.Snapshot()
	want := uint64(goroutines * each)
	if snap.OperationTotal != want {
		t.Errorf("op total = %d, want %d", snap.OperationTotal, want)
	}
}

func TestTracker_AutoCreatesWithDefault(t *testing.T) {
	tr := NewTracker(Caps{MaxPerHour: 50})
	r := tr.Add(t0, "lineage:1", 60)
	if !r.HourExceeded {
		t.Errorf("60 > 50 should exceed under default caps: %+v", r)
	}
}

func TestTracker_RegisterOverridesDefault(t *testing.T) {
	tr := NewTracker(Caps{MaxPerHour: 50})
	tr.Register("user:8821", Caps{MaxPerHour: 1000})

	r := tr.Add(t0, "user:8821", 100)
	if r.HourExceeded {
		t.Errorf("100 ≤ 1000 (registered override) should not exceed: %+v", r)
	}
}

func TestTracker_Drop(t *testing.T) {
	tr := NewTracker(Caps{})
	tr.Add(t0, "request:abc", 10)
	if tr.Size() != 1 {
		t.Fatalf("size = %d after Add, want 1", tr.Size())
	}
	tr.Drop("request:abc")
	if tr.Size() != 0 {
		t.Errorf("size = %d after Drop, want 0", tr.Size())
	}
}

func TestTracker_SweepInactive(t *testing.T) {
	tr := NewTracker(Caps{})
	tr.Add(t0, "stale", 1)
	tr.Add(t0.Add(48*time.Hour), "fresh", 1)

	n := tr.SweepInactive(t0.Add(24 * time.Hour))
	if n != 1 {
		t.Errorf("swept %d, want 1", n)
	}
	if tr.Size() != 1 {
		t.Errorf("after sweep size = %d, want 1", tr.Size())
	}
	if _, ok := tr.Snapshot("fresh"); !ok {
		t.Error("fresh key should survive sweep")
	}
}

func TestTracker_Snapshot_UnknownKey(t *testing.T) {
	tr := NewTracker(Caps{})
	if _, ok := tr.Snapshot("never-added"); ok {
		t.Error("Snapshot of unknown key should return ok=false")
	}
}

func BenchmarkBudget_Add_SameMinute(b *testing.B) {
	bg := NewBudget(Caps{MaxPerHour: 1_000_000})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bg.Add(t0, 1)
	}
}

func BenchmarkBudget_Add_MinuteRollover(b *testing.B) {
	bg := NewBudget(Caps{MaxPerHour: 1_000_000})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bg.Add(t0.Add(time.Duration(i)*time.Minute), 1)
	}
}

func BenchmarkTracker_Add_Hot(b *testing.B) {
	tr := NewTracker(Caps{})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Add(t0, "hot-key", 1)
	}
}

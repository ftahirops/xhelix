package firerate

import (
	"sync"
	"testing"
	"time"
)

func TestIncrementAndCount(t *testing.T) {
	tr := New(60*time.Second, 60)
	tr.now = func() time.Time { return time.Unix(1000, 0) }
	for i := 0; i < 5; i++ {
		tr.Increment("r1")
	}
	if got := tr.Count("r1"); got != 5 {
		t.Fatalf("count = %d, want 5", got)
	}
}

func TestRateOverFullWindow(t *testing.T) {
	tr := New(60*time.Second, 60)
	t0 := time.Unix(1000, 0)
	for i := 0; i < 60; i++ {
		tr.now = func() time.Time { return t0.Add(time.Duration(i) * time.Second) }
		tr.Increment("r1")
	}
	// 60 fires across 60s = 1 fire/s
	tr.now = func() time.Time { return t0.Add(60 * time.Second) }
	rate := tr.Rate("r1")
	if rate < 0.9 || rate > 1.1 {
		t.Fatalf("rate = %f, want ~1.0", rate)
	}
}

func TestAgingOut(t *testing.T) {
	tr := New(10*time.Second, 10)
	t0 := time.Unix(1000, 0)
	tr.now = func() time.Time { return t0 }
	for i := 0; i < 10; i++ {
		tr.Increment("r1")
	}
	if got := tr.Count("r1"); got != 10 {
		t.Fatalf("immediate count = %d", got)
	}

	// Jump 20s forward — full rotation, ring should zero.
	tr.now = func() time.Time { return t0.Add(20 * time.Second) }
	if got := tr.Count("r1"); got != 0 {
		t.Fatalf("count after full rotation = %d, want 0", got)
	}
}

func TestPartialRotation(t *testing.T) {
	tr := New(10*time.Second, 10)
	t0 := time.Unix(1000, 0)
	// 5 fires now
	tr.now = func() time.Time { return t0 }
	for i := 0; i < 5; i++ {
		tr.Increment("r1")
	}
	// Advance 3 seconds, fire 3 more
	tr.now = func() time.Time { return t0.Add(3 * time.Second) }
	for i := 0; i < 3; i++ {
		tr.Increment("r1")
	}
	// Still within window — count = 8
	tr.now = func() time.Time { return t0.Add(5 * time.Second) }
	if got := tr.Count("r1"); got != 8 {
		t.Fatalf("count = %d, want 8", got)
	}

	// Advance until the early 5 age out (window=10s, originals at slot 0)
	tr.now = func() time.Time { return t0.Add(12 * time.Second) }
	got := tr.Count("r1")
	// First-5 are gone, second-3 still in window
	if got != 3 {
		t.Fatalf("count after partial rotation = %d, want 3", got)
	}
}

func TestSnapshotSortedByRateDesc(t *testing.T) {
	tr := New(60*time.Second, 60)
	tr.now = func() time.Time { return time.Unix(1000, 0) }

	for i := 0; i < 5; i++ {
		tr.Increment("r1")
	}
	for i := 0; i < 50; i++ {
		tr.Increment("r2")
	}
	for i := 0; i < 20; i++ {
		tr.Increment("r3")
	}

	snap := tr.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("len = %d", len(snap))
	}
	if snap[0].RuleID != "r2" || snap[1].RuleID != "r3" || snap[2].RuleID != "r1" {
		t.Fatalf("wrong order: %+v", snap)
	}
}

func TestTopN(t *testing.T) {
	tr := New(60*time.Second, 60)
	for i := 0; i < 100; i++ {
		tr.Increment("noisy")
	}
	tr.Increment("quiet")
	top := tr.Top(1)
	if len(top) != 1 || top[0].RuleID != "noisy" {
		t.Fatalf("top1 = %+v", top)
	}
}

func TestUnknownRuleReturnsZero(t *testing.T) {
	tr := New(60*time.Second, 60)
	if tr.Rate("missing") != 0 || tr.Count("missing") != 0 {
		t.Fatal("unknown rule should return 0")
	}
}

func TestReset(t *testing.T) {
	tr := New(60*time.Second, 60)
	tr.Increment("x")
	tr.Reset()
	if tr.Count("x") != 0 {
		t.Fatal("Reset did not clear counters")
	}
}

func TestConcurrentIncrement(t *testing.T) {
	tr := New(60*time.Second, 60)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				tr.Increment("r1")
			}
		}()
	}
	wg.Wait()
	if got := tr.Count("r1"); got != 5000 {
		t.Fatalf("count = %d, want 5000", got)
	}
}

func TestDefaultParams(t *testing.T) {
	tr := New(0, 0)
	if tr.window != 60*time.Second {
		t.Errorf("default window = %v", tr.window)
	}
	if tr.buckets != 60 {
		t.Errorf("default buckets = %d", tr.buckets)
	}
}

package alertdedupe

import (
	"testing"
	"time"
)

func mk(at time.Time, rule, exeSHA, dst string, w float64, reason string) Alert {
	return Alert{
		At: at, RuleID: rule, ExeSHA: exeSHA, DstIP: dst,
		Weight: w, Reason: reason,
	}
}

func TestObserveCreatesAndUpdatesCluster(t *testing.T) {
	e := NewEngine()
	t0 := time.Unix(1000, 0)
	c := e.Observe(mk(t0, "beacon.periodic", "shaA", "1.2.3.4", 5, "first"))
	if c.Count != 1 || c.Score != 5 {
		t.Fatalf("first observe: %+v", c)
	}
	c = e.Observe(mk(t0.Add(time.Second), "beacon.periodic", "shaA", "1.2.3.4", 5, "second"))
	if c.Count != 2 {
		t.Fatalf("count = %d, want 2", c.Count)
	}
	if c.Score <= 5 || c.Score > 10 {
		t.Fatalf("score = %v, want >5 and ≤10", c.Score)
	}
}

func TestClusterKeyByExeSHA(t *testing.T) {
	e := NewEngine()
	t0 := time.Unix(1000, 0)
	a := e.Observe(mk(t0, "r", "shaA", "1.1.1.1", 1, ""))
	b := e.Observe(mk(t0, "r", "shaB", "1.1.1.1", 1, "")) // different exe
	if a.Key == b.Key {
		t.Fatal("different exe_sha should produce distinct clusters")
	}
}

func TestSeverityCrossing(t *testing.T) {
	e := NewEngine()
	e.DecayHalfLife = 24 * time.Hour // basically no decay during test
	t0 := time.Unix(1000, 0)

	for i := 0; i < 20; i++ {
		_ = e.Observe(mk(t0.Add(time.Duration(i)*time.Millisecond), "r", "x", "y", 1, ""))
	}
	got := e.Promote(t0.Add(time.Second), SeverityNotice)
	if len(got) != 1 {
		t.Fatalf("promote count = %d", len(got))
	}
	if got[0].Severity < SeverityWarn {
		t.Fatalf("severity = %s, want warn+ at score=%v", got[0].Severity, got[0].Score)
	}
}

func TestDecayHalvesAcrossHalfLife(t *testing.T) {
	e := NewEngine()
	e.DecayHalfLife = time.Minute
	t0 := time.Unix(1000, 0)

	e.Observe(mk(t0, "r", "x", "y", 8, ""))
	// 60s later: should be ~4
	got := e.Promote(t0.Add(time.Minute), SeverityNone)
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	if got[0].Score < 3.0 || got[0].Score > 5.0 {
		t.Fatalf("decayed score = %v, want ~4 after one half-life", got[0].Score)
	}
}

func TestStaleClustersDropped(t *testing.T) {
	e := NewEngine()
	e.WindowDrop = time.Second
	t0 := time.Unix(1000, 0)
	e.Observe(mk(t0, "r", "x", "y", 10, ""))
	got := e.Promote(t0.Add(10*time.Second), SeverityNone)
	if len(got) != 0 {
		t.Fatalf("expected stale cluster dropped; got %+v", got)
	}
}

func TestReasonsBoundedAndOrdered(t *testing.T) {
	e := NewEngine()
	e.MaxReasons = 3
	t0 := time.Unix(1000, 0)
	for i, r := range []string{"one", "two", "three", "four", "five"} {
		e.Observe(mk(t0.Add(time.Duration(i)*time.Second), "r", "x", "y", 1, r))
	}
	got := e.Promote(t0.Add(10*time.Second), SeverityNone)
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	if len(got[0].Reasons) != 3 {
		t.Fatalf("Reasons len = %d, want 3", len(got[0].Reasons))
	}
	// Most recent first
	if got[0].Reasons[0] != "five" {
		t.Errorf("Reasons[0] = %q, want five", got[0].Reasons[0])
	}
}

func TestBucketsGroupBySeverity(t *testing.T) {
	e := NewEngine()
	e.DecayHalfLife = 24 * time.Hour
	t0 := time.Unix(1000, 0)
	// cluster A: many alerts → high severity
	for i := 0; i < 50; i++ {
		e.Observe(mk(t0.Add(time.Duration(i)*time.Millisecond), "r1", "a", "1", 1, ""))
	}
	// cluster B: few → notice/info
	for i := 0; i < 2; i++ {
		e.Observe(mk(t0.Add(time.Duration(i)*time.Millisecond), "r2", "b", "2", 1, ""))
	}
	buckets := e.Buckets(t0.Add(time.Second))
	if len(buckets[SeverityHigh])+len(buckets[SeverityCritical]) == 0 {
		t.Errorf("expected high or critical for cluster A; buckets=%+v", buckets)
	}
}

func TestReset(t *testing.T) {
	e := NewEngine()
	e.Observe(mk(time.Now(), "r", "x", "y", 1, ""))
	e.Reset()
	if len(e.Promote(time.Now(), SeverityNone)) != 0 {
		t.Fatal("Reset did not clear clusters")
	}
}

func TestCustomKeyFunc(t *testing.T) {
	e := NewEngine()
	e.KeyFunc = func(a Alert) string { return "all" }
	t0 := time.Unix(1000, 0)
	e.Observe(mk(t0, "r1", "x", "1.1.1.1", 1, ""))
	e.Observe(mk(t0, "r2", "y", "2.2.2.2", 1, ""))
	got := e.Promote(t0.Add(time.Second), SeverityNone)
	if len(got) != 1 {
		t.Fatalf("expected 1 merged cluster; got %d", len(got))
	}
	if got[0].Count != 2 {
		t.Fatalf("count = %d, want 2", got[0].Count)
	}
}

func TestPromoteOrdersByScoreDesc(t *testing.T) {
	e := NewEngine()
	e.DecayHalfLife = 24 * time.Hour
	t0 := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		e.Observe(mk(t0.Add(time.Duration(i)*time.Millisecond), "a", "x", "1", 1, ""))
	}
	for i := 0; i < 20; i++ {
		e.Observe(mk(t0.Add(time.Duration(i)*time.Millisecond), "b", "x", "2", 1, ""))
	}
	got := e.Promote(t0.Add(time.Second), SeverityNone)
	if len(got) != 2 || got[0].Score <= got[1].Score {
		t.Fatalf("expected sorted desc; got %+v", got)
	}
}

func TestDefaultWeightApplied(t *testing.T) {
	e := NewEngine()
	e.DefaultWeight = 7
	t0 := time.Unix(1000, 0)
	c := e.Observe(mk(t0, "r", "x", "y", 0, ""))
	if c.Score != 7 {
		t.Fatalf("score = %v, want 7", c.Score)
	}
}

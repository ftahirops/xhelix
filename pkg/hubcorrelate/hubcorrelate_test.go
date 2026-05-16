package hubcorrelate

import (
	"testing"
	"time"
)

func TestEmptyObservationIgnored(t *testing.T) {
	e := New()
	if c := e.Observe(Observation{}); c != nil {
		t.Fatalf("empty observation should not fire: %+v", c)
	}
	if e.Observe(Observation{HostID: "h", RuleID: "r"}) != nil {
		t.Fatal("missing Key should not fire")
	}
}

func TestSingleHostDoesNotFire(t *testing.T) {
	e := New()
	e.SetDefaultPolicy(Policy{Window: time.Hour, Threshold: 3})
	t0 := time.Unix(1000, 0)
	for i := 0; i < 10; i++ {
		c := e.Observe(Observation{
			HostID: "host-a", RuleID: "r", Key: "k", At: t0.Add(time.Duration(i) * time.Second),
		})
		if c != nil {
			t.Fatalf("single host should never fire; got %+v", c)
		}
	}
}

func TestThresholdCrossingFires(t *testing.T) {
	e := New()
	e.SetDefaultPolicy(Policy{Window: time.Hour, Threshold: 3})
	t0 := time.Unix(1000, 0)
	if c := e.Observe(Observation{HostID: "h1", RuleID: "r", Key: "k", At: t0}); c != nil {
		t.Fatal("first should not fire")
	}
	if c := e.Observe(Observation{HostID: "h2", RuleID: "r", Key: "k", At: t0.Add(time.Second)}); c != nil {
		t.Fatal("second should not fire")
	}
	c := e.Observe(Observation{HostID: "h3", RuleID: "r", Key: "k", At: t0.Add(2 * time.Second)})
	if c == nil {
		t.Fatal("third distinct host should fire")
	}
	if c.HostCount != 3 {
		t.Errorf("host_count = %d", c.HostCount)
	}
	if len(c.Hosts) != 3 {
		t.Errorf("hosts list len = %d", len(c.Hosts))
	}
}

func TestNoRefireWithinWindow(t *testing.T) {
	e := New()
	e.SetDefaultPolicy(Policy{Window: time.Hour, Threshold: 2})
	t0 := time.Unix(1000, 0)
	e.Observe(Observation{HostID: "h1", RuleID: "r", Key: "k", At: t0})
	c1 := e.Observe(Observation{HostID: "h2", RuleID: "r", Key: "k", At: t0.Add(time.Second)})
	if c1 == nil {
		t.Fatal("first crossing must fire")
	}
	c2 := e.Observe(Observation{HostID: "h3", RuleID: "r", Key: "k", At: t0.Add(2 * time.Second)})
	if c2 != nil {
		t.Fatalf("re-fire within window should be damped; got %+v", c2)
	}
}

func TestRefireAfterWindow(t *testing.T) {
	e := New()
	e.SetDefaultPolicy(Policy{Window: 10 * time.Second, Threshold: 2})
	t0 := time.Unix(1000, 0)
	e.Observe(Observation{HostID: "h1", RuleID: "r", Key: "k", At: t0})
	e.Observe(Observation{HostID: "h2", RuleID: "r", Key: "k", At: t0.Add(time.Second)}) // fires

	// Way past the window — bucket resets, two new hosts → new fire.
	tn := t0.Add(time.Hour)
	e.Observe(Observation{HostID: "h3", RuleID: "r", Key: "k", At: tn})
	c := e.Observe(Observation{HostID: "h4", RuleID: "r", Key: "k", At: tn.Add(time.Second)})
	if c == nil {
		t.Fatal("should re-fire after window elapsed and threshold re-crossed")
	}
}

func TestDuplicateHostNotCounted(t *testing.T) {
	e := New()
	e.SetDefaultPolicy(Policy{Window: time.Hour, Threshold: 3})
	t0 := time.Unix(1000, 0)
	for i := 0; i < 10; i++ {
		c := e.Observe(Observation{HostID: "h1", RuleID: "r", Key: "k", At: t0.Add(time.Duration(i) * time.Second)})
		if c != nil {
			t.Fatalf("duplicate host obs should not fire; got %+v", c)
		}
	}
}

func TestPerRulePolicy(t *testing.T) {
	e := New()
	e.SetRulePolicy("strict", Policy{Window: time.Hour, Threshold: 2})
	e.SetRulePolicy("loose", Policy{Window: time.Hour, Threshold: 10})

	t0 := time.Unix(1000, 0)
	e.Observe(Observation{HostID: "h1", RuleID: "strict", Key: "k", At: t0})
	if c := e.Observe(Observation{HostID: "h2", RuleID: "strict", Key: "k", At: t0}); c == nil {
		t.Fatal("strict rule should fire at threshold 2")
	}

	for i := 0; i < 5; i++ {
		c := e.Observe(Observation{
			HostID: "h-" + itoa(i), RuleID: "loose", Key: "k", At: t0,
		})
		if c != nil {
			t.Fatalf("loose rule fired too early at i=%d", i)
		}
	}
}

func TestSweep(t *testing.T) {
	e := New()
	e.SetDefaultPolicy(Policy{Window: 10 * time.Second, Threshold: 2})
	t0 := time.Unix(1000, 0)
	e.Observe(Observation{HostID: "h1", RuleID: "r", Key: "k", At: t0})
	e.Observe(Observation{HostID: "h2", RuleID: "r", Key: "k", At: t0})

	removed := e.Sweep(t0.Add(5 * time.Second))
	if removed != 0 {
		t.Fatalf("early sweep removed %d, want 0", removed)
	}
	removed = e.Sweep(t0.Add(60 * time.Second))
	if removed != 1 {
		t.Fatalf("late sweep removed %d, want 1", removed)
	}
}

func TestSnapshotSortedByHostCount(t *testing.T) {
	e := New()
	e.SetDefaultPolicy(Policy{Window: time.Hour, Threshold: 100}) // never fire
	t0 := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		e.Observe(Observation{HostID: "h-" + itoa(i), RuleID: "a", Key: "k", At: t0})
	}
	for i := 0; i < 2; i++ {
		e.Observe(Observation{HostID: "h-" + itoa(i), RuleID: "b", Key: "k", At: t0})
	}
	snap := e.Snapshot()
	if len(snap) != 2 || snap[0].RuleID != "a" {
		t.Fatalf("expected 'a' first (5 hosts); got %+v", snap)
	}
}

func TestTopN(t *testing.T) {
	e := New()
	e.SetDefaultPolicy(Policy{Window: time.Hour, Threshold: 100})
	t0 := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		e.Observe(Observation{HostID: "h-" + itoa(i), RuleID: "noisy", Key: "k", At: t0})
	}
	e.Observe(Observation{HostID: "h1", RuleID: "quiet", Key: "k", At: t0})
	top := e.Top(1)
	if len(top) != 1 || top[0].RuleID != "noisy" {
		t.Fatalf("top1 = %+v", top)
	}
}

func TestMaxHostsTrackedCapsListNotCount(t *testing.T) {
	e := New()
	e.SetDefaultPolicy(Policy{Window: time.Hour, Threshold: 100, MaxHostsTracked: 3})
	t0 := time.Unix(1000, 0)
	for i := 0; i < 10; i++ {
		e.Observe(Observation{HostID: "h-" + itoa(i), RuleID: "r", Key: "k", At: t0})
	}
	snap := e.Snapshot()
	if len(snap) != 1 || snap[0].HostCount != 10 {
		t.Fatalf("expected HostCount=10 (counted by set, not list); got %+v", snap)
	}
	if len(snap[0].Hosts) != 3 {
		t.Errorf("Hosts list capped at 3; got %d", len(snap[0].Hosts))
	}
}

func TestReset(t *testing.T) {
	e := New()
	e.SetDefaultPolicy(Policy{Window: time.Hour, Threshold: 2})
	t0 := time.Unix(1000, 0)
	e.Observe(Observation{HostID: "h1", RuleID: "r", Key: "k", At: t0})
	e.Reset()
	if e.Stats().Buckets != 0 {
		t.Fatal("Reset did not clear buckets")
	}
}

func TestStatsReportsCounts(t *testing.T) {
	e := New()
	e.SetDefaultPolicy(Policy{Window: time.Hour, Threshold: 2})
	t0 := time.Unix(1000, 0)
	e.Observe(Observation{HostID: "h1", RuleID: "r1", Key: "k1", At: t0})
	e.Observe(Observation{HostID: "h2", RuleID: "r1", Key: "k1", At: t0}) // fires
	e.Observe(Observation{HostID: "h1", RuleID: "r2", Key: "k2", At: t0})
	s := e.Stats()
	if s.Buckets != 2 {
		t.Errorf("buckets = %d", s.Buckets)
	}
	if s.Fired != 1 {
		t.Errorf("fired = %d, want 1", s.Fired)
	}
}

func TestSampleReasonCarried(t *testing.T) {
	e := New()
	e.SetDefaultPolicy(Policy{Window: time.Hour, Threshold: 2})
	t0 := time.Unix(1000, 0)
	e.Observe(Observation{HostID: "h1", RuleID: "r", Key: "k", At: t0, Reason: "first reason"})
	c := e.Observe(Observation{HostID: "h2", RuleID: "r", Key: "k", At: t0, Reason: "second"})
	if c == nil || c.SampleReason != "first reason" {
		t.Fatalf("first non-empty reason should be sample; got %+v", c)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

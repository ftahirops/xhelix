package lineagescore

import (
	"sync"
	"testing"
	"time"
)

func fixedLineage(root uint32) func(uint32) uint32 {
	return func(uint32) uint32 { return root }
}

func TestEngine_BelowThreshold_NoEmit(t *testing.T) {
	now := time.Unix(1000, 0)
	e := New(Opts{Threshold: 80, Window: time.Hour, LineageOf: fixedLineage(1)})
	if out := e.Observe(Signal{PID: 5, RuleID: "weak1", Weight: 20, At: now}); out != nil {
		t.Fatalf("single weak (20) below threshold (80) must not emit, got %+v", out)
	}
}

func TestEngine_CrossThreshold_EmitsOnce(t *testing.T) {
	now := time.Unix(1000, 0)
	e := New(Opts{Threshold: 80, Window: time.Hour, LineageOf: fixedLineage(1)})
	e.Observe(Signal{PID: 5, RuleID: "a", Weight: 50, At: now})
	out := e.Observe(Signal{PID: 6, RuleID: "b", Weight: 50, At: now})
	if out == nil {
		t.Fatal("crossing threshold must emit")
	}
	if out.Score < 80 {
		t.Fatalf("emitted score %d below threshold", out.Score)
	}
	if len(out.Contributors) != 2 {
		t.Fatalf("must list both contributors, got %d", len(out.Contributors))
	}
	if again := e.Observe(Signal{PID: 7, RuleID: "c", Weight: 50, At: now}); again != nil {
		t.Fatal("already-fired lineage must not re-emit within cooldown")
	}
}

func TestEngine_Decay_AgesOutOldEvidence(t *testing.T) {
	t0 := time.Unix(1000, 0)
	e := New(Opts{Threshold: 80, Window: time.Hour, LineageOf: fixedLineage(1)})
	e.Observe(Signal{PID: 5, RuleID: "a", Weight: 50, At: t0})
	if out := e.Observe(Signal{PID: 5, RuleID: "b", Weight: 50, At: t0.Add(2 * time.Hour)}); out != nil {
		t.Fatal("decayed evidence must not sum across window boundary")
	}
}

func TestEngine_FactsZeroWeight_NeverContribute(t *testing.T) {
	now := time.Unix(1000, 0)
	e := New(Opts{Threshold: 80, Window: time.Hour, LineageOf: fixedLineage(1)})
	for i := 0; i < 100; i++ {
		if out := e.Observe(Signal{PID: 5, RuleID: "fact", Weight: 0, At: now}); out != nil {
			t.Fatal("zero-weight facts must never accumulate")
		}
	}
}

func TestEngine_Deterministic(t *testing.T) {
	run := func() *Verdict {
		now := time.Unix(1000, 0)
		e := New(Opts{Threshold: 80, Window: time.Hour, LineageOf: fixedLineage(1)})
		e.Observe(Signal{PID: 5, RuleID: "a", Weight: 50, At: now})
		return e.Observe(Signal{PID: 6, RuleID: "b", Weight: 50, At: now})
	}
	a, b := run(), run()
	if a == nil || b == nil || a.Score != b.Score || len(a.Contributors) != len(b.Contributors) {
		t.Fatal("engine must be deterministic")
	}
}

func TestEngine_SeparateLineagesIndependent(t *testing.T) {
	now := time.Unix(1000, 0)
	e := New(Opts{Threshold: 80, Window: time.Hour, LineageOf: func(p uint32) uint32 {
		if p%2 == 0 {
			return 100
		}
		return 200
	}})
	e.Observe(Signal{PID: 2, RuleID: "a", Weight: 50, At: now})
	if out := e.Observe(Signal{PID: 3, RuleID: "b", Weight: 50, At: now}); out != nil {
		t.Fatal("signals on different lineages must not sum together")
	}
}

func TestEngine_CooldownExpiry_AllowsReEmit(t *testing.T) {
	t0 := time.Unix(1000, 0)
	e := New(Opts{Threshold: 80, Window: 4 * time.Hour, Cooldown: time.Hour, LineageOf: fixedLineage(1)})
	e.Observe(Signal{PID: 5, RuleID: "a", Weight: 50, At: t0})
	if e.Observe(Signal{PID: 5, RuleID: "b", Weight: 50, At: t0}) == nil {
		t.Fatal("should fire first time")
	}
	if e.Observe(Signal{PID: 5, RuleID: "c", Weight: 50, At: t0.Add(90 * time.Minute)}) == nil {
		t.Fatal("after cooldown expiry with score still over threshold, must re-emit")
	}
}

func TestEngine_ConcurrentObserve_NoRace(t *testing.T) {
	now := time.Unix(1000, 0)
	e := New(Opts{Threshold: 1000000, Window: time.Hour, LineageOf: func(p uint32) uint32 { return p }})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			e.Observe(Signal{PID: uint32(n), RuleID: "r", Weight: 10, At: now})
		}(i)
	}
	wg.Wait()
}

func TestVerdict_HasTier(t *testing.T) {
	now := time.Unix(1000, 0)
	e := New(Opts{Threshold: 80, Window: time.Hour, LineageOf: fixedLineage(1)})
	e.Observe(Signal{PID: 5, RuleID: "a", Weight: 70, At: now})
	v := e.Observe(Signal{PID: 5, RuleID: "b", Weight: 70, At: now}) // cum 140 -> critical
	if v == nil {
		t.Fatal("should emit")
	}
	if v.Tier != "critical" {
		t.Fatalf("score %d must be tier critical, got %q", v.Score, v.Tier)
	}
}

func TestVerdict_TierHigh(t *testing.T) {
	now := time.Unix(1000, 0)
	e := New(Opts{Threshold: 80, Window: time.Hour, LineageOf: fixedLineage(1)})
	e.Observe(Signal{PID: 5, RuleID: "a", Weight: 50, At: now})
	v := e.Observe(Signal{PID: 5, RuleID: "b", Weight: 50, At: now}) // cum 100 -> high
	if v == nil || v.Tier != "high" {
		t.Fatalf("score 100 must be tier high, got %+v", v)
	}
}

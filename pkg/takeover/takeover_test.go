package takeover

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/actionlog"
	"github.com/xhelix/xhelix/pkg/decision"
	"github.com/xhelix/xhelix/pkg/model"
)

func TestScorer_SingleDeterministicSignalCrossesSuspended(t *testing.T) {
	s := NewScorer(nil)
	r := s.Score([]Signal{{Kind: SignalCanaryTouch}})
	if r.Score < 75 {
		t.Fatalf("canary touch alone should cross 75 (suspended): got %d", r.Score)
	}
}

func TestScorer_DiminishingReturnsOnSameKind(t *testing.T) {
	s := NewScorer(nil)
	sigs := []Signal{
		{Kind: SignalNewBinary}, {Kind: SignalNewBinary},
		{Kind: SignalNewBinary}, {Kind: SignalNewBinary},
	}
	r := s.Score(sigs)
	// 20 + 10 + 5 + 2 = 37 (each integer-rounded)
	if r.Score >= 80 {
		t.Fatalf("4 same-kind signals should diminish, not saturate: got %d", r.Score)
	}
	// One signal alone would be just 20; should be higher after stacking.
	if r.Score <= 20 {
		t.Fatalf("stacking should still add some score: got %d", r.Score)
	}
}

func TestScorer_StackingDifferentKindsAccumulates(t *testing.T) {
	s := NewScorer(nil)
	// Two Tier-2 signals — should cross suspended without any Tier-1.
	sigs := []Signal{
		{Kind: SignalCredAccess},
		{Kind: SignalPersistence},
	}
	r := s.Score(sigs)
	if r.Score < 75 {
		t.Fatalf("credaccess + persistence should cross suspended: got %d", r.Score)
	}
}

func TestScorer_WeightOverride(t *testing.T) {
	s := NewScorer(nil)
	// Force a high-severity rule hit via Weight override.
	r := s.Score([]Signal{{Kind: SignalRuleHit, Weight: 90}})
	if r.Score < 90 {
		t.Fatalf("Weight override should apply: got %d", r.Score)
	}
}

func TestScorer_Clamps(t *testing.T) {
	s := NewScorer(nil)
	// Pile on tons of high-weight signals.
	var sigs []Signal
	for i := 0; i < 20; i++ {
		sigs = append(sigs, Signal{Kind: SignalCanaryTouch})
	}
	r := s.Score(sigs)
	if r.Score > 100 {
		t.Fatalf("score must clamp at 100: got %d", r.Score)
	}
}

func TestAggregator_TTLEviction(t *testing.T) {
	a := NewAggregator(50 * time.Millisecond)
	now := time.Now().UTC()
	a.Record(Signal{LineageID: 1, Kind: SignalCanaryTouch, At: now.Add(-200 * time.Millisecond)})
	a.Record(Signal{LineageID: 1, Kind: SignalNewBinary, At: now})

	got := a.Snapshot(1, now)
	if len(got) != 1 {
		t.Fatalf("expected 1 live signal after TTL eviction, got %d", len(got))
	}
	if got[0].Kind != SignalNewBinary {
		t.Fatalf("wrong signal kept: %v", got[0].Kind)
	}
}

func TestAggregator_AttributedIPsDistinct(t *testing.T) {
	a := NewAggregator(0)
	a.Record(Signal{LineageID: 7, Kind: SignalLateralMove, RemoteIP: "1.2.3.4"})
	a.Record(Signal{LineageID: 7, Kind: SignalLateralMove, RemoteIP: "1.2.3.4"}) // dup
	a.Record(Signal{LineageID: 7, Kind: SignalLateralMove, RemoteIP: "5.6.7.8"})

	ips := a.AttributedIPs(7)
	if len(ips) != 2 || ips[0] != "1.2.3.4" || ips[1] != "5.6.7.8" {
		t.Fatalf("AttributedIPs wrong: %v", ips)
	}
}

func TestAggregator_Lineages(t *testing.T) {
	a := NewAggregator(time.Hour)
	a.Record(Signal{LineageID: 1, Kind: SignalNewBinary})
	a.Record(Signal{LineageID: 5, Kind: SignalLOTL})
	a.Record(Signal{LineageID: 3, Kind: SignalCredAccess})

	got := a.Lineages(time.Now().UTC())
	if len(got) != 3 || got[0] != 1 || got[1] != 3 || got[2] != 5 {
		t.Fatalf("Lineages wrong order: %v", got)
	}
}

func TestAggregator_Forget(t *testing.T) {
	a := NewAggregator(0)
	a.Record(Signal{LineageID: 1, Kind: SignalCanaryTouch, RemoteIP: "1.1.1.1"})
	a.Forget(1)
	if got := a.Snapshot(1, time.Now()); len(got) != 0 {
		t.Fatalf("Forget should drop signals: %v", got)
	}
	if got := a.AttributedIPs(1); len(got) != 0 {
		t.Fatalf("Forget should drop IPs: %v", got)
	}
}

func TestAggregator_Concurrent(t *testing.T) {
	a := NewAggregator(time.Hour)
	var wg sync.WaitGroup
	for i := uint64(1); i <= 100; i++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			a.Record(Signal{LineageID: id, Kind: SignalNewBinary})
		}(i)
	}
	wg.Wait()
	if got := len(a.Lineages(time.Now().UTC())); got != 100 {
		t.Fatalf("concurrent records: got %d lineages, want 100", got)
	}
}

func TestPlanner_HappyPath_EmitsSuspend(t *testing.T) {
	p := NewPlanner(PlannerConfig{
		State: actionlog.New(),
	})
	// Canary touch alone is Tier-1; should produce a Suspend-or-stronger plan.
	p.OnSignal(Signal{LineageID: 42, Kind: SignalCanaryTouch, Source: "test"})

	plan := p.Plan(42, time.Now().UTC())
	if plan == nil {
		t.Fatal("expected non-nil plan")
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("plan invalid: %v", err)
	}
	if !plan.IsHardAction() {
		t.Fatalf("canary touch should produce hard action; got actions=%v", plan.Actions())
	}
	if plan.LineageID != 42 {
		t.Fatalf("lineage not propagated: %d", plan.LineageID)
	}
	if !strings.Contains(plan.RuleID, "takeover.composite") {
		t.Fatalf("RuleID should be takeover.composite, got %q", plan.RuleID)
	}
}

func TestPlanner_SubThreshold_NoPlanIfObserved(t *testing.T) {
	log := actionlog.New()
	p := NewPlanner(PlannerConfig{State: log})
	p.OnSignal(Signal{LineageID: 7, Kind: SignalNewEndpoint}) // weight 15

	if got := p.Plan(7, time.Now().UTC()); got != nil {
		t.Fatalf("sub-threshold with no current state should be nil; got %+v", got)
	}
}

func TestPlanner_SubThreshold_EmitsHoldIfElevated(t *testing.T) {
	log := actionlog.New()
	_ = log.Record(actionlog.Transition{
		LineageID: 7, To: actionlog.StateSuspended, Reason: "earlier", PlanID: "p0",
	})

	p := NewPlanner(PlannerConfig{State: log})
	p.OnSignal(Signal{LineageID: 7, Kind: SignalNewEndpoint}) // weight 15
	plan := p.Plan(7, time.Now().UTC())
	if plan == nil {
		t.Fatal("expected plan to hold current state, got nil")
	}
	if plan.Tier != "suspended" {
		t.Fatalf("expected hold at suspended; got %q", plan.Tier)
	}
}

func TestPlanner_PreconditionProbe(t *testing.T) {
	p := NewPlanner(PlannerConfig{
		State: actionlog.New(),
		PreconditionProbe: func() (bool, bool) {
			return true, true
		},
	})
	// Pile signals to push score to 100.
	for i := 0; i < 3; i++ {
		p.OnSignal(Signal{LineageID: 1, Kind: SignalCanaryTouch})
		p.OnSignal(Signal{LineageID: 1, Kind: SignalDefenseEvasion})
	}
	plan := p.Plan(1, time.Now().UTC())
	if plan == nil {
		t.Fatal("expected plan")
	}
	if !plan.IsolateHost {
		t.Fatalf("with bastion+mirror probe true, should set IsolateHost; got actions=%v warnings=%v", plan.Actions(), plan.CapabilityWarnings)
	}
}

func TestPlanner_ResolveCJTierUpgrades(t *testing.T) {
	p := NewPlanner(PlannerConfig{
		State: actionlog.New(),
		ResolveCJTier: func(_ model.Alert) string { return "L1" },
	})
	// Low score signal — would normally be observed.
	p.OnSignal(Signal{LineageID: 1, Kind: SignalNewEndpoint})

	// Use PlanFromAlert so the CJ resolver is consulted directly.
	alert := model.Alert{Event: model.NewEvent("test", model.SeverityWarn), RuleID: "r"}
	plan := p.PlanFromAlert(alert, 1, time.Now().UTC())
	if plan == nil {
		t.Fatal("expected plan with CJ upgrade")
	}
	if plan.Tier != "suspended" {
		t.Fatalf("CJ L1 should upgrade to suspended; got %q", plan.Tier)
	}
}

func TestPlanner_AttributedIPsFlowToPlan(t *testing.T) {
	p := NewPlanner(PlannerConfig{State: actionlog.New()})
	p.OnSignal(Signal{LineageID: 1, Kind: SignalCanaryTouch, RemoteIP: "9.9.9.9"})
	plan := p.Plan(1, time.Now().UTC())
	if plan == nil {
		t.Fatal("expected plan")
	}
	if !plan.BanRemoteIP {
		t.Fatalf("BanRemoteIP should be on with attribution; actions=%v", plan.Actions())
	}
}

func TestPlanner_CapsAnnotateInvoked(t *testing.T) {
	called := false
	p := NewPlanner(PlannerConfig{
		State: actionlog.New(),
		Caps: capsFunc(func(plan *decision.ActionPlan) {
			called = true
			plan.CapabilityWarnings = append(plan.CapabilityWarnings, "from-caps")
		}),
	})
	p.OnSignal(Signal{LineageID: 1, Kind: SignalCanaryTouch})
	plan := p.Plan(1, time.Now().UTC())
	if plan == nil {
		t.Fatal("expected plan")
	}
	if !called {
		t.Fatal("Caps.AnnotatePlan should be invoked")
	}
}

func TestPlanner_NoSignals_NoPlan(t *testing.T) {
	p := NewPlanner(PlannerConfig{State: actionlog.New()})
	if got := p.Plan(99, time.Now().UTC()); got != nil {
		t.Fatalf("no signals should produce nil plan: %+v", got)
	}
}

type capsFunc func(*decision.ActionPlan)

func (f capsFunc) AnnotatePlan(p *decision.ActionPlan) { f(p) }

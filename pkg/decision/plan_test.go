package decision

import (
	"strings"
	"testing"

	"github.com/oklog/ulid/v2"

	"github.com/xhelix/xhelix/pkg/actionlog"
	"github.com/xhelix/xhelix/pkg/model"
)

func mkAlert(rule string, mode model.RuleMode) model.Alert {
	ev := model.NewEvent("test", model.SeverityHigh)
	return model.Alert{Event: ev, RuleID: rule, Mode: mode}
}

func TestPlan_ScoreThresholds(t *testing.T) {
	cases := []struct {
		score    int
		wantTier string
	}{
		{10, "observed"},
		{49, "observed"},
		{50, "triaged"},
		{74, "triaged"},
		{75, "suspended"},
		{89, "suspended"},
		{90, "isolated"},
		{99, "isolated"},
		{100, "isolated"}, // contained downgrades w/o bastion (see TestPlan_Layer5)
	}
	for _, c := range cases {
		p := Plan(Input{
			Alert: mkAlert("test.rule", model.ModeDetect),
			Score: c.score,
		})
		if err := p.Validate(); err != nil {
			t.Fatalf("score=%d: plan invalid: %v", c.score, err)
		}
		if p.Tier != c.wantTier {
			t.Errorf("score=%d: tier=%q want %q (actions=%v)",
				c.score, p.Tier, c.wantTier, p.Actions())
		}
	}
}

func TestPlan_Layer5_DowngradesWithoutBastion(t *testing.T) {
	p := Plan(Input{
		Alert: mkAlert("crit", model.ModeDetect),
		Score: 100,
		// No bastion / mirror.
	})
	if p.IsolateHost {
		t.Fatal("Score=100 without bastion should NOT set IsolateHost")
	}
	if p.Tier != "isolated" {
		t.Fatalf("tier=%q want isolated (downgraded)", p.Tier)
	}
	hasWarning := false
	for _, w := range p.CapabilityWarnings {
		if strings.Contains(w, "bastion") {
			hasWarning = true
		}
	}
	if !hasWarning {
		t.Fatalf("expected bastion capability warning, got %v", p.CapabilityWarnings)
	}
}

func TestPlan_Layer5_AllowedWithBastion(t *testing.T) {
	p := Plan(Input{
		Alert:                  mkAlert("crit", model.ModeDetect),
		Score:                  100,
		BastionAvailable:       true,
		OffHostMirrorAvailable: true,
	})
	if !p.IsolateHost {
		t.Fatal("Score=100 + bastion + mirror should set IsolateHost")
	}
	if p.Tier != "contained" {
		t.Fatalf("tier=%q want contained", p.Tier)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("plan invalid: %v", err)
	}
}

func TestPlan_RuleModeUpgrade(t *testing.T) {
	// ModeQuarantine forces at least suspended even at low score.
	p := Plan(Input{
		Alert: mkAlert("r", model.ModeQuarantine),
		Score: 10,
	})
	if p.Tier != "suspended" {
		t.Fatalf("ModeQuarantine should force suspended; got %q", p.Tier)
	}

	// ModeBlock forces isolated.
	p = Plan(Input{
		Alert: mkAlert("r", model.ModeBlock),
		Score: 10,
	})
	if p.Tier != "isolated" {
		t.Fatalf("ModeBlock should force isolated; got %q", p.Tier)
	}
}

func TestPlan_CrownJewelUpgrade(t *testing.T) {
	// L1 forces at least suspended even at sub-threshold scores.
	p := Plan(Input{
		Alert:          mkAlert("r", model.ModeDetect),
		Score:          20,
		CrownJewelTier: "L1",
	})
	if p.Tier != "suspended" {
		t.Fatalf("CJ tier L1 should force suspended; got %q", p.Tier)
	}

	// L3 forces at least triaged.
	p = Plan(Input{
		Alert:          mkAlert("r", model.ModeDetect),
		Score:          10,
		CrownJewelTier: "L3",
	})
	if p.Tier != "triaged" {
		t.Fatalf("CJ tier L3 should force triaged; got %q", p.Tier)
	}
}

func TestPlan_NoDeEscalation(t *testing.T) {
	log := actionlog.New()
	// Lineage 1 is already isolated.
	_ = log.Record(actionlog.Transition{
		LineageID: 1, To: actionlog.StateSuspended, Reason: "x", PlanID: "p0",
	})
	_ = log.Record(actionlog.Transition{
		LineageID: 1, From: actionlog.StateSuspended,
		To: actionlog.StateIsolated, Reason: "x", PlanID: "p0a",
	})

	// New event scores only 55 (would be triaged), but we should NOT
	// downgrade.
	p := Plan(Input{
		Alert:     mkAlert("r", model.ModeDetect),
		Score:     55,
		LineageID: 1,
		State:     log,
	})
	if p.Tier == "triaged" || p.Tier == "observed" {
		t.Fatalf("must not de-escalate; got %q", p.Tier)
	}
	if p.Tier != "isolated" {
		t.Fatalf("expected hold at isolated; got %q", p.Tier)
	}
}

func TestPlan_AttributionGatesBan(t *testing.T) {
	// Suspended plan but no attributed IP → BanRemoteIP must be off.
	p := Plan(Input{
		Alert: mkAlert("r", model.ModeDetect),
		Score: 80,
	})
	if p.BanRemoteIP {
		t.Fatal("BanRemoteIP must be off with no attribution")
	}
	hasNote := false
	for _, r := range p.Reasons {
		if strings.Contains(r, "ban_remote_ip skipped") {
			hasNote = true
		}
	}
	if !hasNote {
		t.Fatalf("expected skip-reason recorded, got %v", p.Reasons)
	}

	// With attribution it's enabled.
	p = Plan(Input{
		Alert:         mkAlert("r", model.ModeDetect),
		Score:         80,
		AttributedIPs: []string{"1.2.3.4"},
	})
	if !p.BanRemoteIP {
		t.Fatal("BanRemoteIP must be on with attribution")
	}
}

func TestPlan_ProvenanceFields(t *testing.T) {
	a := mkAlert("rule.x", model.ModeDetect)
	a.Reason = "matched 3 indicators"
	p := Plan(Input{
		Alert:     a,
		Score:     80,
		LineageID: 99,
		ProcKey:   "1234@5678",
	})
	if p.PlanID == "" {
		t.Fatal("PlanID should be assigned")
	}
	if _, err := ulid.Parse(p.PlanID); err != nil {
		t.Fatalf("PlanID should be ULID: %v", err)
	}
	if p.RuleID != "rule.x" {
		t.Fatalf("RuleID=%q want rule.x", p.RuleID)
	}
	if p.LineageID != 99 || p.ProcKey != "1234@5678" {
		t.Fatalf("lineage/procKey not propagated: %+v", p)
	}
	if p.AlertID != a.Event.ID.String() {
		t.Fatal("AlertID should be Event.ID")
	}
	hasReason := false
	for _, r := range p.Reasons {
		if strings.Contains(r, "matched 3 indicators") {
			hasReason = true
		}
	}
	if !hasReason {
		t.Fatalf("alert reason not surfaced: %v", p.Reasons)
	}
}

func TestPlan_CapabilityCheckerInvoked(t *testing.T) {
	called := false
	caps := capsFunc(func(p *ActionPlan) {
		called = true
		p.CapabilityWarnings = append(p.CapabilityWarnings, "test-warning")
	})
	p := Plan(Input{
		Alert: mkAlert("r", model.ModeDetect),
		Score: 80,
		Caps:  caps,
	})
	if !called {
		t.Fatal("CapabilityChecker.AnnotatePlan must be called")
	}
	if len(p.CapabilityWarnings) == 0 || p.CapabilityWarnings[len(p.CapabilityWarnings)-1] != "test-warning" {
		t.Fatalf("warning not attached: %v", p.CapabilityWarnings)
	}
}

func TestPlan_NoOpValid(t *testing.T) {
	p := Plan(Input{
		Alert: mkAlert("r", model.ModeDetect),
		Score: 10,
	})
	if !p.IsNoOp() {
		t.Fatalf("score=10 should be no-op; actions=%v", p.Actions())
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("no-op plan must validate: %v", err)
	}
}

// capsFunc is a test helper that satisfies CapabilityChecker.
type capsFunc func(*ActionPlan)

func (f capsFunc) AnnotatePlan(p *ActionPlan) { f(p) }

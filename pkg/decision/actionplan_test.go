package decision

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewNoOp_IsNoOp(t *testing.T) {
	p := NewNoOp("a1", "p1")
	if !p.IsNoOp() {
		t.Fatalf("NewNoOp should be no-op, got actions=%v", p.Actions())
	}
	if p.IsHardAction() {
		t.Fatal("NoOp is not a hard action")
	}
	if p.HasDestructiveAction() {
		t.Fatal("NoOp is not destructive")
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("NoOp should validate: %v", err)
	}
}

func TestNewSoftBlock_Fields(t *testing.T) {
	p := NewSoftBlock("a1", "p1", 55)
	if p.Score != 55 || p.Tier != "triaged" {
		t.Fatalf("bad fields: %+v", p)
	}
	if !p.RequireStepUp || p.Delay <= 0 {
		t.Fatal("SoftBlock should set RequireStepUp + Delay")
	}
	if p.IsHardAction() {
		t.Fatal("SoftBlock must not be a hard action")
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("SoftBlock should validate: %v", err)
	}
}

func TestNewSuspend_OrderAndFields(t *testing.T) {
	p := NewSuspend("a1", "p1", 80)
	got := p.Actions()
	want := []string{"snapshot", "suspend_process", "isolate_cgroup", "ban_remote_ip"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Suspend actions order wrong:\n got %v\nwant %v", got, want)
	}
	if !p.IsHardAction() {
		t.Fatal("Suspend must be a hard action")
	}
	if !p.Reversible {
		t.Fatal("Suspend should default Reversible=true")
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Suspend should validate: %v", err)
	}
}

func TestNewContain_RequiresPreconditions(t *testing.T) {
	// Without preconditions, Validate must reject.
	p := &ActionPlan{
		AlertID: "a1", PlanID: "p1", Score: 95, Tier: "contained",
		Snapshot: true, IsolateHost: true, Reversible: true,
	}
	if err := p.Validate(); err == nil {
		t.Fatal("IsolateHost with no preconditions should fail validation")
	}

	// With preconditions, valid.
	p2 := NewContain("a1", "p1", 95, []string{"bastion_count>=2", "off_host_mirror"})
	if err := p2.Validate(); err != nil {
		t.Fatalf("Contain with preconditions should validate: %v", err)
	}
	if !p2.IsolateHost {
		t.Fatal("Contain should set IsolateHost")
	}
}

func TestValidate_KillRequiresSnapshot(t *testing.T) {
	p := &ActionPlan{
		AlertID: "a1", PlanID: "p1", Score: 100,
		KillProcess: true, Reversible: false,
		// no Snapshot
	}
	if err := p.Validate(); err == nil {
		t.Fatal("KillProcess without Snapshot should fail")
	}

	p.Snapshot = true
	if err := p.Validate(); err != nil {
		t.Fatalf("Kill+Snapshot+!Reversible should validate: %v", err)
	}
}

func TestValidate_KillCannotBeReversible(t *testing.T) {
	p := &ActionPlan{
		AlertID: "a1", PlanID: "p1", Score: 100,
		Snapshot: true, KillProcess: true, Reversible: true,
	}
	if err := p.Validate(); err == nil {
		t.Fatal("Kill with Reversible=true should fail")
	}
}

func TestValidate_RemediateFileCannotBeReversible(t *testing.T) {
	p := &ActionPlan{
		AlertID: "a1", PlanID: "p1", Score: 100,
		RemediateFile: true, Reversible: true,
	}
	if err := p.Validate(); err == nil {
		t.Fatal("RemediateFile with Reversible=true should fail")
	}
}

func TestValidate_TarpitRequiresReasons(t *testing.T) {
	p := &ActionPlan{
		AlertID: "a1", PlanID: "p1", Score: 90,
		Tarpit: true, Reversible: true,
	}
	if err := p.Validate(); err == nil {
		t.Fatal("Tarpit without Reasons should fail (attribution required)")
	}

	p.Reasons = []string{"sensor:netids matched IP 1.2.3.4 to lineage"}
	if err := p.Validate(); err != nil {
		t.Fatalf("Tarpit with Reasons should validate: %v", err)
	}
}

func TestValidate_ScoreRange(t *testing.T) {
	p := NewNoOp("a1", "p1")
	p.Score = 101
	if err := p.Validate(); err == nil {
		t.Fatal("Score=101 should fail")
	}
	p.Score = -1
	if err := p.Validate(); err == nil {
		t.Fatal("Score=-1 should fail")
	}
}

func TestValidate_Provenance(t *testing.T) {
	p := &ActionPlan{PlanID: "p1"} // no AlertID and no RuleID
	if err := p.Validate(); err == nil {
		t.Fatal("plan with no AlertID and no RuleID should fail")
	}

	p2 := &ActionPlan{AlertID: "a1"} // no PlanID
	if err := p2.Validate(); err == nil {
		t.Fatal("plan with no PlanID should fail")
	}
}

func TestHasExpired(t *testing.T) {
	p := NewNoOp("a1", "p1")
	if p.HasExpired(time.Now()) {
		t.Fatal("zero ExpiresAt means never expires")
	}
	p.ExpiresAt = time.Now().Add(-1 * time.Hour)
	if !p.HasExpired(time.Now()) {
		t.Fatal("past ExpiresAt should report expired")
	}
}

func TestAddCapabilityWarning(t *testing.T) {
	p := NewSuspend("a1", "p1", 80)
	p.AddCapabilityWarning("CAP_NET_ADMIN", "ban_remote_ip")
	if len(p.CapabilityWarnings) != 1 {
		t.Fatalf("warning not recorded: %v", p.CapabilityWarnings)
	}
	if !strings.Contains(p.CapabilityWarnings[0], "CAP_NET_ADMIN") {
		t.Fatalf("warning text wrong: %v", p.CapabilityWarnings[0])
	}
}

func TestJSONStability(t *testing.T) {
	p := NewSuspend("a1", "p1", 80)
	p.Reasons = []string{"canary touched"}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	// Stable field names — these are wire format.
	for _, must := range []string{
		`"alert_id"`, `"plan_id"`, `"score"`, `"snapshot"`,
		`"suspend_process"`, `"isolate_cgroup"`, `"ban_remote_ip"`,
		`"reversible"`, `"created_at"`,
	} {
		if !strings.Contains(s, must) {
			t.Fatalf("JSON missing %s: %s", must, s)
		}
	}
	// Omitempty should hide unset bits.
	if strings.Contains(s, `"kill_process"`) {
		t.Fatalf("kill_process should be omitempty: %s", s)
	}
}

func TestActions_OrderIsCanonical(t *testing.T) {
	// Set every bit and check order.
	p := &ActionPlan{
		AlertID: "a1", PlanID: "p1", Snapshot: true, Memscan: true,
		Delay: time.Second, RequireStepUp: true, SuspendProcess: true,
		IsolateCgroup: true, BanRemoteIP: true, Tarpit: true,
		IsolateHost: true, RemediateFile: true, LockLocalUser: true,
		KillProcess: true, Reasons: []string{"r"},
		Preconditions: []string{"p"}, Reversible: false,
	}
	got := p.Actions()
	want := []string{
		"snapshot", "memscan", "delay", "require_step_up",
		"suspend_process", "isolate_cgroup", "ban_remote_ip",
		"tarpit", "isolate_host", "remediate_file",
		"lock_local_user", "kill_process",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Actions order:\n got %v\nwant %v", got, want)
	}
}

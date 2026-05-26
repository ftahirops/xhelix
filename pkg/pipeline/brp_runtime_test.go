package pipeline

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/brp"
	brpphase "github.com/xhelix/xhelix/pkg/brp/phase"
	parser "github.com/xhelix/xhelix/pkg/brp/parser"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/verify"
)

// TestBRP_PipelineEndToEnd verifies the full wiring:
//
//  1. Build a signed nginx-reverse-proxy profile in-memory.
//  2. Stuff it into a Matcher.
//  3. Hand the Matcher to a Pipeline.
//  4. Send a forged exec event "nginx tried to spawn /bin/sh".
//  5. Assert: event tags include brp_decision=hard_deny AND the alert
//     bus received a brp.hard_deny alert.
//
// This test is the contract for `evaluateBRP` — it must fire on the
// canonical "web role exec shell" pattern with NO profile-specific
// configuration beyond the role identity.
func TestBRP_PipelineEndToEnd(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	profile := brp.Profile{
		SchemaVersion: brp.SchemaVersion,
		ProfileID:     "test-nginx-rp-v1",
		Confidence:    brp.ConfidenceStrict,
		SigningEpoch:  time.Now().UnixNano(),
		VersionRange:  "1.24.0",
		Key: parser.ProfileKey{
			App:      "nginx",
			Role:     "nginx-reverse-proxy",
			OSFamily: "debian12",
		},
		Behavior: parser.ConfigDerivedBehavior{
			Role:          "nginx-reverse-proxy",
			ListenPorts:   []int{80, 443},
			UpstreamHosts: []string{"127.0.0.1:8080"},
		},
	}
	signed, err := brp.Sign(profile, "test-signer", priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	m := brp.NewMatcher(map[string]ed25519.PublicKey{"test-signer": pub})
	if err := m.AddProfile(signed); err != nil {
		t.Fatalf("add profile: %v", err)
	}

	var emitted []model.Alert
	p := &Pipeline{
		BRPMatcher: m,
		BRPRuntime: brp.NewRuntime(brp.DefaultInvariants()),
		BRPPhases:  brpphase.NewTracker(0, 0, 0),
		Emit:       func(a model.Alert) { emitted = append(emitted, a) },
	}

	// Forged exec event: nginx (role=nginx-reverse-proxy) spawning
	// /bin/sh. The role tag is what triggers the role-invariant rule.
	ev := model.NewEvent("ebpf.proc", model.SeverityWarn)
	ev.PID = 1234
	ev.ParentPID = 1
	ev.Image = "/bin/sh"
	ev.Tags["kind"] = "proc_exec"
	ev.Tags["app_id"] = "nginx"
	ev.Tags["app_version"] = "1.24.0"
	ev.Tags["os_family"] = "debian12"
	ev.Tags["app_role"] = "nginx-reverse-proxy"
	ev.Tags["image"] = "/bin/sh"

	p.evaluateBRP(ev)

	if got := ev.Tags["brp_decision"]; got != "hard_deny" {
		t.Errorf("brp_decision=%q, want hard_deny", got)
	}
	if got := ev.Tags["brp_profile"]; got != "test-nginx-rp-v1" {
		t.Errorf("brp_profile=%q, want test-nginx-rp-v1", got)
	}
	if got := ev.Tags["brp_phase"]; got != "bootstrap" {
		t.Errorf("brp_phase=%q, want bootstrap (first observe)", got)
	}
	if len(emitted) != 1 {
		t.Fatalf("emitted alerts = %d, want 1", len(emitted))
	}
	if emitted[0].RuleID != "brp.hard_deny" {
		t.Errorf("alert.RuleID=%q, want brp.hard_deny", emitted[0].RuleID)
	}
	if emitted[0].Class != 1 {
		t.Errorf("alert.Class=%d, want 1 (hard invariant)", emitted[0].Class)
	}
}

// TestBRP_PipelineAllowsDeclaredUpstream confirms that an upstream connect
// declared in the profile envelope returns DecisionAllow (no alert).
func TestBRP_PipelineAllowsDeclaredUpstream(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	profile := brp.Profile{
		SchemaVersion: brp.SchemaVersion,
		ProfileID:     "test-nginx-rp-v1",
		Confidence:    brp.ConfidenceStrict,
		SigningEpoch:  time.Now().UnixNano(),
		Key: parser.ProfileKey{App: "nginx", Role: "nginx-reverse-proxy"},
		Behavior: parser.ConfigDerivedBehavior{
			UpstreamHosts: []string{"127.0.0.1:8080"},
		},
	}
	signed, _ := brp.Sign(profile, "test-signer", priv)
	m := brp.NewMatcher(map[string]ed25519.PublicKey{"test-signer": pub})
	if err := m.AddProfile(signed); err != nil {
		t.Fatalf("add: %v", err)
	}

	var emitted []model.Alert
	p := &Pipeline{
		BRPMatcher: m,
		BRPRuntime: brp.NewRuntime(brp.DefaultInvariants()),
		Emit:       func(a model.Alert) { emitted = append(emitted, a) },
	}

	ev := model.NewEvent("ebpf.net", model.SeverityInfo)
	ev.PID = 999
	ev.Tags["kind"] = "net_connect"
	ev.Tags["app_id"] = "nginx"
	ev.Tags["app_role"] = "nginx-reverse-proxy"
	ev.Tags["dst_ip"] = "127.0.0.1"
	ev.Tags["dst_port"] = "8080"

	p.evaluateBRP(ev)

	if got := ev.Tags["brp_decision"]; got != "allow" {
		t.Errorf("brp_decision=%q, want allow", got)
	}
	if len(emitted) != 0 {
		t.Errorf("declared upstream must not alert, got %d", len(emitted))
	}
}

// TestBRP_PipelineUnprofiled confirms an event with no matching profile
// returns DecisionUnknown (log-only, no alert).
func TestBRP_PipelineUnprofiled(t *testing.T) {
	m := brp.NewMatcher(nil)
	var emitted []model.Alert
	p := &Pipeline{
		BRPMatcher: m,
		BRPRuntime: brp.NewRuntime(brp.DefaultInvariants()),
		Emit:       func(a model.Alert) { emitted = append(emitted, a) },
	}
	ev := model.NewEvent("ebpf.net", model.SeverityInfo)
	ev.PID = 11
	ev.Tags["kind"] = "net_connect"
	ev.Tags["dst_ip"] = "8.8.8.8"
	ev.Tags["dst_port"] = "53"
	p.evaluateBRP(ev)
	if got := ev.Tags["brp_decision"]; got != "unknown" {
		t.Errorf("brp_decision=%q, want unknown", got)
	}
	if len(emitted) != 0 {
		t.Errorf("unprofiled must not alert, got %d", len(emitted))
	}
}

// TestBRP_AlwaysSuspicious verifies that a ptrace_attach hard-denies
// even when no profile is loaded — the invariant predates the envelope.
func TestBRP_AlwaysSuspicious(t *testing.T) {
	var emitted []model.Alert
	p := &Pipeline{
		BRPMatcher: brp.NewMatcher(nil),
		BRPRuntime: brp.NewRuntime(brp.DefaultInvariants()),
		Emit:       func(a model.Alert) { emitted = append(emitted, a) },
	}
	ev := model.NewEvent("ebpf.proc", model.SeverityWarn)
	ev.PID = 22
	ev.Tags["kind"] = "ptrace_attach"
	p.evaluateBRP(ev)
	if got := ev.Tags["brp_decision"]; got != "hard_deny" {
		t.Errorf("brp_decision=%q, want hard_deny for ptrace", got)
	}
	if len(emitted) != 1 {
		t.Fatalf("ptrace must alert, got %d", len(emitted))
	}
}

// TestBRP_BaselineKnownAttenuates exercises the AutoBaseline integration
// in the verifier path. When the baseline_known tag is set on an event
// that hits the Verify decision, the verifier's BehaviorHistory domain
// must subtract score, dropping it below threshold for credential-tier
// writes that would otherwise promote.
func TestBRP_BaselineKnownAttenuates(t *testing.T) {
	var emitted []model.Alert
	p := &Pipeline{
		BRPMatcher: brp.NewMatcher(nil),
		BRPRuntime: brp.NewRuntime(brp.DefaultInvariants()),
		VerifyEngine: func() *verify.Engine {
			e := verify.NewEngine()
			return e
		}(),
		Emit: func(a model.Alert) { emitted = append(emitted, a) },
	}

	// Event 1: unattributed write to /etc/shadow with NO baseline_known.
	//   verifier: path=+5 → promote → brp.hard_deny
	ev1 := model.NewEvent("fim", model.SeverityWarn)
	ev1.PID = 0
	ev1.Tags["create"] = "true"
	ev1.Tags["path"] = "/etc/shadow"
	p.Handle(context.Background(), ev1)

	// Event 2: same path, same actor shape, baseline_known=true via tag.
	//   verifier: path=+5, behavior_history=-2 → suspicious, NOT promote
	ev2 := model.NewEvent("fim", model.SeverityWarn)
	ev2.PID = 0
	ev2.Tags["create"] = "true"
	ev2.Tags["path"] = "/etc/shadow"
	ev2.Tags["baseline_known"] = "true"
	p.Handle(context.Background(), ev2)

	// Count outcomes.
	var promote, suspicious int
	for _, a := range emitted {
		switch a.RuleID {
		case "brp.hard_deny":
			promote++
		case "brp.verify_protected_path":
			suspicious++
		}
	}
	if promote < 1 {
		t.Errorf("event 1 (no baseline) should promote: got promote=%d", promote)
	}
	if suspicious < 1 {
		t.Errorf("event 2 (baseline_known) should drop to suspicious: got suspicious=%d", suspicious)
	}
}

// TestBRP_HandleInvocation runs the full Pipeline.Handle path (not just
// evaluateBRP directly) to confirm the tail-call wiring fires.
func TestBRP_HandleInvocation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	profile := brp.Profile{
		SchemaVersion: brp.SchemaVersion,
		ProfileID:     "test-id",
		Confidence:    brp.ConfidenceStrict,
		SigningEpoch:  time.Now().UnixNano(),
		Key:           parser.ProfileKey{App: "nginx", Role: "nginx-reverse-proxy"},
	}
	signed, _ := brp.Sign(profile, "s", priv)
	m := brp.NewMatcher(map[string]ed25519.PublicKey{"s": pub})
	if err := m.AddProfile(signed); err != nil {
		t.Fatalf("add: %v", err)
	}

	var emitted []model.Alert
	p := &Pipeline{
		BRPMatcher: m,
		BRPRuntime: brp.NewRuntime(brp.DefaultInvariants()),
		Emit:       func(a model.Alert) { emitted = append(emitted, a) },
	}

	ev := model.NewEvent("ebpf.proc", model.SeverityWarn)
	ev.PID = 1
	ev.Image = "/bin/sh"
	ev.Tags["kind"] = "proc_exec"
	ev.Tags["app_id"] = "nginx"
	ev.Tags["app_role"] = "nginx-reverse-proxy"
	ev.Tags["image"] = "/bin/sh"

	p.Handle(context.Background(), ev)

	// Handle does many things; we only assert the BRP tail-call ran.
	if got := ev.Tags["brp_decision"]; got != "hard_deny" {
		t.Errorf("Handle did not invoke BRP eval: brp_decision=%q", got)
	}
	if len(emitted) < 1 {
		t.Fatalf("Handle did not emit BRP alert")
	}
}

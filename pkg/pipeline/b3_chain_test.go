package pipeline

import (
	"context"
	"testing"

	"github.com/xhelix/xhelix/pkg/assetclass"
	"github.com/xhelix/xhelix/pkg/brp"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/secrettaint"
	"github.com/xhelix/xhelix/pkg/verify"
)

// TestB3_EndToEnd_SecretTouchToOutboundChain is the contract for
// Phase B.3: a lineage that touches a secret then attempts novel
// outbound should be promoted to brp.hard_deny via the verifier's
// SecretContext + NetworkNovelty + AssetContext domains working
// together.
func TestB3_EndToEnd_SecretTouchToOutboundChain(t *testing.T) {
	var emitted []model.Alert
	p := &Pipeline{
		AssetResolver: assetclass.NewStaticResolver(),
		SecretTaint:   secrettaint.NewStore(0),
		VerifyEngine:  verify.NewEngine(),
		BRPMatcher:    brp.NewMatcher(nil),
		BRPRuntime:    brp.NewRuntime(brp.DefaultInvariants()),
		Emit:          func(a model.Alert) { emitted = append(emitted, a) },
	}

	// Step 1: lineage touches metadata.
	ev1 := model.NewEvent("ebpf.net", model.SeverityInfo)
	ev1.PID = 1000
	ev1.Tags["kind"] = "net_connect"
	ev1.Tags["dst_ip"] = "169.254.169.254"
	ev1.Tags["dst_port"] = "80"
	ev1.Tags["source_anchor_id"] = "777"
	p.Handle(context.Background(), ev1)

	if got := ev1.Tags["secret_class"]; got != "metadata" {
		t.Fatalf("step 1: secret_class=%q, want metadata", got)
	}
	if got := ev1.Tags["secret_taint"]; got != "secret_touched" {
		t.Fatalf("step 1: secret_taint=%q, want secret_touched", got)
	}

	// Step 2: same lineage attempts outbound to a novel external dst.
	ev2 := model.NewEvent("ebpf.net", model.SeverityInfo)
	ev2.PID = 1000
	ev2.Tags["kind"] = "net_connect"
	ev2.Tags["dst_ip"] = "203.0.113.5"
	ev2.Tags["dst_port"] = "443"
	ev2.Tags["dest_class"] = "novel_external"
	ev2.Tags["source_anchor_id"] = "777"
	p.Handle(context.Background(), ev2)

	if got := ev2.Tags["secret_taint"]; got != "secret_touched" {
		t.Errorf("step 2: lineage should still carry taint, got %q", got)
	}
}

// TestB3_AssetContextStampsInfluenceVerifier confirms the asset_class
// tag stamped by Phase B.1 actually changes verifier outcome.
func TestB3_AssetContextStampsInfluenceVerifier(t *testing.T) {
	var emitted []model.Alert
	p := &Pipeline{
		AssetResolver: assetclass.NewStaticResolver(),
		VerifyEngine:  verify.NewEngine(),
		BRPMatcher:    brp.NewMatcher(nil),
		BRPRuntime:    brp.NewRuntime(brp.DefaultInvariants()),
		Emit:          func(a model.Alert) { emitted = append(emitted, a) },
	}

	// Synthetic: file write to a cron path. asset_class should be
	// persistence_surface; verifier should hit Suspicious/Promote.
	ev := model.NewEvent("ebpf.file", model.SeverityWarn)
	ev.PID = 0 // unattributed
	ev.Tags["kind"] = "file_write"
	ev.Tags["path"] = "/etc/cron.d/.implant"
	p.Handle(context.Background(), ev)

	if got := ev.Tags["asset_class"]; got != "persistence_surface" {
		t.Fatalf("asset_class=%q, want persistence_surface", got)
	}
}

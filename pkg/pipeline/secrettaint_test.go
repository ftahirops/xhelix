package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/secrettaint"
)

// TestSecretTaint_TouchStampsClassAndState exercises the Phase B.2
// pipeline integration end-to-end. A metadata-access event should:
//   1. Cause SecretTaint.ObserveTouch to fire
//   2. Stamp secret_class=metadata on the event tags
//   3. Stamp secret_taint=secret_touched on the event tags
//   4. Leave subsequent events from the same lineage tainted
func TestSecretTaint_TouchStampsTags(t *testing.T) {
	st := secrettaint.NewStore(0)
	p := &Pipeline{SecretTaint: st}

	ev := model.NewEvent("ebpf.net", model.SeverityInfo)
	ev.PID = 1234
	ev.CGroupID = 99
	ev.Tags["dst_ip"] = "169.254.169.254"
	ev.Tags["dst_port"] = "80"
	ev.Tags["source_anchor_id"] = "55"

	p.Handle(context.Background(), ev)

	if got := ev.Tags["secret_class"]; got != "metadata" {
		t.Errorf("secret_class=%q, want metadata", got)
	}
	if got := ev.Tags["secret_taint"]; got != "secret_touched" {
		t.Errorf("secret_taint=%q, want secret_touched", got)
	}
	if state := st.StateForLineage(55); state != secrettaint.TaintSecretTouched {
		t.Errorf("store state=%s, want secret_touched", state)
	}
}

func TestSecretTaint_SubsequentEventCarriesTaint(t *testing.T) {
	st := secrettaint.NewStore(0)
	p := &Pipeline{SecretTaint: st}

	// Initial touch.
	ev1 := model.NewEvent("ebpf.file", model.SeverityInfo)
	ev1.PID = 100
	ev1.Tags["kind"] = "file_open"
	ev1.Tags["mode"] = "read"
	ev1.Tags["path"] = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	ev1.Tags["source_anchor_id"] = "77"
	p.Handle(context.Background(), ev1)

	// Subsequent unrelated event from same lineage — should carry taint
	// tag even though it's not itself a secret touch.
	ev2 := model.NewEvent("ebpf.net", model.SeverityInfo)
	ev2.PID = 100
	ev2.Tags["dst_ip"] = "1.2.3.4"
	ev2.Tags["dst_port"] = "443"
	ev2.Tags["source_anchor_id"] = "77"
	p.Handle(context.Background(), ev2)

	if got := ev2.Tags["secret_taint"]; got != "secret_touched" {
		t.Errorf("secondary event missing taint tag: got %q", got)
	}
	// secret_class should NOT be re-stamped (event isn't itself a touch).
	if got := ev2.Tags["secret_class"]; got != "" {
		t.Errorf("secret_class wrongly stamped on non-touch event: %q", got)
	}
}

func TestSecretTaint_CleanLineageNoTags(t *testing.T) {
	st := secrettaint.NewStore(0)
	p := &Pipeline{SecretTaint: st}

	ev := model.NewEvent("ebpf.net", model.SeverityInfo)
	ev.PID = 200
	ev.Tags["dst_ip"] = "8.8.8.8"
	ev.Tags["dst_port"] = "53"
	ev.Tags["source_anchor_id"] = "88"
	p.Handle(context.Background(), ev)

	if got := ev.Tags["secret_taint"]; got != "" {
		t.Errorf("clean lineage stamped taint: %q", got)
	}
}

func TestSecretTaint_NilStoreIsNoop(t *testing.T) {
	p := &Pipeline{SecretTaint: nil}
	ev := model.NewEvent("ebpf.net", model.SeverityInfo)
	ev.PID = 1
	ev.Tags["dst_ip"] = "169.254.169.254"
	p.Handle(context.Background(), ev)
	if got := ev.Tags["secret_class"]; got != "" {
		t.Errorf("nil store should not stamp tags: secret_class=%q", got)
	}
}

func TestSecretTaint_ProcEnvironTouch(t *testing.T) {
	st := secrettaint.NewStore(0)
	p := &Pipeline{SecretTaint: st}
	ev := model.NewEvent("procscrape", model.SeverityWarn)
	ev.PID = 333
	ev.CGroupID = 444
	p.Handle(context.Background(), ev)
	if got := ev.Tags["secret_class"]; got != "proc_environ" {
		t.Errorf("procscrape: secret_class=%q, want proc_environ", got)
	}
}

func TestSecretTaint_PromotionAndContainment(t *testing.T) {
	st := secrettaint.NewStore(0)
	// Touch first to enter SecretTouched state.
	st.ObserveTouch(secrettaint.Touch{
		LineageID:   500,
		SecretClass: secrettaint.SecretCloudCreds,
		At:          time.Now().UTC(),
	})
	// Promote.
	st.PromoteOutboundRestricted(500, time.Now().UTC(), "novel destination after touch")
	if st.StateForLineage(500) != secrettaint.TaintOutboundRestricted {
		t.Errorf("promote to OutboundRestricted failed")
	}
	// Escalate.
	st.PromoteContainmentRequired(500, time.Now().UTC(), "outbound + persistence")
	if st.StateForLineage(500) != secrettaint.TaintContainmentRequired {
		t.Errorf("escalate to ContainmentRequired failed")
	}
	// Now run a pipeline event and confirm tag.
	p := &Pipeline{SecretTaint: st}
	ev := model.NewEvent("ebpf.net", model.SeverityWarn)
	ev.PID = 500
	ev.Tags["source_anchor_id"] = "500"
	p.Handle(context.Background(), ev)
	if got := ev.Tags["secret_taint"]; got != "containment_required" {
		t.Errorf("tainted lineage tag = %q, want containment_required", got)
	}
}

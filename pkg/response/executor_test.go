package response

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/decision"
	"github.com/xhelix/xhelix/pkg/model"
)

// --- mocks for the interface backends ---

type mockNetBanner struct {
	mu    sync.Mutex
	calls []string
}

func (m *mockNetBanner) Ban(ip net.IP, reason string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "ban:"+ip.String())
	return nil
}
func (m *mockNetBanner) Unban(net.IP) error      { return nil }
func (m *mockNetBanner) List() ([]string, error) { return nil, nil }

type mockHostBanner struct {
	mu    sync.Mutex
	armed bool
}

func (m *mockHostBanner) Quarantined() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.armed
}
func (m *mockHostBanner) EngageQuarantine(ctx context.Context, allow []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.armed = true
	return nil
}

type mockRemediator struct {
	mu     sync.Mutex
	calls  int
	called bool
}

func (m *mockRemediator) Restore(path, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.called = true
	return nil
}

type mockSnapshotter struct {
	mu    sync.Mutex
	calls int
}

func (m *mockSnapshotter) Capture(pid int, comm, ruleID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return "/var/lib/xhelix/snap.json", nil
}

type webhookRecorder struct {
	mu    sync.Mutex
	calls int
}

func (w *webhookRecorder) fn(ctx context.Context, a model.Alert) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	return nil
}

func newTestEngine(t *testing.T) (*Engine, *mockNetBanner, *mockHostBanner, *mockRemediator, *mockSnapshotter, *webhookRecorder) {
	t.Helper()
	nb := &mockNetBanner{}
	hb := &mockHostBanner{}
	rm := &mockRemediator{}
	sn := &mockSnapshotter{}
	wh := &webhookRecorder{}
	e := New(Config{
		NetBanner:    nb,
		HostBanner:   hb,
		HostAllowIPs: []string{"10.0.0.1"}, // operator IP
		Remediator:   rm,
		Snapshotter:  sn,
		Webhook:      wh.fn,
	})
	return e, nb, hb, rm, sn, wh
}

func mkAlert() model.Alert {
	ev := model.NewEvent("test", model.SeverityHigh)
	ev.PID = 1234
	ev.Comm = "nginx"
	ev.Image = "/usr/sbin/nginx"
	ev.Tags["dst_ip"] = "10.20.30.40"
	ev.Tags["src_ip"] = "203.0.113.42" // attacker IP for netban
	ev.Tags["path"] = "/etc/cron.d/evil"
	return model.Alert{Event: ev, RuleID: "test.rule"}
}

func TestExecutor_NilPlanIsNoop(t *testing.T) {
	e, _, _, _, _, _ := newTestEngine(t)
	x := NewExecutor(e)
	if r := x.Execute(context.Background(), nil, mkAlert()); r != nil {
		t.Fatalf("nil plan should return nil Result; got %+v", r)
	}
}

func TestExecutor_SnapshotRuns(t *testing.T) {
	e, _, _, _, sn, _ := newTestEngine(t)
	x := NewExecutor(e)
	plan := &decision.ActionPlan{PlanID: "p1", Snapshot: true, Reversible: true}
	r := x.Execute(context.Background(), plan, mkAlert())
	if r == nil {
		t.Fatal("expected Result")
	}
	if sn.calls != 1 {
		t.Fatalf("Snapshotter.SnapshotPID calls=%d want 1", sn.calls)
	}
	if !containsAction(r.Ran, "snapshot") {
		t.Fatalf("Ran=%v want snapshot", r.Ran)
	}
}

func TestExecutor_BanRemoteIP(t *testing.T) {
	e, nb, _, _, _, _ := newTestEngine(t)
	x := NewExecutor(e)
	plan := &decision.ActionPlan{PlanID: "p1", BanRemoteIP: true, Reversible: true}
	x.Execute(context.Background(), plan, mkAlert())
	if len(nb.calls) != 1 || nb.calls[0] != "ban:203.0.113.42" {
		t.Fatalf("NetBanner calls=%v", nb.calls)
	}
}

func TestExecutor_IsolateHost(t *testing.T) {
	e, _, hb, _, _, _ := newTestEngine(t)
	x := NewExecutor(e)
	plan := &decision.ActionPlan{PlanID: "p1", IsolateHost: true, Reversible: true,
		Preconditions: []string{"bastion>=2"}}
	x.Execute(context.Background(), plan, mkAlert())
	if !hb.armed {
		t.Fatal("HostBanner should be armed after IsolateHost")
	}
}

func TestExecutor_RemediateFile(t *testing.T) {
	e, _, _, rm, _, _ := newTestEngine(t)
	x := NewExecutor(e)
	plan := &decision.ActionPlan{PlanID: "p1", RemediateFile: true, Reversible: false}
	x.Execute(context.Background(), plan, mkAlert())
	if !rm.called {
		t.Fatal("Remediator should have been called")
	}
}

func TestExecutor_SoftEnforce_DeferredNotRun(t *testing.T) {
	e, _, _, _, sn, _ := newTestEngine(t)
	x := NewExecutor(e)
	plan := &decision.ActionPlan{
		PlanID:        "p1",
		Delay:         50_000_000, // 50ms
		RequireStepUp: true,
		Reversible:    true,
	}
	r := x.Execute(context.Background(), plan, mkAlert())
	if !containsAction(r.Deferred, "delay") || !containsAction(r.Deferred, "require_step_up") {
		t.Fatalf("expected delay+step_up in Deferred; got %v", r.Deferred)
	}
	if sn.calls != 0 {
		t.Fatal("no hard action enabled — snapshot should NOT have fired")
	}
}

func TestExecutor_TarpitDeferredUntilBackendShips(t *testing.T) {
	e, _, _, _, _, _ := newTestEngine(t)
	x := NewExecutor(e)
	plan := &decision.ActionPlan{
		PlanID: "p1", Tarpit: true, Reversible: true,
		Reasons: []string{"attribution"},
	}
	r := x.Execute(context.Background(), plan, mkAlert())
	if !containsAction(r.Deferred, "tarpit") {
		t.Fatalf("tarpit should be Deferred; got %v", r.Deferred)
	}
}

func TestExecutor_ActionOrderCanonical(t *testing.T) {
	// All hard actions on. Verify Ran order matches the canonical
	// ActionPlan.Actions() order — snapshot first, kill last.
	e, _, _, _, _, _ := newTestEngine(t)
	x := NewExecutor(e)
	plan := &decision.ActionPlan{
		PlanID: "p1",
		Snapshot: true, Memscan: true,
		SuspendProcess: true, IsolateCgroup: true,
		BanRemoteIP: true, IsolateHost: true,
		RemediateFile: true, LockLocalUser: true,
		KillProcess: true, Reversible: false,
	}
	r := x.Execute(context.Background(), plan, mkAlert())

	// snapshot MUST appear before kill_process in Ran order.
	posSnap := indexOf(r.Ran, "snapshot")
	posKill := indexOf(r.Ran, "kill_process")
	if posSnap < 0 || posKill < 0 {
		t.Fatalf("missing actions in Ran: %v", r.Ran)
	}
	if posSnap >= posKill {
		t.Fatalf("snapshot (pos %d) must precede kill (pos %d): %v",
			posSnap, posKill, r.Ran)
	}
	// suspend_process MUST appear before kill_process.
	posSusp := indexOf(r.Ran, "suspend_process")
	if posSusp >= posKill {
		t.Fatalf("suspend (%d) must precede kill (%d)", posSusp, posKill)
	}
}

func TestExecutor_StatsCounters(t *testing.T) {
	e, _, _, _, _, _ := newTestEngine(t)
	x := NewExecutor(e)
	plan := &decision.ActionPlan{PlanID: "p1", Snapshot: true, Tarpit: true,
		Reasons: []string{"attribution"}, Reversible: true}
	x.Execute(context.Background(), plan, mkAlert())
	x.Execute(context.Background(), plan, mkAlert())

	st := x.Stats()
	if st.PlansExecuted != 2 {
		t.Errorf("PlansExecuted=%d want 2", st.PlansExecuted)
	}
	if st.ActionsRun < 1 {
		t.Errorf("ActionsRun should be > 0; got %d", st.ActionsRun)
	}
	if st.ActionsDeferred < 1 {
		t.Errorf("ActionsDeferred should record tarpit; got %d", st.ActionsDeferred)
	}
}

func TestExecutor_ResultSinkCalled(t *testing.T) {
	e, _, _, _, _, _ := newTestEngine(t)
	x := NewExecutor(e)
	var sunk *Result
	x.ResultSink = func(r *Result) { sunk = r }
	plan := &decision.ActionPlan{PlanID: "p1", Snapshot: true, Reversible: true}
	x.Execute(context.Background(), plan, mkAlert())
	if sunk == nil || sunk.PlanID != "p1" {
		t.Fatalf("ResultSink not invoked / wrong PlanID: %+v", sunk)
	}
}

func TestExecutor_PanicSwitchDefersAll(t *testing.T) {
	// We don't have a real PanicSwitch here; the executor checks
	// Engine.panicSwitch.Armed(). With nil panicSwitch, this branch
	// is skipped and the test verifies the normal path works.
	// Real PanicSwitch integration is tested in pkg/enforce.
	t.Skip("PanicSwitch integration verified separately in pkg/enforce")
}

func TestExecutor_CapabilityWarningsPropagated(t *testing.T) {
	e, _, _, _, _, _ := newTestEngine(t)
	x := NewExecutor(e)
	plan := &decision.ActionPlan{
		PlanID:             "p1",
		Snapshot:           true,
		Reversible:         true,
		CapabilityWarnings: []string{"isolate_host requires BastionCount>=2"},
	}
	r := x.Execute(context.Background(), plan, mkAlert())
	if len(r.Warnings) != 1 || r.Warnings[0] != "isolate_host requires BastionCount>=2" {
		t.Fatalf("warnings not propagated: %v", r.Warnings)
	}
}

func TestExecutor_IsolateCgroupAloneTriggersQuarantineRoute(t *testing.T) {
	// IsolateCgroup is reported as "deferred (covered by suspend)" when
	// SuspendProcess is also set; if it's the ONLY action, the executor
	// runs the same code path. Verify the Ran list captures it
	// under the proper name.
	e, _, _, _, _, _ := newTestEngine(t)
	x := NewExecutor(e)
	plan := &decision.ActionPlan{PlanID: "p1", IsolateCgroup: true, Reversible: true}
	r := x.Execute(context.Background(), plan, mkAlert())
	if !containsAction(r.Ran, "isolate_cgroup") {
		t.Fatalf("isolate_cgroup-alone should appear in Ran; got %v", r.Ran)
	}
}

// --- helpers ---

func containsAction(list []string, name string) bool {
	for _, s := range list {
		if s == name {
			return true
		}
		// Tolerate parenthesised suffixes used in Deferred ("(covered by ...)").
		if len(s) > len(name) && s[:len(name)] == name && s[len(name)] == ' ' {
			return true
		}
	}
	return false
}

func indexOf(list []string, name string) int {
	for i, s := range list {
		if s == name {
			return i
		}
	}
	return -1
}

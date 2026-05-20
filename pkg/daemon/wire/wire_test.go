package wire

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/response"
	"github.com/xhelix/xhelix/pkg/takeover"
)

// --- mock backends (subset; full mocks in pkg/response/executor_test.go) ---

type recNetBan struct {
	mu    sync.Mutex
	calls []string
}

func (r *recNetBan) Ban(ip net.IP, reason string, ttl time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, ip.String())
	return nil
}
func (r *recNetBan) Unban(net.IP) error      { return nil }
func (r *recNetBan) List() ([]string, error) { return nil, nil }

func newTestEngine() *response.Engine {
	return response.New(response.Config{
		NetBanner: &recNetBan{},
	})
}

// safeBuf is bytes.Buffer guarded for concurrent Write+String.
type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newWiring(t *testing.T, active bool, tick time.Duration) (*PlannerWiring, *safeBuf) {
	t.Helper()
	buf := &safeBuf{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	w := New(Config{
		Log:          logger,
		Active:       active,
		TickInterval: tick,
	}, newTestEngine())
	return w, buf
}

func TestAlertToSignal_KnownRuleIDs(t *testing.T) {
	cases := []struct {
		ruleID string
		want   takeover.SignalKind
	}{
		{"lolbin.suspicious", takeover.SignalLOTL},
		{"revshell.detected", takeover.SignalShellAttempt},
		{"shm.exec", takeover.SignalRWXMemory},
		{"webshell.argv", takeover.SignalInterpAttempt},
		{"cap.gained", takeover.SignalCapAbuse},
		{"contescape.detected", takeover.SignalDefenseEvasion},
		{"ptrace.suspicious", takeover.SignalDefenseEvasion},
		{"intel.bad_ip", takeover.SignalC2Beacon},
		{"beacon.periodic_callback", takeover.SignalC2Beacon},
		{"dnsexfil.tunnel_pattern", takeover.SignalForbiddenConnect},
		{"netids.dga", takeover.SignalForbiddenConnect},
		{"phishing.brand_lookalike", takeover.SignalForbiddenConnect},
		{"metadata.access_by_unexpected", takeover.SignalLateralMove},
		{"baseline.behavioural_deviation", takeover.SignalNewBinary},
	}
	for _, c := range cases {
		ev := model.NewEvent("test", model.SeverityHigh)
		ev.PID = 99
		ev.CGroupID = 12345
		sig := AlertToSignal(model.Alert{Event: ev, RuleID: c.ruleID})
		if sig.Kind != c.want {
			t.Errorf("%s → %q, want %q", c.ruleID, sig.Kind, c.want)
		}
		if sig.LineageID != 12345 {
			t.Errorf("%s: LineageID=%d, want 12345 (CGroupID)", c.ruleID, sig.LineageID)
		}
	}
}

func TestAlertToSignal_UnknownRuleIDFallsBackBySeverity(t *testing.T) {
	ev := model.NewEvent("test", model.SeverityHigh)
	sig := AlertToSignal(model.Alert{Event: ev, RuleID: "unknown.rule.x"})
	if sig.Kind != takeover.SignalRuleHit {
		t.Fatalf("high-sev unknown rule → %q, want rule_hit", sig.Kind)
	}

	ev2 := model.NewEvent("test", model.SeverityInfo)
	sig2 := AlertToSignal(model.Alert{Event: ev2, RuleID: "unknown.rule.y"})
	if sig2.Kind != "" {
		t.Fatalf("low-sev unknown rule → %q, want empty (dropped)", sig2.Kind)
	}
}

func TestAlertToSignal_LineageFallbackToPID(t *testing.T) {
	// No CGroupID → fall back to PID so the planner can still aggregate.
	ev := model.NewEvent("test", model.SeverityHigh)
	ev.PID = 42
	sig := AlertToSignal(model.Alert{Event: ev, RuleID: "lolbin.suspicious"})
	if sig.LineageID != 42 {
		t.Fatalf("LineageID=%d, want 42 (PID fallback)", sig.LineageID)
	}
}

func TestAlertToSignal_RemoteIPPropagates(t *testing.T) {
	ev := model.NewEvent("test", model.SeverityHigh)
	ev.PID = 1
	ev.Tags["src_ip"] = "203.0.113.5"
	sig := AlertToSignal(model.Alert{Event: ev, RuleID: "intel.bad_ip"})
	if sig.RemoteIP != "203.0.113.5" {
		t.Fatalf("RemoteIP=%q, want 203.0.113.5", sig.RemoteIP)
	}
}

func TestWiring_OnAlertFeedsPlanner(t *testing.T) {
	w, _ := newWiring(t, false, 50*time.Millisecond)
	ev := model.NewEvent("test", model.SeverityHigh)
	ev.PID = 100
	ev.CGroupID = 7
	w.OnAlert(model.Alert{Event: ev, RuleID: "revshell.detected"})

	sigs := w.Plan.Agg.Snapshot(7, time.Now().UTC())
	if len(sigs) != 1 || sigs[0].Kind != takeover.SignalShellAttempt {
		t.Fatalf("planner aggregator missing signal: %+v", sigs)
	}
}

func TestWiring_ShadowModeLogsButDoesNotExecute(t *testing.T) {
	w, buf := newWiring(t, false, 30*time.Millisecond)

	// Feed a Tier-1 signal so the planner emits a real ActionPlan.
	ev := model.NewEvent("test", model.SeverityCritical)
	ev.PID = 200
	ev.CGroupID = 88
	ev.Tags["src_ip"] = "9.9.9.9"
	w.OnAlert(model.Alert{Event: ev, RuleID: "shm.exec"})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go w.Tick(ctx)
	<-ctx.Done()

	s := w.Stats()
	if s.Shadowed == 0 {
		t.Fatalf("shadow mode should have logged at least one plan; stats=%+v\nlog=%s",
			s, buf.String())
	}
	if s.Executed != 0 {
		t.Fatalf("shadow mode must NOT execute; stats=%+v", s)
	}
	if !strings.Contains(buf.String(), "planner shadow") {
		t.Fatalf("expected 'planner shadow' log entry; got:\n%s", buf.String())
	}
}

func TestWiring_ActiveModeExecutes(t *testing.T) {
	w, _ := newWiring(t, true, 30*time.Millisecond)

	ev := model.NewEvent("test", model.SeverityCritical)
	ev.PID = 300
	ev.CGroupID = 99
	ev.Tags["src_ip"] = "9.9.9.9"
	w.OnAlert(model.Alert{Event: ev, RuleID: "shm.exec"})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go w.Tick(ctx)
	<-ctx.Done()

	s := w.Stats()
	if s.Executed == 0 {
		t.Fatalf("active mode should have executed at least one plan; stats=%+v", s)
	}
}

func TestWiring_TickWithNoSignalsIsNoop(t *testing.T) {
	w, _ := newWiring(t, true, 20*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	go w.Tick(ctx)
	<-ctx.Done()

	s := w.Stats()
	if s.Executed != 0 || s.Shadowed != 0 {
		t.Fatalf("empty aggregator should not produce plans; got %+v", s)
	}
}

func TestWiring_MarkActiveFlipsBehaviour(t *testing.T) {
	w, _ := newWiring(t, false, 30*time.Millisecond)
	if w.IsActive() {
		t.Fatal("should start in shadow mode")
	}
	w.MarkActive()
	if !w.IsActive() {
		t.Fatal("MarkActive should flip to active")
	}
}

func TestSeverityToConfidence(t *testing.T) {
	cases := map[model.Severity]string{
		model.SeverityCritical: "deterministic",
		model.SeverityHigh:     "high",
		model.SeverityWarn:     "medium",
		model.SeverityInfo:     "low",
	}
	for sev, want := range cases {
		if got := severityToConfidence(sev); got != want {
			t.Errorf("severity %v → %q, want %q", sev, got, want)
		}
	}
}

func TestWeightForRuleMode(t *testing.T) {
	if w := weightForRuleMode(model.ModeBlock); w != 95 {
		t.Errorf("Block mode → %d, want 95", w)
	}
	if w := weightForRuleMode(model.ModeQuarantine); w != 80 {
		t.Errorf("Quarantine mode → %d, want 80", w)
	}
	if w := weightForRuleMode(model.ModeDetect); w != 0 {
		t.Errorf("Detect mode → %d, want 0 (use kind default)", w)
	}
}

func TestTierToState(t *testing.T) {
	cases := []struct {
		tier string
		want string
	}{
		{"triaged", "triaged"},
		{"suspended", "suspended"},
		{"isolated", "isolated"},
		{"contained", "contained"},
		{"", "observed"},
		{"unknown", "observed"},
	}
	for _, c := range cases {
		got := tierToState(c.tier)
		if string(got) != c.want {
			t.Errorf("tierToState(%q) = %q, want %q", c.tier, got, c.want)
		}
	}
}

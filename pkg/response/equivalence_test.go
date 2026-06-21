package response

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/decision"
	"github.com/xhelix/xhelix/pkg/enforce"
	"github.com/xhelix/xhelix/pkg/model"
)

// This file proves the equivalence contract between the two response
// dispatch surfaces that coexist during the P-RF.9 migration:
//
//   - legacy  Engine.OnAlert(alert)      — RuleID -> action bitmask walk
//   - planner Executor.Execute(plan, …)  — decision.ActionPlan walk
//
// Both share the SAME Engine.do* backends. The Executor docstring claims
// each action bit maps "1:1 … in the same order as OnAlert's bitmask
// walk". That order claim is an OVERSTATEMENT — the two walks order the
// destructive/network actions differently (legacy: netban→remediate→
// quarantine→kill→lockuser→hostquarantine; planner: suspend→netban→
// isolatehost→remediate→lockuser→kill). What is ACTUALLY equivalent, and
// what these tests pin, is:
//
//   1. the SET of backends reached for a maximal action set is identical;
//   2. the evidence-first invariant holds in BOTH (snapshot precedes any
//      process-destroying signal);
//   3. panic-switch parity — an armed panic switch suppresses every
//      backend on BOTH paths.
//
// See docs/RESPONSE_DUAL_PATH.md for the prose contract + cutover
// criteria.

type backendRec struct {
	mu  sync.Mutex
	seq []string
}

func (r *backendRec) add(s string) { r.mu.Lock(); r.seq = append(r.seq, s); r.mu.Unlock() }
func (r *backendRec) get() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.seq))
	copy(out, r.seq)
	return out
}

type recNetBan struct{ rec *backendRec }

func (r recNetBan) Ban(net.IP, string, time.Duration) error { r.rec.add("netban"); return nil }
func (r recNetBan) Unban(net.IP) error                      { return nil }
func (r recNetBan) List() ([]string, error)                 { return nil, nil }

type recHost struct {
	rec   *backendRec
	armed atomic.Bool
}

func (r *recHost) EngageQuarantine(context.Context, []string) error {
	r.rec.add("hostquarantine")
	r.armed.Store(true)
	return nil
}
func (r *recHost) Quarantined() bool { return r.armed.Load() }

type recRemed struct{ rec *backendRec }

func (r recRemed) Restore(string, string) error { r.rec.add("remediate"); return nil }

type recSnap struct{ rec *backendRec }

func (r recSnap) Capture(int, string, string) (string, error) {
	r.rec.add("snapshot")
	return "/var/lib/xhelix/snap.json", nil
}

// recordingEngine wires every observable backend to append to rec in call
// order. memscan is intentionally left unconfigured (its backend does a
// real /proc scan) so it is absent from BOTH paths and never skews the
// set comparison. process signals (SIGSTOP from quarantine, SIGKILL from
// kill) are recorded as "signal" — we assert the count, not the exact
// signal name, to stay platform-agnostic.
func recordingEngine(t *testing.T, rec *backendRec, panicArmed bool) *Engine {
	t.Helper()
	q := enforce.NewQuarantine(func(int, os.Signal) error {
		rec.add("signal")
		return nil
	})
	var ps *enforce.PanicSwitch
	if panicArmed {
		ps = enforce.NewPanicSwitch(filepath.Join(t.TempDir(), "panic"))
		if err := ps.Arm(); err != nil {
			t.Fatalf("arm panic: %v", err)
		}
	}
	host := &recHost{rec: rec}
	return New(Config{
		Policy:       maximalPolicy(),
		NetBanner:    recNetBan{rec},
		HostBanner:   host,
		HostAllowIPs: []string{"10.0.0.1"},
		Remediator:   recRemed{rec},
		Snapshotter:  recSnap{rec},
		LockUser:     func(string) error { rec.add("lockuser"); return nil },
		Quarantine:   q,
		PanicSwitch:  ps,
		Webhook:      func(context.Context, model.Alert) error { rec.add("webhook"); return nil },
	})
}

// maximalPolicy maps the test rule to every destructive action except
// memscan (see recordingEngine).
func maximalPolicy() Policy {
	return Policy{"equiv.rule": ActionLog | ActionWebhook | ActionSnapshot |
		ActionNetBan | ActionRemediate | ActionQuarantine | ActionKill |
		ActionLockUser | ActionHostQuarantine}
}

// maximalPlan is the planner equivalent of maximalPolicy.
func maximalPlan() *decision.ActionPlan {
	return &decision.ActionPlan{
		PlanID:         "equiv",
		Snapshot:       true,
		SuspendProcess: true,
		BanRemoteIP:    true,
		IsolateHost:    true,
		RemediateFile:  true,
		LockLocalUser:  true,
		KillProcess:    true,
		Reversible:     false,
	}
}

func equivAlert() model.Alert {
	ev := model.NewEvent("test", model.SeverityHigh)
	ev.PID = uint32(os.Getpid())
	ev.Comm = "nginx"
	ev.Image = "/usr/sbin/nginx"
	ev.Tags["src_ip"] = "203.0.113.42"
	ev.Tags["path"] = "/etc/cron.d/evil"
	ev.Tags["user"] = "www-data"
	return model.Alert{Event: ev, RuleID: "equiv.rule"}
}

// backendSet collapses the ordered recording to a set, mapping the two
// process-signal entries (SIGSTOP+SIGKILL) to a single "process_signal"
// marker so the set compares cleanly regardless of retry quirks.
func backendSet(seq []string) map[string]bool {
	out := map[string]bool{}
	for _, s := range seq {
		if s == "signal" {
			out["process_signal"] = true
			continue
		}
		out[s] = true
	}
	return out
}

func TestResponsePaths_ReachSameBackends(t *testing.T) {
	var legacyRec, planRec backendRec

	legacy := recordingEngine(t, &legacyRec, false)
	legacy.OnAlert(equivAlert())

	plan := recordingEngine(t, &planRec, false)
	NewExecutor(plan).Execute(context.Background(), maximalPlan(), equivAlert())

	legacySet := backendSet(legacyRec.get())
	planSet := backendSet(planRec.get())

	want := []string{"snapshot", "netban", "remediate", "hostquarantine", "lockuser", "process_signal", "webhook"}
	for _, b := range want {
		if !legacySet[b] {
			t.Errorf("legacy OnAlert did not reach backend %q (seq=%v)", b, legacyRec.get())
		}
		if !planSet[b] {
			t.Errorf("planner Execute did not reach backend %q (seq=%v)", b, planRec.get())
		}
	}

	// The two paths must reach the SAME set — no backend reachable by
	// one but not the other.
	if !sameSet(legacySet, planSet) {
		t.Errorf("backend sets diverge:\n legacy=%v\n plan  =%v", keys(legacySet), keys(planSet))
	}
}

// TestResponsePaths_EvidenceBeforeDestruction pins the one ordering
// invariant that genuinely holds in BOTH walks: a forensic snapshot is
// captured before the process is signalled (SIGSTOP/SIGKILL), because the
// signal destroys the state the snapshot reads.
func TestResponsePaths_EvidenceBeforeDestruction(t *testing.T) {
	check := func(name string, seq []string) {
		snap, sig := -1, -1
		for i, s := range seq {
			if s == "snapshot" && snap < 0 {
				snap = i
			}
			if s == "signal" && sig < 0 {
				sig = i
			}
		}
		if snap < 0 || sig < 0 {
			t.Fatalf("%s: missing snapshot(%d) or signal(%d) in seq=%v", name, snap, sig, seq)
		}
		if snap >= sig {
			t.Errorf("%s: snapshot (pos %d) must precede first process signal (pos %d): %v",
				name, snap, sig, seq)
		}
	}

	var legacyRec, planRec backendRec
	recordingEngine(t, &legacyRec, false).OnAlert(equivAlert())
	check("legacy OnAlert", legacyRec.get())

	NewExecutor(recordingEngine(t, &planRec, false)).
		Execute(context.Background(), maximalPlan(), equivAlert())
	check("planner Execute", planRec.get())
}

// TestResponsePaths_PanicParity proves an armed panic switch suppresses
// every backend on BOTH paths — the daemon-wide kill switch must not be
// bypassable by routing through one path or the other.
func TestResponsePaths_PanicParity(t *testing.T) {
	var legacyRec, planRec backendRec

	recordingEngine(t, &legacyRec, true).OnAlert(equivAlert())
	if got := legacyRec.get(); len(got) != 0 {
		t.Errorf("legacy OnAlert ran backends under armed panic: %v", got)
	}

	NewExecutor(recordingEngine(t, &planRec, true)).
		Execute(context.Background(), maximalPlan(), equivAlert())
	if got := planRec.get(); len(got) != 0 {
		t.Errorf("planner Execute ran backends under armed panic: %v", got)
	}
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

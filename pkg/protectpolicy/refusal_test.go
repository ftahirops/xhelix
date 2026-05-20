package protectpolicy

import (
	"sync"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/profiles/contracts"
	"github.com/xhelix/xhelix/pkg/profiles/serviceid"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
	"github.com/xhelix/xhelix/pkg/takeover"
)

func mkSvc(t *testing.T) *protectedsvc.ProtectedService {
	t.Helper()
	c, err := contracts.Builtin(protectedsvc.KindNginx, protectedsvc.RoleStatic)
	if err != nil {
		t.Fatal(err)
	}
	return &protectedsvc.ProtectedService{
		Name: "nginx", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleStatic,
		ExecPath: "/usr/sbin/nginx", Contract: c,
		CgroupPrefix: "/system.slice/nginx.service",
		Unit:         "nginx.service",
	}
}

func TestEvaluate_ShellExecIsTier1(t *testing.T) {
	e := NewEvaluator()
	svc := mkSvc(t)
	s := e.Evaluate(RefusalEvent{
		Kind: RefuseExec, Path: "/bin/sh", LineageID: 42,
	}, svc)
	if s.Kind != takeover.SignalShellAttempt {
		t.Fatalf("shell exec → %q, want shell_attempt", s.Kind)
	}
	if s.Confidence != "deterministic" {
		t.Fatalf("confidence=%q, want deterministic", s.Confidence)
	}
	if s.LineageID != 42 {
		t.Fatal("lineage not propagated")
	}
}

func TestEvaluate_AllExecClassesClassified(t *testing.T) {
	e := NewEvaluator()
	svc := mkSvc(t)
	cases := []struct {
		path string
		want takeover.SignalKind
	}{
		{"/bin/bash", takeover.SignalShellAttempt},
		{"/usr/local/bin/zsh", takeover.SignalShellAttempt},
		{"/usr/bin/python3", takeover.SignalInterpAttempt},
		{"/usr/bin/curl", takeover.SignalDownloader},
		{"/usr/bin/nmap", takeover.SignalReconTool},
		{"/usr/bin/sudo", takeover.SignalPrivTool},
	}
	for _, c := range cases {
		s := e.Evaluate(RefusalEvent{Kind: RefuseExec, Path: c.path}, svc)
		if s.Kind != c.want {
			t.Errorf("%s → %q, want %q", c.path, s.Kind, c.want)
		}
	}
}

func TestEvaluate_OperatorDenyExecEmitsDefenseEvasion(t *testing.T) {
	svc := mkSvc(t)
	svc.Contract.DenyExecPaths = append(svc.Contract.DenyExecPaths, "/opt/custom/evil")
	e := NewEvaluator()
	s := e.Evaluate(RefusalEvent{Kind: RefuseExec, Path: "/opt/custom/evil"}, svc)
	if s.Kind != takeover.SignalDefenseEvasion {
		t.Fatalf("operator-declared deny → %q, want defense_evasion", s.Kind)
	}
}

func TestEvaluate_UnknownExecPathProducesNothing(t *testing.T) {
	e := NewEvaluator()
	svc := mkSvc(t)
	s := e.Evaluate(RefusalEvent{Kind: RefuseExec, Path: "/usr/bin/legitimate"}, svc)
	if s.Kind != "" {
		t.Fatalf("legitimate path should produce no signal; got %q", s.Kind)
	}
}

func TestEvaluate_ForbiddenWriteRequiresSvc(t *testing.T) {
	e := NewEvaluator()
	// Without svc — no signal (we don't know what "outside" means).
	if s := e.Evaluate(RefusalEvent{Kind: RefuseWrite, Path: "/etc/cron.d/x"}, nil); s.Kind != "" {
		t.Fatal("write refusal without svc should produce no signal")
	}
	// With svc — Tier-1 forbidden_write.
	svc := mkSvc(t)
	s := e.Evaluate(RefusalEvent{Kind: RefuseWrite, Path: "/etc/cron.d/x"}, svc)
	if s.Kind != takeover.SignalForbiddenWrite {
		t.Fatalf("got %q", s.Kind)
	}
}

func TestEvaluate_NeverLearnableSyscallEscalates(t *testing.T) {
	e := NewEvaluator()
	svc := mkSvc(t)
	// ptrace is never-learnable → defense_evasion.
	s := e.Evaluate(RefusalEvent{Kind: RefuseSyscall, SyscallName: "ptrace"}, svc)
	if s.Kind != takeover.SignalDefenseEvasion {
		t.Fatalf("ptrace → %q, want defense_evasion", s.Kind)
	}
	// A random extra denied syscall → forbidden_syscall (Tier-2).
	s = e.Evaluate(RefusalEvent{Kind: RefuseSyscall, SyscallName: "sendmmsg"}, svc)
	if s.Kind != takeover.SignalForbiddenSyscall {
		t.Fatalf("sendmmsg → %q, want forbidden_syscall", s.Kind)
	}
}

func TestEvaluate_MemoryAlwaysTier1(t *testing.T) {
	e := NewEvaluator()
	s := e.Evaluate(RefusalEvent{Kind: RefuseMemory, Path: "anon-rwx"}, nil)
	if s.Kind != takeover.SignalRWXMemory {
		t.Fatalf("memory refusal → %q, want rwx_memory", s.Kind)
	}
	// No svc needed — RWX is attack-grade regardless.
}

func TestEvaluate_IdentityMismatch(t *testing.T) {
	e := NewEvaluator()
	s := e.Evaluate(RefusalEvent{Kind: RefuseIdentity, Discrepancy: "exe_sha mismatch"}, nil)
	if s.Kind != takeover.SignalIdentityMismatch {
		t.Fatalf("identity → %q, want identity_mismatch", s.Kind)
	}
	if s.Detail != "exe_sha mismatch" {
		t.Fatalf("detail should carry discrepancy: %q", s.Detail)
	}
}

func TestEvaluate_ConnectRefusalIsTier2(t *testing.T) {
	e := NewEvaluator()
	s := e.Evaluate(RefusalEvent{
		Kind: RefuseConnect, RemoteIP: "1.2.3.4", RemotePort: 4444,
	}, mkSvc(t))
	if s.Kind != takeover.SignalForbiddenConnect {
		t.Fatalf("got %q", s.Kind)
	}
	if s.RemoteIP != "1.2.3.4" {
		t.Fatalf("RemoteIP not propagated: %q", s.RemoteIP)
	}
	if s.Confidence != "medium" {
		t.Fatalf("confidence=%q, want medium", s.Confidence)
	}
}

func TestEvaluate_AtStamped(t *testing.T) {
	e := NewEvaluator()
	before := time.Now().UTC()
	s := e.Evaluate(RefusalEvent{Kind: RefuseExec, Path: "/bin/sh"}, mkSvc(t))
	if s.At.Before(before) {
		t.Fatal("At should be stamped when zero")
	}
}

// --- Wire tests ---

type recorderSink struct {
	mu      sync.Mutex
	signals []takeover.Signal
}

func (r *recorderSink) OnSignal(s takeover.Signal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signals = append(r.signals, s)
}

func (r *recorderSink) all() []takeover.Signal {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]takeover.Signal, len(r.signals))
	copy(out, r.signals)
	return out
}

func newMatcher(t *testing.T, svc *protectedsvc.ProtectedService) *serviceid.Matcher {
	t.Helper()
	reg := protectedsvc.NewRegistry()
	if err := reg.Load([]protectedsvc.ProtectedService{*svc}); err != nil {
		t.Fatal(err)
	}
	m := serviceid.New(reg)
	// Stub the /proc probes so tests don't touch the filesystem.
	m.ReadCgroup = func(pid uint32) (string, error) { return "/system.slice/nginx.service", nil }
	m.ReadExe = func(pid uint32) (string, error) { return "/usr/sbin/nginx", nil }
	m.ReadUIDGID = func(pid uint32) (uint32, uint32, error) { return 33, 33, nil }
	m.HashFile = func(p string) (string, error) { return "", nil }
	m.ReadUnit = func(pid uint32) (string, error) { return "nginx.service", nil }
	return m
}

func TestWire_HandleEmitsSignal(t *testing.T) {
	svc := mkSvc(t)
	svc.CgroupPrefix = "/system.slice/nginx.service"
	m := newMatcher(t, svc)
	sink := &recorderSink{}
	w := NewWire(m, sink)

	got := w.Handle(RefusalEvent{
		Kind:      RefuseExec,
		Path:      "/bin/sh",
		PID:       1234,
		CGroupID:  1,
		LineageID: 7,
	})
	if got.Kind != takeover.SignalShellAttempt {
		t.Fatalf("Handle returned %q, want shell_attempt", got.Kind)
	}
	sigs := sink.all()
	if len(sigs) != 1 || sigs[0].Kind != takeover.SignalShellAttempt {
		t.Fatalf("sink got %v", sigs)
	}
}

func TestWire_DiscrepancySynthesizesExtraSignal(t *testing.T) {
	svc := mkSvc(t)
	m := newMatcher(t, svc)
	sink := &recorderSink{}
	w := NewWire(m, sink)

	// Refusal carries a Discrepancy (e.g. caller noticed a SHA
	// mismatch). Wire should emit BOTH the original signal AND a
	// synthetic identity-mismatch signal.
	w.Handle(RefusalEvent{
		Kind:        RefuseExec,
		Path:        "/bin/sh",
		LineageID:   7,
		Discrepancy: "exe_sha mismatch on nginx",
	})

	sigs := sink.all()
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signals (identity + shell); got %d: %+v", len(sigs), sigs)
	}
	var foundShell, foundIdentity bool
	for _, s := range sigs {
		if s.Kind == takeover.SignalShellAttempt {
			foundShell = true
		}
		if s.Kind == takeover.SignalIdentityMismatch {
			foundIdentity = true
		}
	}
	if !foundShell || !foundIdentity {
		t.Fatalf("missing signals: shell=%v identity=%v", foundShell, foundIdentity)
	}
}

func TestWire_NoSignalNoEmit(t *testing.T) {
	svc := mkSvc(t)
	m := newMatcher(t, svc)
	sink := &recorderSink{}
	w := NewWire(m, sink)

	// Unrelated exec — no classification, no signal.
	got := w.Handle(RefusalEvent{
		Kind: RefuseExec, Path: "/usr/bin/legitimate",
	})
	if got.Kind != "" {
		t.Fatalf("legitimate exec emitted %q", got.Kind)
	}
	if len(sink.all()) != 0 {
		t.Fatal("sink should be empty")
	}
}

func TestWire_NoMatcherStillWorks(t *testing.T) {
	// Sometimes the caller pre-resolved the service; Wire shouldn't
	// require a matcher to function.
	sink := &recorderSink{}
	w := &Wire{Eval: NewEvaluator(), Sink: sink}
	w.Handle(RefusalEvent{Kind: RefuseMemory})
	if len(sink.all()) != 1 {
		t.Fatal("memory refusal should emit even without matcher")
	}
}

// --- Signal weights from pkg/takeover wired correctly ---

func TestSignalWeights_ProtectedServicesInTable(t *testing.T) {
	w := takeover.DefaultWeights()
	mustHave := []takeover.SignalKind{
		takeover.SignalShellAttempt, takeover.SignalInterpAttempt,
		takeover.SignalDownloader, takeover.SignalReconTool,
		takeover.SignalPrivTool, takeover.SignalForbiddenSyscall,
		takeover.SignalForbiddenWrite, takeover.SignalForbiddenConnect,
		takeover.SignalRWXMemory, takeover.SignalC2Beacon,
		takeover.SignalDecoyTouch, takeover.SignalCrashLoop,
		takeover.SignalIdentityMismatch,
	}
	for _, k := range mustHave {
		if w[k] == 0 {
			t.Errorf("DefaultWeights missing or zero for %q", k)
		}
	}
	// Tier-1 — single signal must cross 75 (Suspended threshold).
	for _, k := range []takeover.SignalKind{
		takeover.SignalShellAttempt, takeover.SignalDownloader,
		takeover.SignalForbiddenWrite, takeover.SignalRWXMemory,
		takeover.SignalDecoyTouch, takeover.SignalCrashLoop,
		takeover.SignalIdentityMismatch,
	} {
		if w[k] < 75 {
			t.Errorf("%q weight %d, must be >=75 (Tier-1)", k, w[k])
		}
	}
}

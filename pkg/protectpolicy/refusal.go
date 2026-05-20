// Package protectpolicy bridges Ring 1 kernel refusals (seccomp +
// AppArmor + LSM denials) into pkg/takeover.Signal events.
//
// The kernel (or an eBPF program, or an audit-log reader) produces a
// RefusalEvent — "this PID tried to do this thing, and the kernel
// said no". protectpolicy.Evaluator classifies the refusal against
// the ProtectedService's contract and emits a typed
// takeover.Signal into the planner's aggregator.
//
// No live consumers in this package — it's the contract surface.
// Concrete event sources land in P-PS.6+ (eBPF programs that listen
// to security_bprm_check / socket_connect / inode_permission LSM
// hooks). The audit-log reader in audit_reader.go is the fallback
// for hosts where eBPF LSM isn't available.
//
// See PROTECTED_SERVICES_TRAP.md §6 (signal integration).
package protectpolicy

import (
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/profiles/contracts"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
	"github.com/xhelix/xhelix/pkg/takeover"
)

// RefusalKind enumerates the categories of kernel refusal we
// translate into signals. Wire-stable strings — new kinds add
// without breaking existing event sources.
type RefusalKind string

const (
	// RefuseExec — execve() blocked by AppArmor/seccomp/LSM.
	RefuseExec RefusalKind = "exec"
	// RefuseWrite — write to path blocked by AppArmor.
	RefuseWrite RefusalKind = "write"
	// RefuseSyscall — generic syscall blocked by seccomp.
	RefuseSyscall RefusalKind = "syscall"
	// RefuseConnect — outbound connect() blocked (not the same as
	// Ring 2 sinkhole — this is hard refusal).
	RefuseConnect RefusalKind = "connect"
	// RefuseMemory — mmap/mprotect with PROT_EXEC|PROT_WRITE.
	RefuseMemory RefusalKind = "memory"
	// RefuseIdentity — process identity mismatch detected by the
	// serviceid matcher (binary swap, unit hijack, uid change).
	RefuseIdentity RefusalKind = "identity"
)

// RefusalEvent is one observation. Event sources fill this from
// whatever kernel telemetry they have (eBPF LSM, audit netlink,
// /var/log/audit/audit.log).
type RefusalEvent struct {
	Kind        RefusalKind
	At          time.Time
	PID         uint32
	LineageID   uint64
	CGroupID    uint64
	ServiceName string // matcher-resolved; empty if no protected svc

	// Kind-specific fields. Only the ones relevant to Kind are
	// populated.
	Path        string // RefuseExec / RefuseWrite / RefuseMemory
	SyscallName string // RefuseSyscall
	RemoteIP    string // RefuseConnect
	RemotePort  uint16 // RefuseConnect
	Source      string // free-form ("apparmor:audit", "ebpf:bprm")
	Detail      string // human-readable extra (e.g. AppArmor reason)
	Discrepancy string // RefuseIdentity reason ("exe_sha mismatch")
}

// Evaluator classifies refusals into typed Signals. Stateless;
// instantiate once and call Evaluate per-event from the dispatcher.
type Evaluator struct{}

// NewEvaluator returns a stateless Evaluator.
func NewEvaluator() *Evaluator { return &Evaluator{} }

// Evaluate produces zero-or-one takeover.Signal from a refusal +
// the matched ProtectedService. svc may be nil (refusal from a
// non-protected process) — in that case we still produce a signal
// for high-severity classes (RWX memory, identity mismatch) because
// they're attack-grade regardless of which process did them.
//
// Returns the zero Signal (Kind == "") if the refusal isn't
// score-worthy.
func (e *Evaluator) Evaluate(rf RefusalEvent, svc *protectedsvc.ProtectedService) takeover.Signal {
	if rf.At.IsZero() {
		rf.At = time.Now().UTC()
	}
	kind := classify(rf, svc)
	if kind == "" {
		return takeover.Signal{}
	}
	return takeover.Signal{
		LineageID:  rf.LineageID,
		Kind:       kind,
		At:         rf.At,
		Source:     pickSource(rf),
		Detail:     buildDetail(rf),
		Confidence: confidenceFor(kind),
		RemoteIP:   rf.RemoteIP,
	}
}

// classify maps RefusalEvent → SignalKind using the contract +
// never-learnable lists. Pure function so tests can hit every branch.
func classify(rf RefusalEvent, svc *protectedsvc.ProtectedService) takeover.SignalKind {
	switch rf.Kind {
	case RefuseExec:
		// Use the contracts classifier — it knows about
		// shell/interp/downloader/recon/priv categories.
		switch contracts.ClassifyExecAttempt(rf.Path) {
		case "shell_attempt":
			return takeover.SignalShellAttempt
		case "interp_attempt":
			return takeover.SignalInterpAttempt
		case "downloader":
			return takeover.SignalDownloader
		case "recon_tool":
			return takeover.SignalReconTool
		case "priv_tool":
			return takeover.SignalPrivTool
		}
		// Not on the never-learnable list; could still be an
		// operator-declared deny (e.g. custom evil tool). If the
		// path matches a contract DenyExecPaths entry, emit a
		// generic defense-evasion signal (Tier-1 weight 90).
		if svc != nil && pathInList(rf.Path, svc.Contract.DenyExecPaths) {
			return takeover.SignalDefenseEvasion
		}
		return ""

	case RefuseWrite:
		// Any blocked write to a path outside WriteRoots is
		// Tier-1 forbidden-write. This requires a protected svc
		// to know what's "outside" — non-svc refusals get nothing.
		if svc == nil {
			return ""
		}
		return takeover.SignalForbiddenWrite

	case RefuseSyscall:
		// Never-learnable syscalls escalate to defense-evasion
		// (someone tried ptrace/bpf/perf_event_open — that's
		// post-exploit recon at minimum). Other syscalls are
		// generic Tier-2 noise.
		if contracts.IsNeverLearnableSyscall(rf.SyscallName) {
			// ptrace/bpf especially target xhelix itself.
			return takeover.SignalDefenseEvasion
		}
		return takeover.SignalForbiddenSyscall

	case RefuseConnect:
		return takeover.SignalForbiddenConnect

	case RefuseMemory:
		// RWX memory primitives are always high-severity.
		return takeover.SignalRWXMemory

	case RefuseIdentity:
		return takeover.SignalIdentityMismatch
	}
	return ""
}

// confidenceFor returns the confidence tier for a SignalKind. Used
// downstream by the planner and forensics.
func confidenceFor(k takeover.SignalKind) string {
	switch k {
	case takeover.SignalShellAttempt,
		takeover.SignalDownloader,
		takeover.SignalReconTool,
		takeover.SignalPrivTool,
		takeover.SignalRWXMemory,
		takeover.SignalForbiddenWrite,
		takeover.SignalDecoyTouch,
		takeover.SignalCrashLoop,
		takeover.SignalIdentityMismatch,
		takeover.SignalDefenseEvasion:
		return "deterministic"
	case takeover.SignalInterpAttempt,
		takeover.SignalC2Beacon:
		return "high"
	case takeover.SignalForbiddenConnect,
		takeover.SignalForbiddenSyscall:
		return "medium"
	}
	return ""
}

func pathInList(p string, list []string) bool {
	for _, x := range list {
		if x == p {
			return true
		}
	}
	return false
}

func pickSource(rf RefusalEvent) string {
	if rf.Source != "" {
		return rf.Source
	}
	if rf.ServiceName != "" {
		return "protectpolicy:" + rf.ServiceName
	}
	return "protectpolicy"
}

func buildDetail(rf RefusalEvent) string {
	var parts []string
	if rf.Path != "" {
		parts = append(parts, rf.Path)
	}
	if rf.SyscallName != "" {
		parts = append(parts, "syscall="+rf.SyscallName)
	}
	if rf.RemoteIP != "" {
		parts = append(parts, "remote="+rf.RemoteIP)
	}
	if rf.Discrepancy != "" {
		parts = append(parts, rf.Discrepancy)
	}
	if rf.Detail != "" {
		parts = append(parts, rf.Detail)
	}
	return strings.Join(parts, " ")
}

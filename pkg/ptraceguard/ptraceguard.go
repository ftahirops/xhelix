// Package ptraceguard classifies ptrace(2) calls captured by the
// existing eBPF tracepoint. ptrace is the highest-fidelity Linux
// signal for process injection — every "Linux malware injects
// into another process" attack chain ends at a PTRACE_POKETEXT or
// PTRACE_POKEDATA.
//
// The package is pure: caller passes a Spec (request code, source +
// target pid, request operands when known, plus process context)
// and gets back a Finding with severity + reasons.
//
// xhelix wide-cast captures every ptrace event; the classifier is
// where the noise gets filtered. Default-allow: gdb / strace / lldb
// against developer-owned processes scores SeverityNotice; the
// same calls from a non-developer process against a privileged
// target are upgraded to Critical.
package ptraceguard

import (
	"path/filepath"
	"strings"
)

// PTRACE_* request constants from sys/ptrace.h. We include only
// the ones we classify; unknown requests fall through to Notice.
const (
	PTRACE_TRACEME       = 0
	PTRACE_PEEKTEXT      = 1
	PTRACE_PEEKDATA      = 2
	PTRACE_PEEKUSR       = 3
	PTRACE_POKETEXT      = 4 // code injection
	PTRACE_POKEDATA      = 5 // data injection
	PTRACE_POKEUSR       = 6 // user-area write
	PTRACE_CONT          = 7
	PTRACE_KILL          = 8
	PTRACE_SINGLESTEP    = 9
	PTRACE_GETREGS       = 12
	PTRACE_SETREGS       = 13 // register hijack
	PTRACE_GETFPREGS     = 14
	PTRACE_SETFPREGS     = 15
	PTRACE_ATTACH        = 16 // debugger attach
	PTRACE_DETACH        = 17
	PTRACE_SYSCALL       = 24
	PTRACE_SETOPTIONS    = 0x4200
	PTRACE_GETEVENTMSG   = 0x4201
	PTRACE_SEIZE         = 0x4206 // newer, non-stop attach
	PTRACE_INTERRUPT     = 0x4207
	PTRACE_LISTEN        = 0x4208
)

// Severity grades a Finding.
type Severity uint8

const (
	SeverityNone     Severity = 0
	SeverityNotice   Severity = 2
	SeverityWarn     Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

func (s Severity) String() string {
	switch s {
	case SeverityNotice:
		return "notice"
	case SeverityWarn:
		return "warn"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "none"
}

// Spec is the input record.
type Spec struct {
	// Request is the ptrace request code.
	Request uint32
	// SourcePID / SourceExe / SourceComm describe the caller.
	SourcePID  uint32
	SourceExe  string
	SourceComm string
	// TargetPID / TargetExe describe the process being traced.
	// TargetExe may be empty if xhelix can't read /proc/<pid>/exe
	// at the time of the event.
	TargetPID  uint32
	TargetExe  string
	TargetComm string
	// CGroupClass is the caller's cgroup class (user / system /
	// container / kernel), already resolved by pkg/cgroupclass.
	CGroupClass string
	// IsSelfTrace is true when SourcePID == TargetPID. Common in
	// anti-debug detection ("am I being debugged?") and not by
	// itself suspicious.
	IsSelfTrace bool
}

// Finding is the classifier output.
type Finding struct {
	Severity     Severity
	RequestName  string
	Reasons      []string
}

// RequestName returns the human-readable name for a ptrace
// request code. Unknown codes render as "PTRACE_<n>".
func RequestName(r uint32) string {
	switch r {
	case PTRACE_TRACEME:
		return "PTRACE_TRACEME"
	case PTRACE_PEEKTEXT:
		return "PTRACE_PEEKTEXT"
	case PTRACE_PEEKDATA:
		return "PTRACE_PEEKDATA"
	case PTRACE_PEEKUSR:
		return "PTRACE_PEEKUSR"
	case PTRACE_POKETEXT:
		return "PTRACE_POKETEXT"
	case PTRACE_POKEDATA:
		return "PTRACE_POKEDATA"
	case PTRACE_POKEUSR:
		return "PTRACE_POKEUSR"
	case PTRACE_CONT:
		return "PTRACE_CONT"
	case PTRACE_KILL:
		return "PTRACE_KILL"
	case PTRACE_SINGLESTEP:
		return "PTRACE_SINGLESTEP"
	case PTRACE_GETREGS:
		return "PTRACE_GETREGS"
	case PTRACE_SETREGS:
		return "PTRACE_SETREGS"
	case PTRACE_GETFPREGS:
		return "PTRACE_GETFPREGS"
	case PTRACE_SETFPREGS:
		return "PTRACE_SETFPREGS"
	case PTRACE_ATTACH:
		return "PTRACE_ATTACH"
	case PTRACE_DETACH:
		return "PTRACE_DETACH"
	case PTRACE_SYSCALL:
		return "PTRACE_SYSCALL"
	case PTRACE_SETOPTIONS:
		return "PTRACE_SETOPTIONS"
	case PTRACE_GETEVENTMSG:
		return "PTRACE_GETEVENTMSG"
	case PTRACE_SEIZE:
		return "PTRACE_SEIZE"
	case PTRACE_INTERRUPT:
		return "PTRACE_INTERRUPT"
	case PTRACE_LISTEN:
		return "PTRACE_LISTEN"
	}
	return "PTRACE_" + itoa(int(r))
}

// Classify returns the Finding for s.
func Classify(s Spec) Finding {
	name := RequestName(s.Request)
	f := Finding{RequestName: name}
	raise := func(to Severity, r string) {
		if to > f.Severity {
			f.Severity = to
		}
		f.Reasons = append(f.Reasons, r)
	}

	// Self-trace (PTRACE_TRACEME or attach to self) is anti-debug
	// and benign by itself.
	if s.Request == PTRACE_TRACEME {
		raise(SeverityNotice, "PTRACE_TRACEME — process opting into being traced (anti-debug)")
		return f
	}
	if s.IsSelfTrace {
		raise(SeverityNotice, "self-trace — anti-debug or instrumentation")
		return f
	}

	// Per-request base severity.
	switch s.Request {
	case PTRACE_POKETEXT, PTRACE_POKEDATA:
		raise(SeverityCritical, name+" — writing to target memory (code/data injection)")
	case PTRACE_POKEUSR:
		raise(SeverityCritical, "PTRACE_POKEUSR — writing to target user-area (register/state hijack)")
	case PTRACE_SETREGS, PTRACE_SETFPREGS:
		raise(SeverityHigh, name+" — overwriting target registers")
	case PTRACE_ATTACH, PTRACE_SEIZE:
		raise(SeverityHigh, name+" — taking control of another process")
	case PTRACE_PEEKTEXT, PTRACE_PEEKDATA, PTRACE_PEEKUSR:
		raise(SeverityWarn, name+" — reading target memory")
	case PTRACE_GETREGS, PTRACE_GETFPREGS:
		raise(SeverityWarn, name+" — reading target registers")
	case PTRACE_SYSCALL, PTRACE_SINGLESTEP, PTRACE_CONT,
		PTRACE_DETACH, PTRACE_SETOPTIONS, PTRACE_GETEVENTMSG,
		PTRACE_INTERRUPT, PTRACE_LISTEN, PTRACE_KILL:
		raise(SeverityNotice, name)
	default:
		raise(SeverityNotice, name+" — unrecognised request code")
	}

	// Context boosts / downgrades.
	if isKnownDebugger(s.SourceComm) || isKnownDebugger(filepath.Base(s.SourceExe)) {
		// Known debugger: downgrade by one if we landed at High,
		// keep Critical for POKE* — debuggers writing other
		// processes' memory is still attention-worthy in
		// production.
		if f.Severity == SeverityHigh {
			f.Severity = SeverityWarn
			f.Reasons = append(f.Reasons, "downgraded — caller is known debugger ("+s.SourceComm+")")
		} else if f.Severity == SeverityWarn {
			f.Severity = SeverityNotice
			f.Reasons = append(f.Reasons, "downgraded — caller is known debugger ("+s.SourceComm+")")
		}
		return f
	}

	// Target is a privileged or security-critical process — upgrade.
	if isHighValueTarget(s.TargetComm) || isHighValueTarget(filepath.Base(s.TargetExe)) {
		if f.Severity < SeverityCritical {
			f.Severity = SeverityCritical
			f.Reasons = append(f.Reasons,
				"upgraded — target is privileged/security-critical ("+s.TargetComm+")")
		}
	}

	// Container caller upgrade — ptrace into another process from
	// inside a container almost never legitimate.
	if s.CGroupClass == "container" && f.Severity < SeverityCritical {
		if s.Request != PTRACE_TRACEME && !s.IsSelfTrace {
			if f.Severity < SeverityHigh {
				f.Severity = SeverityHigh
				f.Reasons = append(f.Reasons, "container caller traced another process — uncommon escape primitive")
			}
		}
	}

	return f
}

// IsInjection reports whether the request is one of the
// memory-write variants — the universally-malicious subset.
func IsInjection(req uint32) bool {
	switch req {
	case PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_POKEUSR,
		PTRACE_SETREGS, PTRACE_SETFPREGS:
		return true
	}
	return false
}

// ── data tables ───────────────────────────────────────────────

// knownDebuggers is the basename set of legitimate ptrace callers.
var knownDebuggers = map[string]struct{}{
	"gdb":      {},
	"lldb":     {},
	"strace":   {},
	"ltrace":   {},
	"perf":     {},
	"rr":       {},
	"valgrind": {},
	"dlv":      {},  // delve, Go debugger
	"radare2":  {},
	"r2":       {},
	"drrun":    {},  // DynamoRIO
}

func isKnownDebugger(s string) bool {
	if s == "" {
		return false
	}
	_, ok := knownDebuggers[s]
	return ok
}

// highValueTargets are processes that should rarely be traced by
// anything — credential daemons, the audit framework, the agent
// itself.
var highValueTargets = map[string]struct{}{
	"sshd":            {},
	"sudo":            {},
	"login":           {},
	"gdm":             {},
	"gdm-session-worker": {},
	"systemd":         {},
	"systemd-logind":  {},
	"auditd":          {},
	"polkitd":         {},
	"agetty":          {},
	"xhelix":          {},
	"xhub":            {},
	"chronyd":         {},
	"keyring-daemon":  {},
	"gnome-keyring-daemon": {},
}

func isHighValueTarget(s string) bool {
	if s == "" {
		return false
	}
	_, ok := highValueTargets[s]
	return ok
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// stripPrefix exposes a tiny helper for callers needing to
// normalise basename-from-path.
func Basename(p string) string {
	return filepath.Base(p)
}

var _ = strings.HasPrefix // keep strings import even if unused above

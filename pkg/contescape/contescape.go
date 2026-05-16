// Package contescape classifies container-escape signals captured
// by the eBPF pivot_root + unshare tracepoints.
//
// What we're looking for:
//   - pivot_root by anything that isn't the runtime at container
//     start. Inside a running container, pivot_root means an
//     attempt to swap the root filesystem out from under the
//     workload — classic escape gadget.
//   - unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID) by a
//     workload process — the standard escape primitive sequence.
//
// The package is pure-Go: it takes a Spec (the captured event +
// process context) and returns a Finding. Decisions are by
// process context (cgroup class, parent exe), not by the
// syscall in isolation — pivot_root by the *runtime* itself is
// fine; by an nginx descendant inside a container is not.
package contescape

import (
	"sort"
	"strings"
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

// SyscallKind is which trace was hit.
type SyscallKind uint8

const (
	SyscallPivotRoot SyscallKind = 1
	SyscallUnshare   SyscallKind = 2
)

// CLONE_NEW* flag bit positions from linux/sched.h
const (
	CLONE_NEWNS     uint64 = 0x00020000
	CLONE_NEWUSER   uint64 = 0x10000000
	CLONE_NEWPID    uint64 = 0x20000000
	CLONE_NEWNET    uint64 = 0x40000000
	CLONE_NEWIPC    uint64 = 0x08000000
	CLONE_NEWUTS    uint64 = 0x04000000
	CLONE_NEWCGROUP uint64 = 0x02000000
)

// Spec is the input record.
type Spec struct {
	Syscall     SyscallKind
	Flags       uint64 // only used for Unshare
	PID         uint32
	Comm        string
	Exe         string
	ParentExe   string
	CGroupClass string // "user" / "system" / "container" / "kernel"
	Ancestors   []string
}

// Finding is the classifier output.
type Finding struct {
	Severity   Severity
	Reasons    []string
	Namespaces []string // human-readable list of CLONE_NEW* bits, when applicable
}

// knownRuntimes — basename matches that legitimately call
// pivot_root and unshare at container boot.
var knownRuntimes = map[string]struct{}{
	"runc":                {},
	"crun":                {},
	"containerd-shim":     {},
	"containerd-shim-runc-v2": {},
	"docker-init":         {},
	"dockerd":             {},
	"docker":              {},
	"podman":              {},
	"conmon":              {},
	"systemd-nspawn":      {},
	"unshare":             {}, // operator-invoked, but rare in workloads
	"buildkit-runc":       {},
	"crio":                {},
	"firecracker":         {},
}

// Classify returns the Finding for s.
func Classify(s Spec) Finding {
	f := Finding{}
	raise := func(to Severity, r string) {
		if to > f.Severity {
			f.Severity = to
		}
		f.Reasons = append(f.Reasons, r)
	}

	switch s.Syscall {
	case SyscallPivotRoot:
		// pivot_root is exclusively a runtime/init-time call.
		// Anything else is escape unless we explicitly recognise
		// the caller.
		if isKnownRuntime(s.Comm) || isKnownRuntime(basename(s.Exe)) {
			raise(SeverityInfo("info_runtime_init"), "pivot_root by known container runtime")
			return f
		}
		if isAnyAncestorRuntime(s.Ancestors) {
			raise(SeverityNotice, "pivot_root by descendant of container runtime")
			return f
		}
		// In a container, by an unknown caller, is critical.
		if s.CGroupClass == "container" {
			raise(SeverityCritical, "pivot_root inside container by non-runtime process — escape attempt")
			return f
		}
		raise(SeverityHigh, "pivot_root by non-runtime process")

	case SyscallUnshare:
		f.Namespaces = decodeFlags(s.Flags)
		if len(f.Namespaces) == 0 {
			// unshare(0) is a no-op — informational only.
			return f
		}
		// Workloads inside a container that call unshare are the
		// textbook escape primitive sequence.
		caller := basename(s.Exe)
		if isKnownRuntime(s.Comm) || isKnownRuntime(caller) {
			raise(SeverityNotice, "unshare by container runtime/tooling")
			return f
		}
		// Heuristics by flag.
		risky := s.Flags & (CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID)
		switch {
		case s.CGroupClass == "container" && risky != 0:
			raise(SeverityCritical, "unshare("+strings.Join(f.Namespaces, "|")+") inside container by workload — escape primitive")
		case risky != 0 && isWebDaemon(s.ParentExe):
			raise(SeverityHigh, "unshare("+strings.Join(f.Namespaces, "|")+") under web daemon — likely post-exploit")
		case s.Flags&CLONE_NEWUSER != 0:
			raise(SeverityHigh, "CLONE_NEWUSER outside expected context — common escape building block")
		case risky != 0:
			raise(SeverityWarn, "unshare("+strings.Join(f.Namespaces, "|")+") by unexpected caller")
		default:
			raise(SeverityNotice, "unshare("+strings.Join(f.Namespaces, "|")+")")
		}
	}
	return f
}

// SeverityInfo helper for the rare case where we want to surface
// runtime calls as informational rather than dropping them
// entirely (operators can grep for them in audit views).
func SeverityInfo(_ string) Severity { return SeverityNotice }

// decodeFlags returns the list of human-readable CLONE_NEW*
// names corresponding to flags.
func decodeFlags(flags uint64) []string {
	type bit struct {
		mask uint64
		name string
	}
	bits := []bit{
		{CLONE_NEWNS, "CLONE_NEWNS"},
		{CLONE_NEWUSER, "CLONE_NEWUSER"},
		{CLONE_NEWPID, "CLONE_NEWPID"},
		{CLONE_NEWNET, "CLONE_NEWNET"},
		{CLONE_NEWIPC, "CLONE_NEWIPC"},
		{CLONE_NEWUTS, "CLONE_NEWUTS"},
		{CLONE_NEWCGROUP, "CLONE_NEWCGROUP"},
	}
	out := make([]string, 0, len(bits))
	for _, b := range bits {
		if flags&b.mask != 0 {
			out = append(out, b.name)
		}
	}
	sort.Strings(out)
	return out
}

func isKnownRuntime(name string) bool {
	if name == "" {
		return false
	}
	if _, ok := knownRuntimes[name]; ok {
		return true
	}
	if strings.HasPrefix(name, "containerd-shim") {
		return true
	}
	return false
}

func isAnyAncestorRuntime(anc []string) bool {
	for _, a := range anc {
		if isKnownRuntime(basename(a)) {
			return true
		}
	}
	return false
}

func isWebDaemon(p string) bool {
	if p == "" {
		return false
	}
	switch basename(p) {
	case "nginx", "apache2", "httpd", "caddy", "haproxy",
		"php-fpm", "uwsgi", "gunicorn", "puma", "tomcat", "jetty":
		return true
	}
	return false
}

func basename(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

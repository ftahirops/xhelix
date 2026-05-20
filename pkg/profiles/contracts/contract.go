// Package contracts ships built-in ServiceContract defaults for the
// supported (Kind, Role) combinations and overlays operator config
// on top. See PROTECTED_SERVICES_TRAP.md §9 + §5.4.
//
// The built-ins encode the "never-learnable invariants" from the
// design: shell/interpreter/downloader/recon/privilege exec,
// memory-corruption primitives, namespace-escape syscalls. These
// CANNOT be removed by an operator override — they're invariants,
// not preferences. Merge() returns an error if an operator config
// tries to add them to AllowExecPaths.
//
// The package has zero behavior. It returns ServiceContract values
// that pkg/prevent/* consumes to generate seccomp/AppArmor profiles,
// and that pkg/deception/* consumes to know when to engage Ring 2.
package contracts

import (
	"errors"
	"fmt"
	"strings"

	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

// ErrInvariantViolation is returned by Merge() when the operator
// override attempts to weaken a baked-in security invariant.
var ErrInvariantViolation = errors.New("contracts: invariant violation (operator override forbidden)")

// ErrUnsupportedRole is returned when (Kind, Role) has no built-in.
var ErrUnsupportedRole = errors.New("contracts: unsupported (kind, role) combination")

// Builtin returns the default ServiceContract for the given Kind
// and Role. Returns ErrUnsupportedRole if no built-in exists.
func Builtin(kind protectedsvc.ServiceKind, role protectedsvc.ServiceRole) (protectedsvc.ServiceContract, error) {
	switch kind {
	case protectedsvc.KindNginx:
		return builtinNginx(role)
	case protectedsvc.KindApache:
		return builtinApache(role)
	}
	return protectedsvc.ServiceContract{}, fmt.Errorf("%w: kind=%q role=%q", ErrUnsupportedRole, kind, role)
}

// NeverLearnableExec is the union of exec paths that may NEVER appear
// in any service's AllowExecPaths, regardless of role or operator
// override. Source of truth for the §5.4 invariants.
//
// Note: php-fpm IPC from nginx is the canonical legitimate path for
// invoking PHP — that goes through a UNIX socket, not exec. So
// /usr/bin/php is forbidden as a direct exec target for nginx.
var NeverLearnableExec = []string{
	// Shells
	"/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash", "/bin/zsh",
	"/bin/ksh", "/bin/csh", "/bin/tcsh", "/bin/fish",
	// Interpreters (when invoked directly, not via FastCGI sock)
	"/usr/bin/python", "/usr/bin/python2", "/usr/bin/python3",
	"/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/node",
	"/usr/bin/php", "/usr/bin/php-cgi", "/usr/bin/lua",
	// Downloaders
	"/usr/bin/curl", "/usr/bin/wget", "/usr/bin/fetch",
	"/usr/bin/aria2c", "/usr/bin/axel",
	// Recon
	"/usr/bin/nmap", "/usr/bin/nc", "/usr/bin/ncat",
	"/usr/bin/socat", "/usr/sbin/tcpdump",
	// Privilege
	"/usr/bin/su", "/usr/bin/sudo", "/usr/bin/pkexec", "/usr/bin/doas",
	// Common malware staging
	"/usr/bin/base64", "/usr/bin/xxd", "/usr/bin/openssl",
}

// NeverLearnableSyscalls is the syscall deny-list baked in for ALL
// protected services regardless of contract. Operator override can
// ADD to deny list; it cannot REMOVE entries from this set.
var NeverLearnableSyscalls = []string{
	"ptrace", "userfaultfd", "bpf", "perf_event_open",
	"mount", "umount2", "pivot_root", "unshare", "setns",
	"kexec_load", "kexec_file_load", "init_module", "finit_module",
	"delete_module", "swapon", "swapoff", "reboot",
	// Cross-process memory access — exploit primitive for reading
	// other process address spaces. Per the live-exploit-detection
	// comparison, a sleeper signal worth blocking from any
	// protected web server.
	"process_vm_readv", "process_vm_writev",
}

// NeverLearnableMemory is the always-deny memory primitive set.
var NeverLearnableMemory = []protectedsvc.MemoryPrimitive{
	protectedsvc.MemAnonRWX,
	protectedsvc.MemMemfdExec,
	protectedsvc.MemRWXMProtect,
	protectedsvc.MemPtrace,
	protectedsvc.MemUserfaultfd,
}

// Merge overlays an operator-supplied contract on top of a built-in.
// Override semantics:
//
//   - Lists in the override REPLACE the built-in list when non-empty,
//     EXCEPT the deny lists (DenyExecPaths, DenySyscalls,
//     DenyMemoryPrimitives) which UNION with the never-learnable
//     baseline.
//   - Booleans in the override always win (operator can flip
//     StrictReadOnly either direction).
//
// Returns ErrInvariantViolation if the override tries to allow any
// NeverLearnable entry.
func Merge(builtin, override protectedsvc.ServiceContract) (protectedsvc.ServiceContract, error) {
	// Invariant check FIRST — never silently accept an unsafe override.
	for _, p := range override.AllowExecPaths {
		if isNeverLearnable(p) {
			return protectedsvc.ServiceContract{},
				fmt.Errorf("%w: AllowExecPaths contains never-learnable %q", ErrInvariantViolation, p)
		}
	}

	out := builtin

	// Allow-lists: override replaces when non-empty (operator knows
	// what their app needs).
	if len(override.AllowExecPaths) > 0 {
		out.AllowExecPaths = dedupe(override.AllowExecPaths)
	}
	if len(override.WriteRoots) > 0 {
		out.WriteRoots = dedupe(override.WriteRoots)
	}
	if len(override.ReadSensitiveRoots) > 0 {
		out.ReadSensitiveRoots = dedupe(override.ReadSensitiveRoots)
	}
	if len(override.UpstreamCIDRs) > 0 {
		out.UpstreamCIDRs = dedupe(override.UpstreamCIDRs)
	}
	if len(override.DNSResolvers) > 0 {
		out.DNSResolvers = dedupe(override.DNSResolvers)
	}
	if len(override.UnixSockets) > 0 {
		out.UnixSockets = dedupe(override.UnixSockets)
	}
	if len(override.ListenPorts) > 0 {
		out.ListenPorts = dedupePorts(override.ListenPorts)
	}

	// Deny-lists: UNION the override with the built-in (operator can
	// only TIGHTEN, never loosen). The built-in already includes the
	// never-learnable baseline.
	out.DenyExecPaths = unionStrings(out.DenyExecPaths, override.DenyExecPaths)
	out.DenySyscalls = unionStrings(out.DenySyscalls, override.DenySyscalls)
	out.DenyMemoryPrimitives = unionMemPrimitives(out.DenyMemoryPrimitives, override.DenyMemoryPrimitives)

	// Booleans — operator always wins.
	out.StrictReadOnly = override.StrictReadOnly || builtin.StrictReadOnly

	return out, nil
}

// IsNeverLearnableExec reports whether p appears in the
// NeverLearnableExec list. Exported for tests + for the matcher to
// quickly classify exec attempts as Tier-1 SignalShellAttempt /
// SignalInterpAttempt / SignalDownloader.
func IsNeverLearnableExec(p string) bool { return isNeverLearnable(p) }

// IsNeverLearnableSyscall reports whether name is always denied.
func IsNeverLearnableSyscall(name string) bool {
	for _, s := range NeverLearnableSyscalls {
		if s == name {
			return true
		}
	}
	return false
}

// IsNeverLearnableMemory reports whether prim is always denied.
func IsNeverLearnableMemory(prim protectedsvc.MemoryPrimitive) bool {
	for _, m := range NeverLearnableMemory {
		if m == prim {
			return true
		}
	}
	return false
}

// ClassifyExecAttempt returns the takeover.SignalKind name for an
// exec-attempt event against the given path. Returns "" if the path
// is not on the never-learnable list. Caller uses the returned
// string as the SignalKind in the aggregator.
//
// Returned values mirror takeover.SignalKind constants but are
// kept as strings here to avoid an import cycle. The consumer
// (pkg/protectpolicy in P-PS.5) maps these to the typed SignalKind.
func ClassifyExecAttempt(path string) string {
	low := strings.ToLower(path)
	base := low
	if i := strings.LastIndex(low, "/"); i >= 0 {
		base = low[i+1:]
	}
	switch {
	case isShell(base):
		return "shell_attempt"
	case isInterp(base):
		return "interp_attempt"
	case isDownloader(base):
		return "downloader"
	case isRecon(base):
		return "recon_tool"
	case isPriv(base):
		return "priv_tool"
	}
	return ""
}

// ClassifyArgvShape (P-PS.21) inspects the FULL argv of a forbidden
// exec attempt and returns a more-specific SignalKind name for
// known dropper patterns:
//
//   base64_decode    — `base64 -d`, `openssl base64 -d`, `xxd -r -p`
//   recursive_delete — `rm -rf` against any path
//   chmod_exec       — `chmod +x` / `chmod 0?7??` on a path under
//                       /tmp, /dev/shm, /var/tmp, or /run
//
// Returns "" if the argv is not on the dropper list. Cheap; meant
// to be called from the protectpolicy refusal classifier on every
// argv-bearing exec event.
//
// Borrowed from IDE Shepherd's task_base64_decode / task_rm_rf /
// task_chmod_executable rules but adapted to per-process exec
// rather than .vscode/tasks.json.
func ClassifyArgvShape(path string, argv []string) string {
	low := strings.ToLower(path)
	base := low
	if i := strings.LastIndex(low, "/"); i >= 0 {
		base = low[i+1:]
	}

	switch base {
	case "base64":
		if argvContains(argv, "-d", "--decode") {
			return "base64_decode"
		}
	case "openssl":
		if len(argv) >= 2 && argv[0] == "base64" && argvContains(argv, "-d") {
			return "base64_decode"
		}
	case "xxd":
		if argvContains(argv, "-r") {
			return "base64_decode"
		}
	case "rm":
		// "rm -rf <path>" or "rm -r -f" etc. Either of the deletion
		// recursion flags + force is enough.
		if argvContainsAny(argv, "-rf", "-fr", "--recursive") ||
			(argvContains(argv, "-r") && argvContains(argv, "-f")) ||
			(argvContains(argv, "-R") && argvContains(argv, "-f")) {
			return "recursive_delete"
		}
	case "chmod":
		// chmod +x / chmod 0?7?? on a tempfile path is the
		// canonical dropper signature.
		if argvHasChmodExec(argv) && argvTargetsTempfile(argv) {
			return "chmod_exec"
		}
	}
	return ""
}

func argvContains(argv []string, needles ...string) bool {
	for _, a := range argv {
		for _, n := range needles {
			if a == n {
				return true
			}
		}
	}
	return false
}

func argvContainsAny(argv []string, needles ...string) bool { return argvContains(argv, needles...) }

func argvHasChmodExec(argv []string) bool {
	for _, a := range argv {
		if a == "+x" || a == "u+x" || a == "g+x" || a == "o+x" || a == "a+x" {
			return true
		}
		// Numeric modes: any with the exec bit on (xx7, xx5, xx3, xx1).
		if len(a) == 3 || len(a) == 4 {
			last := a[len(a)-1]
			if last == '1' || last == '3' || last == '5' || last == '7' {
				// Only treat as suspicious if it's pure-digit (real
				// mode strings start with 0 or 1-7).
				allDigit := true
				for _, r := range a {
					if r < '0' || r > '7' {
						allDigit = false
					}
				}
				if allDigit {
					return true
				}
			}
		}
	}
	return false
}

func argvTargetsTempfile(argv []string) bool {
	for _, a := range argv {
		low := strings.ToLower(a)
		for _, prefix := range []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/run/"} {
			if strings.HasPrefix(low, prefix) {
				return true
			}
		}
	}
	return false
}

// --- internals ---

func isNeverLearnable(p string) bool {
	for _, x := range NeverLearnableExec {
		if x == p {
			return true
		}
	}
	return false
}

func isShell(base string) bool {
	for _, s := range []string{"sh", "bash", "dash", "ash", "zsh", "ksh", "csh", "tcsh", "fish"} {
		if base == s {
			return true
		}
	}
	return false
}

func isInterp(base string) bool {
	for _, s := range []string{"python", "python2", "python3", "perl", "ruby", "node", "php", "php-cgi", "lua"} {
		if base == s {
			return true
		}
	}
	return false
}

func isDownloader(base string) bool {
	for _, s := range []string{"curl", "wget", "fetch", "aria2c", "axel"} {
		if base == s {
			return true
		}
	}
	return false
}

func isRecon(base string) bool {
	for _, s := range []string{"nmap", "nc", "ncat", "socat", "tcpdump"} {
		if base == s {
			return true
		}
	}
	return false
}

func isPriv(base string) bool {
	for _, s := range []string{"su", "sudo", "pkexec", "doas"} {
		if base == s {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func dedupePorts(in []uint16) []uint16 {
	seen := map[uint16]struct{}{}
	out := make([]uint16, 0, len(in))
	for _, p := range in {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func unionStrings(a, b []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range b {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func unionMemPrimitives(a, b []protectedsvc.MemoryPrimitive) []protectedsvc.MemoryPrimitive {
	seen := map[protectedsvc.MemoryPrimitive]struct{}{}
	out := make([]protectedsvc.MemoryPrimitive, 0, len(a)+len(b))
	for _, m := range a {
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	for _, m := range b {
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out
}

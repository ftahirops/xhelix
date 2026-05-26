//go:build linux

package selfprotect

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// applyNoNewPrivs sets PR_SET_NO_NEW_PRIVS. After this prctl returns
// successfully, execve() and clone() cannot grant privileges to any
// child via setuid/setgid bits, file capabilities, or LSM transitions.
//
// Safe for xhelix because:
//   - The daemon does not exec setuid helpers
//   - eBPF / nftables work through syscalls and caps the daemon
//     already holds, not via setuid wrappers
//   - response/enforce uses signals + cgroup writes, not setuid kill
//     helpers
//
// Effect: even if an attacker drops a setuid binary, our daemon
// cannot be coerced into spawning one with elevated privileges. The
// host's setuid binaries remain setuid for OTHER processes — this is
// a per-process bit on us only.
//
// Reference: man 2 prctl, kernel/sys.c PR_SET_NO_NEW_PRIVS handler.
func applyNoNewPrivs() error {
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL,
		unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", errno)
	}
	return nil
}

// applyNonDumpable sets PR_SET_DUMPABLE=0. Effects:
//   - Core dumps are suppressed (no /var/lib/systemd/coredump dump
//     leaking secrets, BPF program bytes, signing keys, etc.)
//   - /proc/<pid>/{mem,maps,environ,…} become root-only-readable
//     (specifically: owned by root:root regardless of fsuid)
//   - ptrace(PTRACE_ATTACH) is blocked from same-uid attackers
//     (Yama's protection works in addition, not instead)
//
// Safe for xhelix because:
//   - We don't rely on core dumps for diagnostics — we have the
//     chain, hot store, and journal
//   - We don't expose our /proc/<pid>/maps to non-root tools
//
// Reference: man 5 proc "/proc/[pid]/dumpable", man 2 prctl.
func applyNonDumpable() error {
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL,
		unix.PR_SET_DUMPABLE, 0, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("PR_SET_DUMPABLE=0: %w", errno)
	}
	return nil
}

// hardenProcess applies all Phase G.1 process-level mitigations.
// Each step is best-effort and logged through the caller; failures
// in one step do NOT abort the others (a kernel that lacks one
// prctl flag should not block startup).
func hardenProcess() (results []hardeningResult) {
	results = append(results, hardeningResult{
		Name: "PR_SET_NO_NEW_PRIVS", Err: applyNoNewPrivs(),
	})
	results = append(results, hardeningResult{
		Name: "PR_SET_DUMPABLE=0", Err: applyNonDumpable(),
	})
	return results
}

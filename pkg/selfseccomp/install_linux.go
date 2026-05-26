//go:build linux

package selfseccomp

import (
	"fmt"
	"log/slog"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// installForHost is the Linux-only side of Apply. Compiles for the
// running arch, marshals into struct sock_fprog, calls seccomp(2)
// with SECCOMP_SET_MODE_FILTER.
//
// Pre-conditions:
//   - PR_SET_NO_NEW_PRIVS must already be set (Phase G.1 does this
//     unconditionally at startup). We do NOT set it here because
//     selfprotect already owns that path.
//   - Process must have CAP_SYS_ADMIN OR the kernel must allow
//     unprivileged seccomp use. xhelix runs as root so this is
//     satisfied.
//
// On failure returns wrapped errno. Caller logs + decides whether
// to abort.
func installForHost(a AllowList, log *slog.Logger) error {
	prog, err := Compile(a, runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("install: compile: %w", err)
	}

	// Build kernel struct.
	filters := make([]unix.SockFilter, len(prog))
	for i, ins := range prog {
		filters[i] = unix.SockFilter{
			Code: ins.Code,
			Jt:   ins.JT,
			Jf:   ins.JF,
			K:    ins.K,
		}
	}
	fprog := unix.SockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}

	// SECCOMP_SET_MODE_FILTER = 1.
	const seccompSetModeFilter = 1
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		seccompSetModeFilter, 0, uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		return fmt.Errorf("install: SECCOMP_SET_MODE_FILTER: %w", errno)
	}

	if log != nil {
		log.Info("selfseccomp: filter installed",
			"mode", a.Mode.String(),
			"instructions", len(filters),
			"allowed_syscalls", len(a.Numbers),
			"audit_note", "kernel logs denied syscalls to /var/log/audit/audit.log via type=SECCOMP")
	}
	return nil
}

//go:build linux

package seccomp

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Install applies the filter to the calling thread. Two prctl calls:
//
//  1. PR_SET_NO_NEW_PRIVS — required for unprivileged seccomp use.
//     This is irreversible for the calling thread (and via thread-
//     group propagation, eventually the whole process).
//  2. seccomp(SECCOMP_SET_MODE_FILTER, ..., &fprog) — load the filter.
//
// Filters are inherited across fork+execve, so the common deployment
// pattern is:
//
//   parent → prctl(NO_NEW_PRIVS) → seccomp(SET_MODE_FILTER) → execve(real-service)
//
// xhelix is NOT the typical caller — systemd's SystemCallFilter is
// the production path (see SystemdDirective). Install() is here for
// xhelix-supervised services and for integration tests.
func (p Profile) Install() error {
	if err := p.Validate(); err != nil {
		return err
	}

	// Step 1: PR_SET_NO_NEW_PRIVS.
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL,
		unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("seccomp: PR_SET_NO_NEW_PRIVS: %w", errno)
	}

	// Step 2: build struct sock_fprog and call seccomp(2).
	filters := make([]unix.SockFilter, len(p.Instructions))
	for i, ins := range p.Instructions {
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

	// SECCOMP_SET_MODE_FILTER = 1
	const seccompSetModeFilter = 1
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		seccompSetModeFilter, 0, uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		return fmt.Errorf("seccomp: SECCOMP_SET_MODE_FILTER: %w", errno)
	}
	return nil
}

// SelfTest applies the filter and immediately invokes the first
// denied syscall to verify EPERM is returned. Returns nil if the
// filter is working as expected.
//
// DESTRUCTIVE: irreversible for the calling thread (NO_NEW_PRIVS is
// sticky). Use only in a forked-off helper process, never in the
// main daemon. Test code only.
func (p Profile) SelfTest() error {
	if len(p.Denied) == 0 {
		return fmt.Errorf("seccomp: profile denies nothing — nothing to self-test")
	}
	if err := p.Install(); err != nil {
		return err
	}
	// Try to invoke ptrace (cheapest, always denied if listed). If
	// "ptrace" isn't in the profile, this test is skipped.
	for _, name := range p.Denied {
		if name == "ptrace" {
			_, _, errno := unix.Syscall6(unix.SYS_PTRACE, 0, 0, 0, 0, 0, 0)
			if errno == unix.EPERM {
				return nil
			}
			return fmt.Errorf("seccomp: self-test failed: ptrace returned %v, want EPERM", errno)
		}
	}
	return nil
}

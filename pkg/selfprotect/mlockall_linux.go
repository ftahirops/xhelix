//go:build linux

package selfprotect

import "syscall"

// mlockall pins the current and future process memory so the
// kernel cannot swap secrets / keys / event payloads to disk.
// Returns nil on success, the syscall errno otherwise (typically
// EPERM when RLIMIT_MEMLOCK is too low).
func mlockall() error {
	const (
		MCL_CURRENT = 1
		MCL_FUTURE  = 2
	)
	_, _, errno := syscall.Syscall(syscall.SYS_MLOCKALL, MCL_CURRENT|MCL_FUTURE, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

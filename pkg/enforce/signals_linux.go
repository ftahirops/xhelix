//go:build linux

package enforce

import (
	"errors"
	"os"
	"syscall"
)

var (
	sigSTOP os.Signal = syscall.SIGSTOP
	sigCONT os.Signal = syscall.SIGCONT
	sigKILL os.Signal = syscall.SIGKILL

	errInvalidPID     = errors.New("enforce: refusing to signal pid 0 or 1")
	errNotQuarantined = errors.New("enforce: pid is not under quarantine")
)

// DefaultSignalFn is a wrapper around syscall.Kill suitable for
// production use. NewQuarantine(DefaultSignalFn) wires the real
// signal delivery path.
func DefaultSignalFn(pid int, sig os.Signal) error {
	s, ok := sig.(syscall.Signal)
	if !ok {
		return errors.New("enforce: signal is not a syscall.Signal")
	}
	return syscall.Kill(pid, s)
}

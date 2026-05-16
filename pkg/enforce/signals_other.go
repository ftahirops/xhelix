//go:build !linux

package enforce

import (
	"errors"
	"os"
)

// On non-Linux platforms we still compile, but signal delivery is a
// no-op. xhelix only enforces on Linux at runtime; cross-builds for
// developer machines (mac/windows) keep working.
var (
	sigSTOP os.Signal = os.Interrupt // unused
	sigCONT os.Signal = os.Interrupt
	sigKILL os.Signal = os.Kill

	errInvalidPID     = errors.New("enforce: refusing to signal pid 0 or 1")
	errNotQuarantined = errors.New("enforce: pid is not under quarantine")
)

// DefaultSignalFn is a no-op off Linux.
func DefaultSignalFn(pid int, sig os.Signal) error {
	return errors.New("enforce: signal delivery only supported on Linux")
}

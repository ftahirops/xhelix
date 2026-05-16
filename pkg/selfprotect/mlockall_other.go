//go:build !linux

package selfprotect

import "errors"

// mlockall is a no-op on non-Linux platforms. xhelix is Linux-only
// at runtime; this stub keeps cross-compilation green.
func mlockall() error {
	return errors.New("mlockall: not supported on this platform")
}

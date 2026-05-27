//go:build !linux

package landlock

import "fmt"

// probeABI is a no-op on non-Linux. xhelix doesn't run landlock on
// non-Linux at runtime; this stub keeps `go build` green.
func probeABI() (int, error) {
	return 0, fmt.Errorf("landlock: not supported on non-Linux")
}

func enforce(_ Policy, _ int, _ interface{}) error {
	return fmt.Errorf("landlock: not supported on non-Linux")
}

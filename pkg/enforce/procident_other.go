//go:build !linux

package enforce

// procStartTicks is Linux-only; on other platforms identity verification is a
// no-op (the daemon does not run in production off Linux).
func procStartTicks(pid uint32) (uint64, bool) { return 0, false }

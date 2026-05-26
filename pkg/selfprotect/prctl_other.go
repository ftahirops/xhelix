//go:build !linux

package selfprotect

// hardenProcess is a no-op on non-Linux platforms. xhelix is
// Linux-only at runtime; this stub keeps `go build` green on dev
// machines.
func hardenProcess() (results []hardeningResult) { return nil }

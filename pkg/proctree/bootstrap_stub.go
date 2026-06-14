//go:build !linux

package proctree

// BootstrapFromProc is a no-op on non-Linux. /proc only exists on Linux;
// daemons on other platforms run only for build-green purposes.
func (g *Graph) BootstrapFromProc() int { return 0 }

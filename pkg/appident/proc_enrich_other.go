//go:build !linux

package appident

// EnrichFromProc is a no-op on non-Linux dev builds. The daemon runs
// on Linux only; this stub exists so `go build` stays green on macOS
// dev machines.
func EnrichFromProc(pid uint32, s Signals) Signals { return s }

// ResolveCGroupID is a no-op on non-Linux builds.
func ResolveCGroupID(pid uint32) uint64 { return 0 }

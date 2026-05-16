//go:build linux && !amd64 && !arm64

package bpfprobe

// Unknown architecture; setting to 0 will produce ENOSYS at
// runtime, which Snapshot handles by returning empty results.
const sysBPF = 0

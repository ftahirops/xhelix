//go:build !linux

package bpfprobe

// SnapshotNow is a non-Linux stub. xhelix runs only on Linux at
// runtime; this exists so cross-builds stay green.
func SnapshotNow() (Snapshot, error) {
	return Snapshot{}, nil
}

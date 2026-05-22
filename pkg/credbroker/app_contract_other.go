//go:build !linux

package credbroker

import (
	"os"
	"time"
)

// statSig fallback for non-Linux dev builds. Uses size+mtime; cache
// is unreliable across platform-specific filesystems but the daemon
// only runs on Linux so this is dev-only.
func statSig(st os.FileInfo) (uint64, time.Time, bool) {
	return uint64(st.Size()), st.ModTime(), true
}

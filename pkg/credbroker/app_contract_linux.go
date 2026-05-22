//go:build linux

package credbroker

import (
	"os"
	"syscall"
	"time"
)

// statSig returns inode + mtime for sha-cache key on Linux.
func statSig(st os.FileInfo) (uint64, time.Time, bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, time.Time{}, false
	}
	return sys.Ino, st.ModTime(), true
}

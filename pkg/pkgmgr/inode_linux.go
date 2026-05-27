//go:build linux

package pkgmgr

import (
	"os"
	"syscall"
)

// statInode extracts the inode number from an os.FileInfo on Linux via
// syscall.Stat_t. Used by tailLog for log-rotation detection.
func statInode(fi os.FileInfo) (uint64, bool) {
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		return sys.Ino, true
	}
	return 0, false
}

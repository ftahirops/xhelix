//go:build linux

package integrity

import (
	"os"
	"syscall"
)

func statInode(st os.FileInfo) uint64 {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return sys.Ino
	}
	return 0
}

//go:build linux

package tamperguard

import (
	"os"
	"syscall"
)

func inodeOf(st os.FileInfo) uint64 {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return s.Ino
}

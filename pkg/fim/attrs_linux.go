//go:build linux

package fim

import (
	"os"
	"syscall"
)

func readPlatformAttrs(e *Entry, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	e.Inode = st.Ino
	e.UID = st.Uid
	e.GID = st.Gid
	return nil
}

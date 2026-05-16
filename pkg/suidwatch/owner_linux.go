//go:build linux

package suidwatch

import (
	"os"
	"syscall"
)

func fillOwnerLinux(e *Entry, info os.FileInfo) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		e.UID = st.Uid
		e.GID = st.Gid
	}
}

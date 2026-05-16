//go:build linux

package decoy

import (
	"os"
	"syscall"
	"time"
)

func statATime(info os.FileInfo) time.Time {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return info.ModTime()
	}
	return time.Unix(st.Atim.Sec, st.Atim.Nsec)
}

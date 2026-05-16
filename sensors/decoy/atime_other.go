//go:build !linux

package decoy

import (
	"os"
	"time"
)

// statATime is best-effort off Linux; fall back to ModTime.
func statATime(info os.FileInfo) time.Time {
	return info.ModTime()
}

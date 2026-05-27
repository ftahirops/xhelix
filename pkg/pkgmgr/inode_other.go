//go:build !linux

package pkgmgr

import "os"

// statInode is a no-op on non-Linux. xhelix doesn't run pkgmgr tailers on
// non-Linux at runtime; this stub keeps `go build` green.
func statInode(_ os.FileInfo) (uint64, bool) { return 0, false }

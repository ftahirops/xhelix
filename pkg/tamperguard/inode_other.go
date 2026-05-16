//go:build !linux

package tamperguard

import "os"

func inodeOf(_ os.FileInfo) uint64 { return 0 }

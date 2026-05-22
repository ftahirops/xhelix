//go:build !linux

package integrity

import "os"

func statInode(st os.FileInfo) uint64 { return 0 }

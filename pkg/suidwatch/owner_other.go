//go:build !linux

package suidwatch

import "os"

func fillOwnerLinux(e *Entry, info os.FileInfo) {
	// No-op on non-Linux; UID/GID stay zero.
}

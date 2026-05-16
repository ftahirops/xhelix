//go:build !linux

package fim

import "os"

// readPlatformAttrs is a no-op off Linux; cross-builds keep working.
func readPlatformAttrs(e *Entry, info os.FileInfo) error { return nil }

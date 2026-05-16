//go:build !linux

package decoy

// newFileWatcher returns the polling watcher off Linux.
func newFileWatcher(files []HoneyFile, hit HitFn) (fileWatcher, error) {
	return newPollWatcher(files, hit), nil
}

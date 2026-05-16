//go:build linux

package decoy

// newFileWatcher prefers the fanotify-backed watcher and falls back
// to atime polling when fanotify init fails (no CAP_SYS_ADMIN, FUSE
// FS, or kernel without fanotify support).
func newFileWatcher(files []HoneyFile, hit HitFn) (fileWatcher, error) {
	if w, err := newFanotify(files, hit); err == nil {
		return w, nil
	}
	return newPollWatcher(files, hit), nil
}

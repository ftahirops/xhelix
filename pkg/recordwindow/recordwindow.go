// Package recordwindow implements the operator-controlled "learning window"
// switch. While the window is open, the workflow-chain stamp may mark events
// learnable so the recorder captures behavioral shapes; while closed, nothing
// is learnable and the recorder stores nothing.
//
// The switch is file-backed (presence of the control file = open), mirroring
// pkg/enforce.PanicSwitch. This lets an operator — or xhelixctl, or the
// LocalAPI — toggle learning on a running daemon without a restart or config
// edit, and the state survives across restarts. The in-process state is cached
// in an atomic so the pipeline's per-event Open() check is lock-free; Refresh
// re-reads the file for out-of-band edits.
package recordwindow

import (
	"os"
	"path/filepath"
	"sync/atomic"
)

// DefaultPath is the conventional control-file location under the runtime dir.
const DefaultPath = "/run/xhelix/record_window"

// Flag is a file-backed, runtime-toggleable learning-window switch. The zero
// value is not usable; construct with New.
type Flag struct {
	open atomic.Bool
	path string
}

// New builds a Flag bound to controlPath and seeds the cached state from
// whether the control file currently exists (state persists across restarts).
// An empty path selects DefaultPath.
func New(controlPath string) *Flag {
	if controlPath == "" {
		controlPath = DefaultPath
	}
	f := &Flag{path: controlPath}
	f.open.Store(fileExists(controlPath))
	return f
}

// Path returns the control-file path.
func (f *Flag) Path() string {
	if f == nil {
		return ""
	}
	return f.path
}

// Open reports whether the learning window is currently open. Nil-safe and
// lock-free — safe to call on the per-event hot path.
func (f *Flag) Open() bool {
	return f != nil && f.open.Load()
}

// Refresh re-reads the control file and updates the cached state, returning the
// new value. Call periodically so out-of-band toggles (a different process
// creating/removing the file) propagate.
func (f *Flag) Refresh() bool {
	if f == nil {
		return false
	}
	v := fileExists(f.path)
	f.open.Store(v)
	return v
}

// SetOpen opens or closes the window: it creates or removes the control file
// and updates the cached state. Creating the file also creates its parent
// directory if missing. Returns an error only on a filesystem failure.
func (f *Flag) SetOpen(open bool) error {
	if f == nil {
		return nil
	}
	if open {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(f.path, []byte("open\n"), 0o640); err != nil {
			return err
		}
	} else {
		if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	f.open.Store(open)
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

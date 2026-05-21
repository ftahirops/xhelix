//go:build linux

package fim

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xhelix/xhelix/pkg/model"
)

// inotifyWatcher provides real-time file-change detection on top of
// the periodic FIM baseline-hasher. Inotify gives us sub-second
// latency on file create/modify/delete/move events — closing the
// 5-minute hole where the periodic verifier was the only signal.
//
// Why both? The periodic verifier catches:
//   - changes that happened while xhelix was down
//   - changes via bind-mount / direct block-device write that bypass VFS
//   - hash drift caused by partial / incomplete previous events
// Inotify catches:
//   - the moment a file is touched
//   - the writer's pid/uid (when correlated against /proc/<pid>/status)
//   - operations on files we haven't yet hashed
//
// They are complementary, not redundant. Inotify is the "loud
// alarm"; periodic verify is the "did anything slip past us?" sweep.
//
// Linux-only. Build-tagged to keep the dev-build green on macOS.
type inotifyWatcher struct {
	fd      int
	out     chan<- model.Event
	host    string
	cancel  context.CancelFunc

	mu        sync.Mutex
	watches   map[int]string // wd → path
	// dirWatchedFor tracks file paths we asked to watch inside a
	// dir-watch (because the file didn't exist yet or inotify
	// rejected the leaf). Keyed by dir, value is set of basenames
	// we care about; "*" means "everything in dir".
	dirWatchedFor map[string]map[string]bool
}

// newInotify opens an inotify fd and arms watches for every
// resolved path in patterns. Glob patterns are expanded via
// filepath.Glob; non-existing paths register a dir-watch on the
// parent so we still see the create event.
//
// Returns the watcher and a slice of paths it actually watches
// (for logging), or an error if inotify_init fails (in which case
// the caller falls back to periodic-only mode).
func newInotify(patterns []string, out chan<- model.Event, host string) (*inotifyWatcher, []string, error) {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, nil, fmt.Errorf("inotify_init: %w", err)
	}
	w := &inotifyWatcher{
		fd: fd, out: out, host: host,
		watches:       map[int]string{},
		dirWatchedFor: map[string]map[string]bool{},
	}
	var got []string

	// Mask: we want create, write-close, attrib change, delete,
	// move. IN_CLOSE_WRITE is the right "file finished being
	// modified" signal — better than IN_MODIFY which fires on
	// every write() call.
	mask := uint32(unix.IN_CREATE | unix.IN_CLOSE_WRITE |
		unix.IN_DELETE | unix.IN_MOVED_TO | unix.IN_MOVED_FROM |
		unix.IN_ATTRIB | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF)
	dirMask := mask | unix.IN_ONLYDIR

	seen := map[string]bool{}
	add := func(target string, dir bool) {
		if target == "" || seen[target] {
			return
		}
		seen[target] = true
		m := mask
		if dir {
			m = dirMask
		}
		wd, err := unix.InotifyAddWatch(fd, target, m)
		if err != nil {
			// Permission, ENOENT, ENOTDIR — softfail; the periodic
			// verifier still covers this.
			return
		}
		w.mu.Lock()
		w.watches[wd] = target
		w.mu.Unlock()
		got = append(got, target)
	}

	for _, p := range patterns {
		// Expand globs.
		matches, err := filepath.Glob(p)
		if err != nil || len(matches) == 0 {
			// Even if no current match, watch the parent dir so
			// a future create fires (common case: wp-config.php
			// in a vhost that's being scaffolded).
			parent := filepath.Dir(p)
			if base := filepath.Base(p); !strings.ContainsAny(base, "*?[") {
				// Plain (non-glob) leaf — watch parent dir for create.
				if _, err := os.Stat(parent); err == nil {
					add(parent, true)
					w.mu.Lock()
					if w.dirWatchedFor[parent] == nil {
						w.dirWatchedFor[parent] = map[string]bool{}
					}
					w.dirWatchedFor[parent][base] = true
					w.mu.Unlock()
				}
			}
			continue
		}
		for _, m := range matches {
			st, err := os.Stat(m)
			if err != nil {
				continue
			}
			if st.IsDir() {
				add(m, true)
				w.mu.Lock()
				if w.dirWatchedFor[m] == nil {
					w.dirWatchedFor[m] = map[string]bool{}
				}
				w.dirWatchedFor[m]["*"] = true
				w.mu.Unlock()
			} else {
				add(m, false)
			}
		}
	}
	return w, got, nil
}

// Run reads events until ctx is done. Decodes inotify_event records
// (struct inotify_event { __s32 wd; __u32 mask; __u32 cookie; __u32 len; char name[]; })
// and emits model.Event for each interesting one.
func (w *inotifyWatcher) Run(ctx context.Context) {
	defer unix.Close(w.fd)

	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				// Non-blocking: sleep briefly and retry.
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}
		w.decode(buf[:n])
	}
}

// inotifyEvent header is 16 bytes.
const inotifyHeaderLen = 16

func (w *inotifyWatcher) decode(buf []byte) {
	// inotify_event { int32 wd; uint32 mask; uint32 cookie; uint32 len; char name[len]; }
	for off := 0; off+inotifyHeaderLen <= len(buf); {
		wd := int32(binary.LittleEndian.Uint32(buf[off : off+4]))
		mask := binary.LittleEndian.Uint32(buf[off+4 : off+8])
		nameLen := int(binary.LittleEndian.Uint32(buf[off+12 : off+16]))
		nameStart := off + inotifyHeaderLen
		nameEnd := nameStart + nameLen
		if nameEnd > len(buf) {
			return
		}
		name := ""
		if nameLen > 0 {
			name = strings.TrimRight(string(buf[nameStart:nameEnd]), "\x00")
		}
		w.handle(int(wd), mask, name)
		off = nameEnd
	}
}

func (w *inotifyWatcher) handle(wd int, mask uint32, name string) {
	w.mu.Lock()
	watched := w.watches[wd]
	dirSel := w.dirWatchedFor[watched]
	w.mu.Unlock()
	if watched == "" {
		return
	}

	var fullPath string
	if name != "" {
		fullPath = filepath.Join(watched, name)
		// If we registered the parent dir only because of a
		// specific leaf (e.g. /var/spool/cron/crontabs for root),
		// filter unrelated names.
		if dirSel != nil && !dirSel["*"] && !dirSel[name] {
			return
		}
	} else {
		fullPath = watched
	}

	reason := decodeMask(mask)
	if reason == "" {
		return
	}

	ev := model.NewEvent("fim", model.SeverityHigh)
	ev.Time = time.Now().UTC()
	ev.Host = w.host
	ev.Tags["path"] = fullPath
	ev.Tags["reason"] = reason
	ev.Tags["realtime"] = "true"
	// Boolean tags consumed by rules (write/create/delete) — these
	// were the missing piece that made the existing rules dormant.
	switch {
	case mask&unix.IN_CREATE != 0 || mask&unix.IN_MOVED_TO != 0:
		ev.Tags["create"] = "true"
	case mask&unix.IN_CLOSE_WRITE != 0:
		ev.Tags["write"] = "true"
	case mask&unix.IN_DELETE != 0 || mask&unix.IN_MOVED_FROM != 0:
		ev.Tags["delete"] = "true"
	case mask&unix.IN_ATTRIB != 0:
		ev.Tags["attrib"] = "true"
	}
	// Stamp the file owner if we can stat it (will fail for deletes).
	if st, err := os.Stat(fullPath); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			ev.Tags["file_uid"] = fmt.Sprintf("%d", sys.Uid)
			ev.Tags["file_gid"] = fmt.Sprintf("%d", sys.Gid)
			ev.Tags["file_mode"] = fmt.Sprintf("%o", st.Mode().Perm())
		}
	}

	select {
	case w.out <- ev:
	default:
		// Drop on full channel rather than blocking the inotify
		// reader — losing one fim event is preferable to falling
		// behind on the kernel queue (which would overflow into
		// IN_Q_OVERFLOW and lose far more).
	}
}

// decodeMask returns the short human-readable reason for an inotify
// event mask, or "" if the mask isn't interesting (overflow, ignored).
func decodeMask(m uint32) string {
	var bits []string
	if m&unix.IN_CREATE != 0 {
		bits = append(bits, "create")
	}
	if m&unix.IN_CLOSE_WRITE != 0 {
		bits = append(bits, "write")
	}
	if m&unix.IN_DELETE != 0 {
		bits = append(bits, "delete")
	}
	if m&unix.IN_MOVED_TO != 0 {
		bits = append(bits, "moved_to")
	}
	if m&unix.IN_MOVED_FROM != 0 {
		bits = append(bits, "moved_from")
	}
	if m&unix.IN_ATTRIB != 0 {
		bits = append(bits, "attrib")
	}
	if m&unix.IN_DELETE_SELF != 0 {
		bits = append(bits, "delete_self")
	}
	if m&unix.IN_MOVE_SELF != 0 {
		bits = append(bits, "move_self")
	}
	if len(bits) == 0 {
		return ""
	}
	return strings.Join(bits, "|")
}


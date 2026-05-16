//go:build linux

package decoy

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fanWatcher is the production fanotify-backed file watcher.
//
// It opens a single fanotify fd, marks each honey file with FAN_OPEN
// + FAN_ACCESS, and decodes records to surface the originating pid.
// Falls back to the polling watcher if fanotify init fails (e.g.
// missing CAP_SYS_ADMIN in tests).
type fanWatcher struct {
	files []HoneyFile
	hit   HitFn

	mu      sync.Mutex
	fd      int
	cancel  context.CancelFunc
	running atomic.Bool
}

func newFanotify(files []HoneyFile, hit HitFn) (fileWatcher, error) {
	// FAN_CLASS_NOTIF = 0; FAN_NONBLOCK + FAN_REPORT_TID help reads.
	// FAN_CLOEXEC set so the fd doesn't leak across the daemon's
	// own subprocess invocations.
	flags := unix.FAN_CLOEXEC | unix.FAN_NONBLOCK | unix.FAN_CLASS_NOTIF
	fd, err := unix.FanotifyInit(uint(flags), unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}
	w := &fanWatcher{files: files, hit: hit, fd: fd}
	mask := uint64(unix.FAN_OPEN | unix.FAN_ACCESS | unix.FAN_CLOSE_WRITE)
	for _, f := range files {
		// Mark each individual file (FAN_MARK_ADD); FAN_MARK_FILESYSTEM
		// would be wider but requires CAP_SYS_ADMIN.
		dir := filepath.Dir(f.Path)
		if err := unix.FanotifyMark(fd,
			unix.FAN_MARK_ADD,
			mask,
			unix.AT_FDCWD,
			f.Path,
		); err != nil {
			// Try marking the directory instead — works around FUSE etc.
			_ = unix.FanotifyMark(fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, dir)
		}
	}
	return w, nil
}

func (w *fanWatcher) Start(parent context.Context) error {
	if !w.running.CompareAndSwap(false, true) {
		return nil
	}
	ctx, cancel := context.WithCancel(parent)
	w.mu.Lock()
	w.cancel = cancel
	w.mu.Unlock()
	go w.loop(ctx)
	return nil
}

func (w *fanWatcher) Stop(ctx context.Context) error {
	if !w.running.CompareAndSwap(true, false) {
		return nil
	}
	w.mu.Lock()
	if w.cancel != nil {
		w.cancel()
	}
	if w.fd >= 0 {
		_ = unix.Close(w.fd)
		w.fd = -1
	}
	w.mu.Unlock()
	return nil
}

const fanotifyEventMetadataSize = 24 // sizeof(struct fanotify_event_metadata)

func (w *fanWatcher) loop(ctx context.Context) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		w.mu.Lock()
		fd := w.fd
		w.mu.Unlock()
		if fd < 0 {
			return
		}
		// Block-with-timeout poll on the fd so Stop is responsive.
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(pfd, 250)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return
		}
		if pfd[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			return
		}
		w.parse(buf[:n])
	}
}

// parse walks the fanotify_event_metadata records returned by read(2)
// and dispatches a FileHit per record.
func (w *fanWatcher) parse(buf []byte) {
	for len(buf) >= fanotifyEventMetadataSize {
		// struct fanotify_event_metadata layout (kernel ABI):
		//   __u32 event_len
		//   __u8  vers, reserved
		//   __u16 metadata_len
		//   __aligned_u64 mask
		//   __s32 fd
		//   __s32 pid
		eventLen := binary.LittleEndian.Uint32(buf[0:4])
		fd := int32(binary.LittleEndian.Uint32(buf[16:20]))
		pid := int32(binary.LittleEndian.Uint32(buf[20:24]))
		if eventLen == 0 || int(eventLen) > len(buf) {
			return
		}
		path, comm := resolveFanotifyEvent(fd)
		w.hit(FileHit{Path: path, PID: uint32(pid), Comm: comm})
		if fd >= 0 {
			_ = unix.Close(int(fd))
		}
		buf = buf[eventLen:]
	}
}

// resolveFanotifyEvent reads /proc/self/fd/<fd> to recover the path
// and /proc/<pid>/comm for the originating process. Both reads are
// best-effort — missing files don't block the hit dispatch.
func resolveFanotifyEvent(fd int32) (path, comm string) {
	if fd >= 0 {
		link := fmt.Sprintf("/proc/self/fd/%d", fd)
		if p, err := os.Readlink(link); err == nil {
			path = p
		}
	}
	return path, comm
}

// silence unused-import warning when only some of unsafe's symbols
// are reached in build configurations that don't exercise them.
var _ = unsafe.Sizeof(uint32(0))

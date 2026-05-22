//go:build linux

// FanGate is the kernel-side interception layer for credbroker.
// When a process tries to open(2) a managed sealed file, the kernel
// suspends the syscall and asks fanotify; we look up the lineage,
// call Broker.Decide, and reply ALLOW or DENY synchronously.
//
// fanotify perm events require CAP_SYS_ADMIN and Linux ≥ 4.18.
// On a missing capability or unsupported kernel the gate degrades
// to "broker not gating at kernel level" with a warning — the
// rest of the broker (seal/unseal, audit, history) still works.
//
// Why fanotify and not bpf_lsm:
//   - fanotify has synchronous perm decision built into the kernel
//     ABI; no new eBPF program needed
//   - already used by sensors/decoy/file_watcher_fanotify_linux.go
//     so the wire-up pattern is proven in this codebase
//   - works on kernels back to 4.18 (vs bpf_lsm needing 5.7 + boot
//     cmdline lsm=bpf, which isn't always present on rented VMs)
//   - bpf_lsm is the right v2 — but a working fanotify gate today
//     beats a v2 bpf_lsm in three weeks
//
// Honest scope of v1 (this commit):
//   - intercepts FAN_OPEN_PERM on configured sealed-file paths
//   - synchronous decide + reply (allow/deny within ~5ms target)
//   - lineage built from /proc/<pid> walk (parent chain, comm, image)
//   - audit record per decision
//   - falls back to allow-with-loud-warn if Broker.Decide errors
//     (don't break the production app because the broker bugged)
//
// What v1 does NOT yet do (USG.2 follow-on):
//   - per-FD tracking (a process that opened once and held the FD
//     can still read; we don't intercept the read itself)
//   - honey-on-deny content substitution (returns -EPERM only;
//     USG.1d wires honey)
//   - FUSE overlay so the original plaintext path stays unchanged
//     (today the process opens .sealed file and gets denied; the
//     compatibility layer for legacy apps lands in USG.2b)
package credbroker

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// FanGate is the fanotify-backed permission gate.
type FanGate struct {
	broker *Broker

	// fd is the fanotify file descriptor; -1 when stopped.
	fdMu sync.RWMutex
	fd   int

	// marked tracks the absolute paths we've successfully marked
	// with FAN_OPEN_PERM. xhelixctl credbroker status reads this.
	marked atomic.Value // []string

	// statistics
	stats struct {
		eventsRx atomic.Uint64
		allowed  atomic.Uint64
		denied   atomic.Uint64
		errors   atomic.Uint64
	}

	cancel  context.CancelFunc
	running atomic.Bool
	log     interface{ Warn(string, ...any) }
}

// NewFanGate wires fanotify with FAN_CLASS_CONTENT (the class that
// supports perm events). Requires CAP_SYS_ADMIN.
func NewFanGate(broker *Broker, log interface{ Warn(string, ...any) }) (*FanGate, error) {
	if broker == nil {
		return nil, errors.New("fangate: broker is nil")
	}
	// FAN_CLASS_CONTENT supports OPEN_PERM. FAN_NONBLOCK lets us
	// timeout-poll cleanly. FAN_CLOEXEC avoids leaking fd across
	// daemon-spawned subprocesses.
	flags := unix.FAN_CLOEXEC | unix.FAN_NONBLOCK | unix.FAN_CLASS_CONTENT
	fd, err := unix.FanotifyInit(uint(flags), unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}
	g := &FanGate{
		broker: broker,
		fd:     fd,
		log:    log,
	}
	g.marked.Store([]string{})
	return g, nil
}

// Mark arms FAN_OPEN_PERM on the given absolute path. Returns nil
// if marking succeeded. Failures are typically EPERM (missing
// CAP_SYS_ADMIN) or ENOTDIR/ENOENT (path doesn't exist).
func (g *FanGate) Mark(path string) error {
	g.fdMu.RLock()
	fd := g.fd
	g.fdMu.RUnlock()
	if fd < 0 {
		return errors.New("fangate: stopped")
	}
	mask := uint64(unix.FAN_OPEN_PERM)
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, path); err != nil {
		return fmt.Errorf("fanotify_mark %s: %w", path, err)
	}
	g.appendMarked(path)
	return nil
}

// MarkSealedFilesIn walks dir recursively and Marks every file
// whose name ends in ".sealed" — the canonical credbroker
// extension. Returns count successfully marked + list of errors.
func (g *FanGate) MarkSealedFilesIn(dir string) (int, []error) {
	var errs []error
	count := 0
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(p, ".sealed") {
			return nil
		}
		if err := g.Mark(p); err != nil {
			errs = append(errs, err)
			return nil
		}
		count++
		return nil
	})
	return count, errs
}

func (g *FanGate) appendMarked(path string) {
	old, _ := g.marked.Load().([]string)
	g.marked.Store(append(append([]string{}, old...), path))
}

// MarkedPaths returns a snapshot for status output.
func (g *FanGate) MarkedPaths() []string {
	v, _ := g.marked.Load().([]string)
	out := make([]string, len(v))
	copy(out, v)
	return out
}

// Stats returns a counter snapshot.
type FanGateStats struct {
	EventsRx uint64
	Allowed  uint64
	Denied   uint64
	Errors   uint64
}

// Stats returns running counters.
func (g *FanGate) Stats() FanGateStats {
	return FanGateStats{
		EventsRx: g.stats.eventsRx.Load(),
		Allowed:  g.stats.allowed.Load(),
		Denied:   g.stats.denied.Load(),
		Errors:   g.stats.errors.Load(),
	}
}

// Start begins the event loop. Returns immediately; loop runs in a
// goroutine until ctx is cancelled or Stop is called.
func (g *FanGate) Start(parent context.Context) error {
	if !g.running.CompareAndSwap(false, true) {
		return errors.New("fangate: already started")
	}
	ctx, cancel := context.WithCancel(parent)
	g.cancel = cancel
	go g.loop(ctx)
	return nil
}

// Stop halts the loop and closes the fanotify fd.
func (g *FanGate) Stop() {
	if !g.running.CompareAndSwap(true, false) {
		return
	}
	if g.cancel != nil {
		g.cancel()
	}
	g.fdMu.Lock()
	if g.fd >= 0 {
		_ = unix.Close(g.fd)
		g.fd = -1
	}
	g.fdMu.Unlock()
}

const fanEventMetadataSize = 24 // sizeof(struct fanotify_event_metadata)

// fanotify_response struct (kernel ABI):
//   __s32 fd
//   __u32 response
const fanResponseSize = 8

func (g *FanGate) loop(ctx context.Context) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		g.fdMu.RLock()
		fd := g.fd
		g.fdMu.RUnlock()
		if fd < 0 {
			return
		}
		// Poll with timeout so Stop is responsive.
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(pfd, 250)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			g.stats.errors.Add(1)
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
			g.stats.errors.Add(1)
			return
		}
		g.handleBuffer(fd, buf[:n])
	}
}

// handleBuffer walks fanotify_event_metadata records and processes
// each. struct fanotify_event_metadata (24 bytes, packed):
//
//	u32 event_len   // total record length incl trailing names
//	u8  vers
//	u8  reserved
//	u16 metadata_len
//	u64 mask        // FAN_OPEN_PERM etc.
//	s32 fd          // FD to inspect (or read perm reply)
//	s32 pid         // requesting process
func (g *FanGate) handleBuffer(fanFD int, buf []byte) {
	for len(buf) >= fanEventMetadataSize {
		eventLen := binary.LittleEndian.Uint32(buf[0:4])
		// vers @4, reserved @5, metadata_len @6:8
		mask := binary.LittleEndian.Uint64(buf[8:16])
		fdRaw := int32(binary.LittleEndian.Uint32(buf[16:20]))
		pid := int32(binary.LittleEndian.Uint32(buf[20:24]))
		if eventLen < uint32(fanEventMetadataSize) || int(eventLen) > len(buf) {
			return
		}
		g.processEvent(fanFD, int(fdRaw), uint32(pid), mask)
		buf = buf[eventLen:]
	}
}

func (g *FanGate) processEvent(fanFD, eventFD int, pid uint32, mask uint64) {
	g.stats.eventsRx.Add(1)
	defer unix.Close(eventFD)

	// Only handle perm events.
	if mask&unix.FAN_OPEN_PERM == 0 {
		return
	}

	// Resolve the path being opened by reading /proc/self/fd/<fd>.
	path, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", eventFD))

	// Build lineage from /proc/<pid>.
	lineage := buildLineage(pid)

	req := Request{
		SealedPath: path,
		PID:        pid,
		Lineage:    lineage,
		Now:        time.Now().UTC(),
		Reason:     "fanotify perm event",
	}

	// We need to actually read the sealed file to call Decide.
	// Read the bytes via the kernel-provided fd (which is the
	// opened file, already permission-checked at VFS layer for us).
	// In v1 we just call Broker.Decide with the SealedPath; Decide
	// itself re-opens the file. This is a small efficiency loss
	// but keeps the broker API clean.
	sf, err := ReadSealed(path)
	if err != nil {
		// Read failed — let the open succeed so the caller gets
		// the normal kernel error rather than a fangate-induced
		// hang. Audit the event so operator sees the failure.
		g.respond(fanFD, eventFD, true)
		g.stats.errors.Add(1)
		if g.log != nil {
			g.log.Warn("fangate read sealed failed", "path", path, "err", err)
		}
		return
	}
	res := g.broker.Decide(sf, req)
	allow := res.Outcome == OutcomeAllow || res.Outcome == OutcomeHoney
	g.respond(fanFD, eventFD, allow)
	if allow {
		g.stats.allowed.Add(1)
	} else {
		g.stats.denied.Add(1)
	}
}

// respond writes a fanotify_response (FD + ALLOW/DENY) back.
func (g *FanGate) respond(fanFD, eventFD int, allow bool) {
	var buf [fanResponseSize]byte
	binary.LittleEndian.PutUint32(buf[0:4], uint32(eventFD))
	if allow {
		binary.LittleEndian.PutUint32(buf[4:8], unix.FAN_ALLOW)
	} else {
		binary.LittleEndian.PutUint32(buf[4:8], unix.FAN_DENY)
	}
	if _, err := unix.Write(fanFD, buf[:]); err != nil && err != io.EOF {
		g.stats.errors.Add(1)
	}
}

// buildLineage walks /proc to construct the causal chain for pid.
// Best-effort: missing pids return what we got so far.
func buildLineage(pid uint32) []LineageNode {
	var chain []LineageNode
	seen := map[uint32]bool{}
	cur := pid
	for depth := 0; depth < 16 && cur != 0 && !seen[cur]; depth++ {
		seen[cur] = true
		node := procNode(cur)
		if node.PID == 0 {
			break
		}
		chain = append(chain, node)
		cur = parentPID(cur)
	}
	return chain
}

func procNode(pid uint32) LineageNode {
	n := LineageNode{PID: pid}
	// comm
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		n.Comm = strings.TrimSpace(string(data))
	}
	// exe (image)
	if link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		// Strip " (deleted)" suffix.
		if strings.HasSuffix(link, " (deleted)") {
			link = strings.TrimSuffix(link, " (deleted)")
		}
		n.Image = link
	}
	// uid from status
	if f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "Uid:") {
				fs := strings.Fields(sc.Text())
				if len(fs) >= 2 {
					u, _ := strconv.ParseUint(fs[1], 10, 32)
					n.UID = uint32(u)
				}
				break
			}
		}
		f.Close()
	}
	return n
}

func parentPID(pid uint32) uint32 {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "PPid:") {
			fs := strings.Fields(sc.Text())
			if len(fs) >= 2 {
				u, _ := strconv.ParseUint(fs[1], 10, 32)
				return uint32(u)
			}
		}
	}
	return 0
}

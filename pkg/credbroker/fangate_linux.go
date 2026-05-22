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

// markMode is how the gate treats opens of a marked path.
type markMode uint8

const (
	modeSealed markMode = iota // .sealed: broker.Decide → ALLOW or DENY
	modeHoney                  // .honey: always ALLOW, emit "honey touched" alert
)

// FanGate is the fanotify-backed permission gate.
type FanGate struct {
	broker *Broker
	honey  *HoneyFactory // for honey-touched alert metadata; may be nil
	emit   AlertEmitter  // optional alert sink; nil → no alerts

	// fd is the fanotify file descriptor; -1 when stopped.
	fdMu sync.RWMutex
	fd   int

	// pathMode records how each marked path is treated. Updated under
	// marked's lock; read under fast path on every event.
	pathModeMu sync.RWMutex
	pathMode   map[string]markMode

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
		broker:   broker,
		fd:       fd,
		log:      log,
		pathMode: map[string]markMode{},
	}
	g.marked.Store([]string{})
	return g, nil
}

// WithHoney attaches a HoneyFactory so honey-touched events carry
// marker metadata in their alerts.
func (g *FanGate) WithHoney(h *HoneyFactory) *FanGate { g.honey = h; return g }

// WithAlertEmitter attaches a sink for decision alerts. May be nil.
func (g *FanGate) WithAlertEmitter(e AlertEmitter) *FanGate { g.emit = e; return g }

// Mark arms FAN_OPEN_PERM on the given absolute path as a sealed file
// (broker.Decide gates each open).
func (g *FanGate) Mark(path string) error { return g.markPath(path, modeSealed) }

// MarkHoney arms FAN_OPEN_PERM on path as a honey decoy (every open
// triggers an alert, but the open is allowed — attacker exfiltrates
// the marked honey content and is detected later via the marker).
func (g *FanGate) MarkHoney(path string) error { return g.markPath(path, modeHoney) }

func (g *FanGate) markPath(path string, mode markMode) error {
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
	g.pathModeMu.Lock()
	g.pathMode[path] = mode
	g.pathModeMu.Unlock()
	g.appendMarked(path)
	return nil
}

// MarkHoneyFilesIn walks dir recursively and marks every *.honey file.
func (g *FanGate) MarkHoneyFilesIn(dir string) (int, []error) {
	return g.markFilesWithSuffix(dir, ".honey", modeHoney)
}

// MarkSealedFilesIn walks dir recursively and Marks every *.sealed file.
func (g *FanGate) MarkSealedFilesIn(dir string) (int, []error) {
	return g.markFilesWithSuffix(dir, ".sealed", modeSealed)
}

func (g *FanGate) markFilesWithSuffix(dir, suffix string, mode markMode) (int, []error) {
	var errs []error
	count := 0
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(p, suffix) {
			return nil
		}
		if err := g.markPath(p, mode); err != nil {
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

	if mask&unix.FAN_OPEN_PERM == 0 {
		return
	}

	path, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", eventFD))
	lineage := buildLineage(pid)
	req := Request{
		SealedPath: path,
		PID:        pid,
		Lineage:    lineage,
		Now:        time.Now().UTC(),
		Reason:     "fanotify perm event",
	}

	g.pathModeMu.RLock()
	mode := g.pathMode[path]
	g.pathModeMu.RUnlock()

	switch mode {
	case modeHoney:
		// Decoy file. ALLOW the open (attacker reads honey content
		// and walks off) but emit a HIGH-CONFIDENCE alert: a
		// honey-only file has no legitimate reader by construction.
		g.respond(fanFD, eventFD, true)
		g.stats.allowed.Add(1)
		g.emitAlert(AlertHoneyTouched, path, req, "honey decoy opened (no legitimate reader by construction)")
	default: // modeSealed
		// Read content directly from the kernel-provided event fd.
		// CRITICAL: we MUST NOT re-open `path` here. fanotify
		// suppresses self-generated events only on the listener's
		// own OS thread; Go goroutines migrate across threads, so
		// an os.ReadFile on a non-listener thread re-enters fanotify
		// and deadlocks (listener thread waits for itself to respond).
		sf, err := readSealedFromFD(eventFD)
		if err != nil {
			// Read failed — let the open succeed so the caller gets
			// the normal kernel error, but loud-warn.
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
			g.emitAlert(AlertSealedDenied, path, req, res.Reason)
		}
	}
}

// emitAlert sends a credbroker alert to the registered emitter, if any.
// No-op when emit is nil — keeps fangate usable in tests without
// requiring an alert bus.
func (g *FanGate) emitAlert(kind AlertKind, sealedPath string, req Request, reason string) {
	if g.emit == nil {
		return
	}
	a := BrokerAlert{
		Kind:       kind,
		SealedPath: sealedPath,
		PID:        req.PID,
		Lineage:    req.Lineage,
		Reason:     reason,
		At:         req.Now,
	}
	g.emit.Emit(a)
}

// readSealedFromFD reads bytes from the kernel-provided event fd and
// parses them as a sealed file. Avoids re-opening the path (which
// would deadlock — see modeSealed comment in processEvent).
func readSealedFromFD(fd int) (*SealedFile, error) {
	// Sealed files are tiny (header + base64 ciphertext); 16 KiB is
	// generous.
	var buf [16 * 1024]byte
	total := 0
	for {
		n, err := unix.Pread(fd, buf[total:], int64(total))
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return nil, err
		}
		if n == 0 {
			break
		}
		total += n
		if total >= len(buf) {
			break
		}
	}
	return ParseSealed(buf[:total])
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

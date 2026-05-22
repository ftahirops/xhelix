//go:build linux

// Package execguard denies exec of a deny-listed binary before the
// kernel hands control to it.
//
// Mechanism: fanotify in FAN_CLASS_CONTENT mode with FAN_OPEN_EXEC_PERM.
// On every execve(), the kernel blocks the calling thread and hands
// us a permission event on a file descriptor pointing at the binary.
// We resolve the path via /proc/self/fd/<fd>, evaluate it against the
// deny rules, and write back FAN_ALLOW or FAN_DENY. FAN_DENY makes
// the execve fail with EPERM — the binary never runs.
//
// This is the closest thing to "kernel-level prevention" we can get
// from userspace without writing an eBPF LSM program. Latency is
// sub-millisecond for cached paths.
//
// Constraints:
//   - Requires CAP_SYS_ADMIN (root).
//   - Requires CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y (set on every
//     mainstream distro since 2020).
//   - Marks the entire mount with FAN_MARK_MOUNT, so deny rules apply
//     to every exec on that mount.
//   - Must write a response within the kernel's timeout (default 30s)
//     or the kernel auto-allows. We write within ~milliseconds.
package execguard

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// Decision is what the guard returns for a given exec event.
type Decision int

const (
	Allow Decision = iota
	Deny
)

// Rule matches an exec event by path. The first matching rule wins.
type Rule struct {
	// Match is the path-matching predicate. Use HasPrefix, HasSuffix
	// or full equality. Compiled regex is supported via PathRegex.
	PathEquals     string
	PathHasPrefix  string
	PathHasSuffix  string
	// PathContains substring match (cheap; used for /tmp/, /dev/shm/, etc.)
	PathContains   string
	// Decision applied if the rule matches.
	Decision Decision
	// Reason logged when this rule fires.
	Reason string
}

// EventCallback is invoked for every exec event after the decision is
// written. Useful for logging without blocking the kernel.
type EventCallback func(path string, pid int, decision Decision, reason string)

// IntegrityMode is how the guard treats an integrity-baseline mismatch.
type IntegrityMode int

const (
	// IntegrityOff disables the baseline check entirely. Default —
	// preserves pre-B3 behaviour.
	IntegrityOff IntegrityMode = iota
	// IntegrityDetect logs mismatches but still allows the execve.
	// Used during baseline calibration so the operator can see what
	// would have been denied without breaking production.
	IntegrityDetect
	// IntegrityEnforce denies execve on baseline mismatch unless the
	// writer was authenticated as a package-manager upgrade.
	IntegrityEnforce
)

// IntegrityVerifier is the contract pkg/integrity satisfies. Kept as
// an interface so execguard doesn't import pkg/integrity directly
// (cleaner, easier to stub in tests).
type IntegrityVerifier interface {
	// Verify is called after the rule engine has decided Allow.
	// Inputs: the absolute path being execved + the executing PID.
	// Returns (allow, reason). When allow is false, the guard treats
	// the result per IntegrityMode (detect = log; enforce = deny).
	Verify(path string, pid uint32) (allow bool, reason string)
}

// Guard is the public API.
type Guard struct {
	mu      sync.RWMutex
	rules   []Rule
	cb      EventCallback

	verifier IntegrityVerifier
	intMode  IntegrityMode

	fd      int
	cancel  context.CancelFunc
	running atomic.Bool

	stats struct {
		seen          atomic.Uint64
		denied        atomic.Uint64
		errors        atomic.Uint64
		integrityHits atomic.Uint64
	}
}

// New returns an unstarted guard. Call SetRules then Start.
func New(cb EventCallback) *Guard {
	return &Guard{cb: cb, fd: -1}
}

// SetIntegrity wires a baseline verifier into the guard. Pass mode =
// IntegrityOff (the default) to disable. Setting verifier=nil also
// disables regardless of mode.
func (g *Guard) SetIntegrity(v IntegrityVerifier, mode IntegrityMode) {
	g.mu.Lock()
	g.verifier = v
	g.intMode = mode
	g.mu.Unlock()
}

// SetRules atomically replaces the rule set.
func (g *Guard) SetRules(rules []Rule) {
	g.mu.Lock()
	g.rules = append([]Rule(nil), rules...)
	g.mu.Unlock()
}

// Start initialises fanotify and begins serving permission events.
// mountPoints is the list of paths to mark; "/" covers the whole
// filesystem.
func (g *Guard) Start(parent context.Context, mountPoints []string) error {
	if !g.running.CompareAndSwap(false, true) {
		return errors.New("execguard: already running")
	}
	if len(mountPoints) == 0 {
		mountPoints = []string{"/"}
	}

	// FAN_CLASS_CONTENT lets us answer permission events. FAN_NONBLOCK
	// keeps Read from hanging the loop on shutdown. CLOEXEC so the fd
	// doesn't survive into our own children.
	flags := unix.FAN_CLOEXEC | unix.FAN_NONBLOCK | unix.FAN_CLASS_CONTENT
	fd, err := unix.FanotifyInit(uint(flags), unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		g.running.Store(false)
		return fmt.Errorf("fanotify_init: %w (need CAP_SYS_ADMIN + CONFIG_FANOTIFY_ACCESS_PERMISSIONS)", err)
	}
	g.fd = fd

	mask := uint64(unix.FAN_OPEN_EXEC_PERM)
	for _, mp := range mountPoints {
		if err := unix.FanotifyMark(fd,
			unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT,
			mask,
			unix.AT_FDCWD,
			mp); err != nil {
			_ = unix.Close(fd)
			g.fd = -1
			g.running.Store(false)
			return fmt.Errorf("fanotify_mark %s: %w", mp, err)
		}
	}

	ctx, cancel := context.WithCancel(parent)
	g.cancel = cancel
	go g.loop(ctx)
	return nil
}

// Stop tears down the fanotify fd. Idempotent.
//
// Closing the fd is delegated to the loop goroutine (see loop()) so
// there's no cross-goroutine fd race: the loop reads/writes g.fd as
// the sole owner, and Stop just signals it via ctx.
func (g *Guard) Stop() error {
	if !g.running.CompareAndSwap(true, false) {
		return nil
	}
	if g.cancel != nil {
		g.cancel()
	}
	return nil
}

// Stats reports counters for the dashboard.
type Stats struct {
	Seen          uint64
	Denied        uint64
	Errors        uint64
	IntegrityHits uint64
}

func (g *Guard) Stats() Stats {
	return Stats{
		Seen:          g.stats.seen.Load(),
		Denied:        g.stats.denied.Load(),
		Errors:        g.stats.errors.Load(),
		IntegrityHits: g.stats.integrityHits.Load(),
	}
}

const (
	fanotifyEventMetadataSize = 24 // sizeof(struct fanotify_event_metadata) on amd64
	fanotifyResponseSize      = 8  // __s32 fd + __u32 response
)

func (g *Guard) loop(ctx context.Context) {
	// Loop owns the fd: it's the only goroutine that reads from it,
	// writes to it (via respond), and closes it. Stop() just signals
	// via ctx and we tear down here, eliminating the prior race
	// where Stop() closed the fd while respond() held it.
	defer func() {
		if g.fd >= 0 {
			_ = unix.Close(g.fd)
			g.fd = -1
		}
	}()
	buf := make([]byte, 8192)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		fd := g.fd
		if fd < 0 {
			return
		}
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
		g.handle(buf[:n])
	}
}

func (g *Guard) handle(buf []byte) {
	for len(buf) >= fanotifyEventMetadataSize {
		eventLen := binary.LittleEndian.Uint32(buf[0:4])
		// vers := buf[4]; reserved := buf[5]
		// metadataLen := binary.LittleEndian.Uint16(buf[6:8])
		mask := binary.LittleEndian.Uint64(buf[8:16])
		eventFD := int32(binary.LittleEndian.Uint32(buf[16:20]))
		pid := int32(binary.LittleEndian.Uint32(buf[20:24]))

		if eventLen == 0 || int(eventLen) > len(buf) {
			return
		}
		g.stats.seen.Add(1)

		// Resolve path via the magic /proc/self/fd/<fd> link.
		path := ""
		if eventFD >= 0 {
			if p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", eventFD)); err == nil {
				path = p
			}
		}

		decision, reason := g.evaluate(path)
		// B3 (integrity check) runs AFTER the path-based rules. Only
		// consulted when rules said Allow — explicit denies still
		// short-circuit. Allows can be overridden by integrity in
		// IntegrityEnforce mode.
		if decision == Allow {
			g.mu.RLock()
			v := g.verifier
			mode := g.intMode
			g.mu.RUnlock()
			if v != nil && mode != IntegrityOff && path != "" {
				ok, intReason := v.Verify(path, uint32(pid))
				if !ok {
					g.stats.integrityHits.Add(1)
					reason = intReason
					if mode == IntegrityEnforce {
						decision = Deny
					}
				}
			}
		}
		if mask&unix.FAN_OPEN_EXEC_PERM != 0 {
			g.respond(eventFD, decision)
		}
		if decision == Deny {
			g.stats.denied.Add(1)
		}
		if g.cb != nil {
			g.cb(path, int(pid), decision, reason)
		}
		if eventFD >= 0 {
			_ = unix.Close(int(eventFD))
		}
		buf = buf[eventLen:]
	}
}

func (g *Guard) evaluate(path string) (Decision, string) {
	if path == "" {
		// Path resolution failed (Readlink error, race with the
		// process exiting, or anonymous memfd that didn't surface
		// a /proc/self/fd/<n> link). An exec whose path we can't
		// determine is HIGHER suspicion, not lower — the prior
		// "Allow on empty" silently bypassed every rule, including
		// the /proc/self/fd/* memfd-deny rule. Default to Deny;
		// operators who need a softer policy can configure an
		// allow-by-default rule explicitly.
		return Deny, "path-unresolvable"
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, r := range g.rules {
		if r.PathEquals != "" && path == r.PathEquals {
			return r.Decision, r.Reason
		}
		if r.PathHasPrefix != "" && strings.HasPrefix(path, r.PathHasPrefix) {
			return r.Decision, r.Reason
		}
		if r.PathHasSuffix != "" && strings.HasSuffix(path, r.PathHasSuffix) {
			return r.Decision, r.Reason
		}
		if r.PathContains != "" && strings.Contains(path, r.PathContains) {
			return r.Decision, r.Reason
		}
	}
	return Allow, ""
}

func (g *Guard) respond(eventFD int32, decision Decision) {
	resp := make([]byte, fanotifyResponseSize)
	binary.LittleEndian.PutUint32(resp[0:4], uint32(eventFD))
	r := uint32(unix.FAN_ALLOW)
	if decision == Deny {
		r = unix.FAN_DENY
	}
	binary.LittleEndian.PutUint32(resp[4:8], r)
	if _, err := unix.Write(g.fd, resp); err != nil {
		g.stats.errors.Add(1)
	}
}

// DefaultRules returns a starting deny-list of high-signal exec
// patterns that are nearly always malicious in production.
//
// Operators tune this via config; this is the safe baseline.
func DefaultRules() []Rule {
	return []Rule{
		{PathHasPrefix: "/tmp/", Decision: Deny, Reason: "exec from /tmp"},
		{PathHasPrefix: "/var/tmp/", Decision: Deny, Reason: "exec from /var/tmp"},
		{PathHasPrefix: "/dev/shm/", Decision: Deny, Reason: "exec from /dev/shm"},
		{PathContains: "/.cache/", Decision: Deny, Reason: "exec from cache dir"},
		// Exec via /proc/self/fd/<n> is a classic memfd_create trick.
		{PathHasPrefix: "/proc/self/fd/", Decision: Deny, Reason: "exec via /proc/self/fd"},
	}
}

// silence unused-import; filepath is referenced in tests on some builds.
var _ = filepath.Base

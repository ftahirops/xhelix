// Package tamperguard is xhelix's self-protection watchdog.
//
// The first thing a competent attacker does after gaining root is
// disable the EDR. This package is the boundary between "agent
// running" and "agent neutralised". It runs as a goroutine, polls
// signals that should be invariant, and emits a CRITICAL alert as
// soon as one of them changes.
//
// Signals checked:
//
//   tracerpid       /proc/self/status TracerPid — must be 0
//                   (anything else means someone is ptrace'ing us,
//                   which is a sensor-tamper signal)
//
//   binary_mtime    stat(/proc/self/exe) — modification time of the
//                   on-disk binary as the kernel sees it. Drift means
//                   the daemon has been replaced.
//
//   binary_inode    same path — inode change means a swap-and-reload
//                   happened
//
//   auditd_alive    pgrep auditd — auditd is the redundant log
//                   channel. If it disappears, an attacker is closing
//                   the second eye.
//
//   xhelix_pid_file the configured pid file still points to us. If
//                   it's been rewritten to a different pid, someone
//                   is tricking systemd into mis-restarting.
//
// Cadence: 5s by default. Each anomaly emits exactly one alert (we
// don't spam — once tamper is detected, the operator knows).
package tamperguard

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AlertFn is called once per detected anomaly. The Reason string is
// short and actionable (e.g., "ptrace detected: TracerPid=12345").
// Tags map carries structured context.
type AlertFn func(reason string, tags map[string]string)

// Config tunes the watchdog.
type Config struct {
	Interval      time.Duration
	PidFile       string  // optional; skipped if empty
	CheckAuditd   bool    // require auditd to be alive
	BinaryPath    string  // override for /proc/self/exe (testing)
	Logger        *slog.Logger
	OnAnomaly     AlertFn
}

// Guard is the watchdog.
type Guard struct {
	cfg       Config
	log       *slog.Logger

	running   atomic.Bool
	cancel    context.CancelFunc

	mu         sync.Mutex
	baseline   baseline
	fired      map[string]time.Time

	stats struct {
		ticks  atomic.Uint64
		fired  atomic.Uint64
	}
}

type baseline struct {
	binaryMtime time.Time
	binaryInode uint64
	binaryPath  string
}

// New returns an unstarted guard. Capture the baseline at process
// startup, before any attacker has had time to act.
func New(cfg Config) *Guard {
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Guard{cfg: cfg, log: cfg.Logger, fired: map[string]time.Time{}}
}

// Start captures the baseline and launches the watchdog goroutine.
func (g *Guard) Start(parent context.Context) error {
	if !g.running.CompareAndSwap(false, true) {
		return nil
	}
	if err := g.captureBaseline(); err != nil {
		g.running.Store(false)
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	g.cancel = cancel
	go g.loop(ctx)
	return nil
}

// Stop signals shutdown.
func (g *Guard) Stop() {
	if !g.running.CompareAndSwap(true, false) {
		return
	}
	if g.cancel != nil {
		g.cancel()
	}
}

// Stats returns counters for the dashboard.
type Stats struct {
	Ticks  uint64
	Fired  uint64
}

func (g *Guard) Stats() Stats {
	return Stats{Ticks: g.stats.ticks.Load(), Fired: g.stats.fired.Load()}
}

func (g *Guard) captureBaseline() error {
	path := g.cfg.BinaryPath
	if path == "" {
		var err error
		path, err = os.Readlink("/proc/self/exe")
		if err != nil {
			return fmt.Errorf("readlink /proc/self/exe: %w", err)
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.baseline = baseline{
		binaryPath:  path,
		binaryMtime: st.ModTime(),
		binaryInode: inodeOf(st),
	}
	return nil
}

func (g *Guard) loop(ctx context.Context) {
	t := time.NewTicker(g.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.tick()
		}
	}
}

func (g *Guard) tick() {
	g.stats.ticks.Add(1)
	g.checkTracerPid()
	g.checkBinary()
	if g.cfg.CheckAuditd {
		g.checkAuditd()
	}
	if g.cfg.PidFile != "" {
		g.checkPidFile()
	}
}

// checkTracerPid reads /proc/self/status and fires when TracerPid
// becomes non-zero. Debuggers attach via ptrace; so do many tampering
// tools.
func (g *Guard) checkTracerPid() {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "TracerPid:") {
			continue
		}
		pidStr := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
		pid, _ := strconv.Atoi(pidStr)
		if pid != 0 {
			g.fire("tamper.ptrace", fmt.Sprintf("TracerPid=%d (someone is ptrace'ing xhelix)", pid),
				map[string]string{"tracer_pid": pidStr})
		}
		return
	}
}

// checkBinary stats the on-disk binary and compares to the baseline
// captured at start. Mismatch = the agent file was replaced.
func (g *Guard) checkBinary() {
	g.mu.Lock()
	bp := g.baseline
	g.mu.Unlock()
	if bp.binaryPath == "" {
		return
	}
	st, err := os.Stat(bp.binaryPath)
	if err != nil {
		g.fire("tamper.binary_missing", "xhelix binary unreadable: "+err.Error(),
			map[string]string{"path": bp.binaryPath})
		return
	}
	if !st.ModTime().Equal(bp.binaryMtime) {
		g.fire("tamper.binary_mtime",
			fmt.Sprintf("binary mtime changed: %s -> %s", bp.binaryMtime, st.ModTime()),
			map[string]string{"path": bp.binaryPath, "old_mtime": bp.binaryMtime.String(), "new_mtime": st.ModTime().String()})
	}
	if ino := inodeOf(st); ino != 0 && bp.binaryInode != 0 && ino != bp.binaryInode {
		g.fire("tamper.binary_inode",
			fmt.Sprintf("binary inode changed: %d -> %d (atomic replace)", bp.binaryInode, ino),
			map[string]string{"path": bp.binaryPath})
	}
}

// checkAuditd verifies the auditd process is alive. APTs disable it
// to silence the redundant log channel. We bound the pgrep with a
// 2-second context so a stalled /proc (under heavy load or during
// an incident affecting scheduling) doesn't hang the whole watchdog
// goroutine — that would silence the rest of the checks for the
// duration of the stall.
func (g *Guard) checkAuditd() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "pgrep", "-x", "auditd").Run(); err != nil {
		g.fire("tamper.auditd_dead", "auditd process not running",
			map[string]string{})
	}
}

// checkPidFile reads the configured pid file and verifies it points
// to us. If it's been rewritten to point at a different pid, an
// attacker is poisoning systemd's view of the daemon.
func (g *Guard) checkPidFile() {
	body, err := os.ReadFile(g.cfg.PidFile)
	if err != nil {
		return // pid file missing during reload is normal
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(body)))
	if pid != 0 && pid != os.Getpid() {
		g.fire("tamper.pidfile",
			fmt.Sprintf("pid file points at %d (we are %d)", pid, os.Getpid()),
			map[string]string{"pidfile_pid": strconv.Itoa(pid), "our_pid": strconv.Itoa(os.Getpid())})
	}
}

// fire emits an anomaly. Each (reason) ID is rate-limited to once per
// hour so a persistent tamper doesn't flood the alert bus.
func (g *Guard) fire(id, reason string, tags map[string]string) {
	g.mu.Lock()
	if last, ok := g.fired[id]; ok && time.Since(last) < time.Hour {
		g.mu.Unlock()
		return
	}
	g.fired[id] = time.Now()
	g.mu.Unlock()
	g.stats.fired.Add(1)
	g.log.Error("tamper detected", "id", id, "reason", reason)
	if g.cfg.OnAnomaly != nil {
		if tags == nil {
			tags = map[string]string{}
		}
		tags["tamper_id"] = id
		g.cfg.OnAnomaly(reason, tags)
	}
}

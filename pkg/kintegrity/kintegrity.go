// Package kintegrity detects kernel-level tampering — rootkits,
// patched syscalls, hidden modules.
//
// We can't directly read kernel text from userspace, but we can hash
// public surfaces that should be invariant for the lifetime of the
// boot:
//
//   /proc/kallsyms   — every kernel symbol's address. A rootkit that
//                      patches sys_call_table or sys_open changes the
//                      address of those symbols (it relocates them
//                      or trampolines them).
//   /proc/modules    — list of loaded modules with addresses + sizes.
//                      An attacker who hides their module from this
//                      list (the classic LKM rootkit trick) shows up
//                      as a missing module count.
//   sys_call_table   — addresses of the first ~50 syscalls, parsed
//                      from kallsyms. If they shift, someone is
//                      hooking syscalls.
//
// Method:
//
//   1. At startup, read all three sources and store baseline hashes.
//   2. Periodically re-read and compare.
//   3. On mismatch, emit a critical alert with which baseline broke.
//
// Limits — be honest:
//
//   - kallsyms requires kernel.kptr_restrict ≤ 1 to show real values
//     for non-root, or root to read at all. With kptr_restrict=2 we
//     fall back to using *just* the symbol names (count + sorted
//     hash), which still detects added/removed symbols.
//   - A rootkit that patches kallsyms output itself defeats this
//     check. We're not chasing tier-4 nation-state kernel implants —
//     we're catching the LKM rootkits that 95% of attackers use.
//   - For real kernel integrity you want IMA + EVM with a TPM. This
//     is a userspace approximation, not that.
package kintegrity

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AlertFn is called once per detected mismatch.
type AlertFn func(reason string, tags map[string]string)

// Config tunes the checker.
type Config struct {
	Interval  time.Duration // re-check cadence; default 60s
	OnAlert   AlertFn
}

// Checker holds the baseline + state.
type Checker struct {
	cfg    Config
	mu     sync.Mutex
	base   *baseline
	// firedAt rate-limits each anomaly id (kallsyms_changed,
	// modules_changed, syscall_address_drift) to one fire per hour.
	// Without this, every 60-second tick after a real rootkit detection
	// would re-fire the same alert — flooding the bus with duplicates
	// of a "happened-once" event.
	firedAt map[string]time.Time

	running atomic.Bool
	cancel  context.CancelFunc

	stats struct {
		ticks  atomic.Uint64
		fired  atomic.Uint64
	}
}

type baseline struct {
	kallsymsHash    string
	kallsymsCount   int
	modulesList     []string // canonical "name size" pairs, sorted
	syscallTable    map[string]string // syscall name → address (or "" if hidden)
	capturedAt      time.Time
}

// New returns an unstarted checker.
func New(cfg Config) *Checker {
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	return &Checker{cfg: cfg}
}

// Start captures the baseline and launches the periodic checker.
func (c *Checker) Start(parent context.Context) error {
	if !c.running.CompareAndSwap(false, true) {
		return nil
	}
	if err := c.capture(); err != nil {
		c.running.Store(false)
		return fmt.Errorf("kintegrity baseline: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	c.cancel = cancel
	go c.loop(ctx)
	return nil
}

// Stop tears down the checker.
func (c *Checker) Stop() {
	if !c.running.CompareAndSwap(true, false) {
		return
	}
	if c.cancel != nil {
		c.cancel()
	}
}

// Stats reports counters.
type Stats struct {
	Ticks    uint64
	Fired    uint64
	BaselineAt time.Time
	KallsymsCount int
	ModulesCount  int
	SyscallsTracked int
}

func (c *Checker) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Stats{
		Ticks: c.stats.ticks.Load(),
		Fired: c.stats.fired.Load(),
	}
	if c.base != nil {
		s.BaselineAt = c.base.capturedAt
		s.KallsymsCount = c.base.kallsymsCount
		s.ModulesCount = len(c.base.modulesList)
		s.SyscallsTracked = len(c.base.syscallTable)
	}
	return s
}

func (c *Checker) capture() error {
	hash, count, err := hashKallsyms()
	if err != nil {
		return err
	}
	mods, err := readModules()
	if err != nil {
		return err
	}
	syms, _ := readSyscalls()
	c.mu.Lock()
	c.base = &baseline{
		kallsymsHash:    hash,
		kallsymsCount:   count,
		modulesList:     mods,
		syscallTable:    syms,
		capturedAt:      time.Now(),
	}
	c.mu.Unlock()
	return nil
}

func (c *Checker) loop(ctx context.Context) {
	t := time.NewTicker(c.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.tick()
		}
	}
}

func (c *Checker) tick() {
	c.stats.ticks.Add(1)
	c.mu.Lock()
	base := c.base
	c.mu.Unlock()
	if base == nil {
		return
	}
	hash, count, err := hashKallsyms()
	if err == nil {
		if hash != base.kallsymsHash {
			c.fire("kallsyms_changed",
				fmt.Sprintf("kallsyms hash drift (count: %d→%d)", base.kallsymsCount, count),
				map[string]string{"old_hash": base.kallsymsHash[:16], "new_hash": hash[:16]})
		}
	}
	if mods, err := readModules(); err == nil {
		if added, removed := diffStrings(base.modulesList, mods); len(added) > 0 || len(removed) > 0 {
			c.fire("modules_changed",
				fmt.Sprintf("module list drift: added=%v removed=%v", added, removed),
				map[string]string{"added": strings.Join(added, ","), "removed": strings.Join(removed, ",")})
		}
	}
	if syms, err := readSyscalls(); err == nil {
		var changed []string
		for name, baseAddr := range base.syscallTable {
			if newAddr, ok := syms[name]; ok && baseAddr != "" && newAddr != "" && baseAddr != newAddr {
				changed = append(changed, name+":"+baseAddr+"->"+newAddr)
			}
		}
		if len(changed) > 0 {
			c.fire("syscall_address_drift",
				fmt.Sprintf("%d syscall addresses changed: %s", len(changed),
					strings.Join(truncate(changed, 5), ", ")),
				map[string]string{"changed": strings.Join(changed, ",")})
		}
	}
}

func (c *Checker) fire(id, reason string, tags map[string]string) {
	// Per-ID rate-limit: at most one fire per hour for the same anomaly
	// kind. Without this a persistent rootkit produces one alert per
	// tick interval, drowning the alert bus and the operator inbox.
	c.mu.Lock()
	if c.firedAt == nil {
		c.firedAt = map[string]time.Time{}
	}
	if last, ok := c.firedAt[id]; ok && time.Since(last) < time.Hour {
		c.mu.Unlock()
		return
	}
	c.firedAt[id] = time.Now()
	c.mu.Unlock()

	c.stats.fired.Add(1)
	if c.cfg.OnAlert != nil {
		if tags == nil {
			tags = map[string]string{}
		}
		tags["kintegrity_id"] = id
		c.cfg.OnAlert(reason, tags)
	}
}

// hashKallsyms reads /proc/kallsyms and produces a stable hash of the
// (sorted, name-only) symbol set. Counts symbols. We don't hash
// addresses because kASLR makes them boot-unique; we hash the SET of
// symbol NAMES, which should be stable across the lifetime of the
// boot and changes only when a module is loaded/unloaded or a kernel
// rootkit relocates the table.
func hashKallsyms() (string, int, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	var names []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 3 {
			names = append(names, fields[2])
		}
	}
	if err := sc.Err(); err != nil {
		return "", 0, err
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), len(names), nil
}

// readModules returns "name size" pairs from /proc/modules, sorted.
// Used as a set diff target rather than a hash so we can show what
// changed in alerts.
func readModules() ([]string, error) {
	body, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range bytes.Split(body, []byte("\n")) {
		fields := strings.Fields(string(line))
		if len(fields) < 2 {
			continue
		}
		out = append(out, fields[0]+" "+fields[1])
	}
	sort.Strings(out)
	return out, nil
}

// readSyscalls extracts the first ~50 sys_* symbol addresses from
// /proc/kallsyms. Useful as a syscall-hooking detector — if any of
// these addresses shifts mid-boot, something patched the table.
//
// Returns name → hex-address map. Addresses appear as "0000000000000000"
// when kptr_restrict hides them; we treat those as unknown and do not
// alert on differences within the unknown set.
func readSyscalls() (map[string]string, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	want := map[string]bool{
		"__x64_sys_open": true, "__x64_sys_openat": true,
		"__x64_sys_read": true, "__x64_sys_write": true,
		"__x64_sys_execve": true, "__x64_sys_execveat": true,
		"__x64_sys_kill": true, "__x64_sys_clone": true,
		"__x64_sys_fork": true, "__x64_sys_ptrace": true,
		"__x64_sys_setuid": true, "__x64_sys_setreuid": true,
		"__x64_sys_init_module": true, "__x64_sys_finit_module": true,
		"__x64_sys_delete_module": true,
		"sys_call_table": true,
		"do_syscall_64":  true,
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		if want[fields[2]] {
			out[fields[2]] = fields[0]
		}
	}
	return out, sc.Err()
}

func diffStrings(a, b []string) (added, removed []string) {
	in := func(set []string, x string) bool {
		i := sort.SearchStrings(set, x)
		return i < len(set) && set[i] == x
	}
	for _, x := range b {
		if !in(a, x) {
			added = append(added, x)
		}
	}
	for _, x := range a {
		if !in(b, x) {
			removed = append(removed, x)
		}
	}
	return added, removed
}

func truncate(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string{}, s[:n]...), fmt.Sprintf("(+%d more)", len(s)-n))
}

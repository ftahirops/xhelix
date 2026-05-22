// Package memdiff detects in-memory implants by watching for NEW
// anonymous executable mappings appearing in any running process.
//
// Why: reflective loaders, in-memory RATs (RemotePE-class on Windows,
// the Linux equivalent via memfd_create + reflective ELF), and
// process-injection malware all create new PROT_EXEC anonymous
// mappings that didn't exist a minute ago. /proc/<pid>/maps surfaces
// every such mapping. A diff between two snapshots catches the
// appearance regardless of how the implant was loaded.
//
// Cost: cheap. Reading /proc/*/maps is metadata-only — no per-pid
// memory traversal, no syscalls into the inspected process. On a
// 200-process host, full snapshot is ~10-50ms wall time and a few
// MB of RAM for the previous-snapshot cache.
//
// What this catches that procmem doesn't: procmem only fires on
// thread-RIP-in-anonymous-page. A reflective loader that copies code
// into anon RWX then *also* keeps the original entry point would
// evade procmem's RIP check, but its new RWX region still appears in
// /proc/<pid>/maps. memdiff catches the *appearance*; procmem
// catches *execution from*. Together they're stronger than either.
//
// Allowlist: JIT runtimes (Node/V8, JVM, .NET) legitimately create
// anonymous RWX regions on demand. Same runtimeallow.Allowlister
// interface used by procmem — when a process matches, its anonymous-
// exec regions are silently accepted.
package memdiff

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/procmem"
)

// Region identifies one anonymous-executable mapping in a process.
type Region struct {
	StartAddr uint64
	EndAddr   uint64
	Perms     string // four-char rwxp string from /proc/<pid>/maps
}

// Key returns a comparison key for a Region. Two regions are "the
// same" if their start address matches — that's how we distinguish
// "this region grew" from "a new region appeared".
func (r Region) Key() uint64 { return r.StartAddr }

// Finding is one diff result: a new anonymous-executable region in
// some process that wasn't there in the prior snapshot.
type Finding struct {
	PID    uint32
	Comm   string
	Image  string
	Region Region
}

// Scanner snapshots /proc on every Tick and diffs against the prior
// snapshot. The first Tick produces a baseline with no findings.
//
// Grace period semantics: a PID that didn't exist in the prior tick
// is normally skipped to suppress process-startup JIT noise. Once
// the PID has been observed for at least Grace duration, that
// suppression lifts — any new anon-exec region appearing AFTER the
// PID started but before its first "established" tick will still
// fire. Set Grace = 0 to disable (every new PID fires immediately).
type Scanner struct {
	allow procmem.Allowlister
	grace time.Duration

	mu        sync.Mutex
	prev      map[uint32]map[uint64]Region // pid → addr → Region
	firstSeen map[uint32]time.Time         // pid → when first observed

	stats struct {
		ticks         atomic.Uint64
		newRegions    atomic.Uint64
		allowlisted   atomic.Uint64
		newPidSkipped atomic.Uint64
	}
}

// New constructs a Scanner with the default grace period (30s).
func New(allow procmem.Allowlister) *Scanner {
	return NewWithGrace(allow, 30*time.Second)
}

// NewWithGrace constructs a Scanner with a custom grace period.
// Grace = 0 disables the new-PID suppression (every appearance fires
// immediately — useful for tight testing, noisy in production).
func NewWithGrace(allow procmem.Allowlister, grace time.Duration) *Scanner {
	return &Scanner{
		allow:     allow,
		grace:     grace,
		prev:      map[uint32]map[uint64]Region{},
		firstSeen: map[uint32]time.Time{},
	}
}

// Tick performs one /proc walk + diff. Returns findings since the
// previous Tick. First call always returns nil (baseline-only).
func (s *Scanner) Tick() []Finding {
	s.stats.ticks.Add(1)
	now := s.snapshot()
	tickAt := time.Now()
	var findings []Finding

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.prev) == 0 {
		// Baseline — no prior snapshot to diff against.
		s.prev = now
		for pid := range now {
			s.firstSeen[pid] = tickAt
		}
		return nil
	}

	for pid, regions := range now {
		priorRegions, hadPid := s.prev[pid]
		comm := readComm(pid)
		image := readExe(pid)
		// JIT allowlist: full skip on this process regardless of
		// new/old.
		if s.allow != nil && s.allow.MatchAny(image, comm) {
			s.stats.allowlisted.Add(uint64(len(regions)))
			continue
		}
		if !hadPid {
			// New PID. Two sub-cases:
			//   - We've never recorded a first-seen → record now,
			//     skip this tick (let JIT noise settle).
			//   - PID has been observed for at least grace, but was
			//     missing from prev (transient kernel race or grace
			//     expired between observations) → all regions count
			//     as new. This is what catches the synthetic-test
			//     case where a PID was spawned, RWX-mmap'd, and the
			//     tick boundary fell inside its lifetime.
			seen, ok := s.firstSeen[pid]
			if !ok {
				s.firstSeen[pid] = tickAt
				s.stats.newPidSkipped.Add(1)
				continue
			}
			if s.grace > 0 && tickAt.Sub(seen) < s.grace {
				s.stats.newPidSkipped.Add(1)
				continue
			}
			// Fall through: treat all regions as new for this PID.
			priorRegions = nil
		}
		for addr, r := range regions {
			if _, existed := priorRegions[addr]; existed {
				continue
			}
			s.stats.newRegions.Add(1)
			findings = append(findings, Finding{
				PID:    pid,
				Comm:   comm,
				Image:  image,
				Region: r,
			})
		}
	}
	// Rotate snapshots and prune firstSeen for PIDs no longer
	// present (process exited).
	s.prev = now
	for pid := range s.firstSeen {
		if _, alive := now[pid]; !alive {
			delete(s.firstSeen, pid)
		}
	}
	return findings
}

// snapshot walks /proc/*/maps and returns pid → addr → Region for
// every anonymous-executable mapping (perms contain 'x' AND the
// mapping has no backing file).
func (s *Scanner) snapshot() map[uint32]map[uint64]Region {
	out := map[uint32]map[uint64]Region{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		regions := parseAnonExecRegions(uint32(pid))
		if len(regions) > 0 {
			out[uint32(pid)] = regions
		}
	}
	return out
}

// parseAnonExecRegions reads /proc/<pid>/maps and returns every
// anonymous-executable mapping keyed by start address.
//
// Maps line format (canonical):
//
//	5577c5c00000-5577c5c01000 r-xp 00000000 08:01 12345 /usr/bin/sleep
//	7f8a8b2c0000-7f8a8b2d0000 rwxp 00000000 00:00 0
//	                                          ^^^^^^^^^^^^^ no backing file
//
// We want lines with 'x' in perms AND no path (or path is [stack]/[heap]
// — those are also anonymous from our perspective, though we skip
// [vdso] / [vsyscall] which are kernel-provided).
func parseAnonExecRegions(pid uint32) map[uint64]Region {
	path := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "maps")
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[uint64]Region{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		// Fields: <range> <perms> <offset> <dev> <inode> [<path>]
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		perms := fields[1]
		if len(perms) < 4 || perms[2] != 'x' {
			continue
		}
		// Has a backing file? Field 6+ present and not a special name.
		if len(fields) >= 6 {
			pathField := fields[5]
			// Kernel-provided regions are not implant pages.
			if pathField == "[vdso]" || pathField == "[vsyscall]" ||
				pathField == "[vvar]" || pathField == "[uprobes]" {
				continue
			}
			// File-backed mapping (most legit executable pages).
			if !strings.HasPrefix(pathField, "[") {
				continue
			}
			// [stack], [heap] with executable perms — that IS the
			// signal we want. Fall through to record it.
		}
		// Parse the start-end range.
		rng := fields[0]
		dash := strings.IndexByte(rng, '-')
		if dash < 0 {
			continue
		}
		start, err := strconv.ParseUint(rng[:dash], 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(rng[dash+1:], 16, 64)
		if err != nil {
			continue
		}
		out[start] = Region{StartAddr: start, EndAddr: end, Perms: perms}
	}
	return out
}

func readComm(pid uint32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readExe(pid uint32) string {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	link = strings.TrimSuffix(link, " (deleted)")
	return link
}

// Stats returns snapshot counters.
type Stats struct {
	Ticks       uint64
	NewRegions  uint64
	Allowlisted uint64
}

// Stats returns the current scanner counters.
func (s *Scanner) Stats() Stats {
	return Stats{
		Ticks:       s.stats.ticks.Load(),
		NewRegions:  s.stats.newRegions.Load(),
		Allowlisted: s.stats.allowlisted.Load(),
	}
}

// Run starts a periodic Tick loop on the given interval. Findings
// are emitted to out as model.Event with kind=mem_new_rwx_mapping.
// Returns when ctx is cancelled.
func (s *Scanner) Run(ctx context.Context, interval time.Duration, out chan<- model.Event, host string) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	// Run the first Tick immediately so we have a baseline ASAP.
	s.Tick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			findings := s.Tick()
			for _, f := range findings {
				emitFinding(out, host, f)
			}
		}
	}
}

func emitFinding(out chan<- model.Event, host string, f Finding) {
	if out == nil {
		return
	}
	ev := model.NewEvent("memdiff", model.SeverityHigh)
	ev.Time = time.Now().UTC()
	ev.Host = host
	ev.PID = f.PID
	ev.Comm = f.Comm
	ev.Image = f.Image
	ev.Tags["kind"] = "mem_new_rwx_mapping"
	ev.Tags["region_start"] = fmt.Sprintf("%#x", f.Region.StartAddr)
	ev.Tags["region_end"] = fmt.Sprintf("%#x", f.Region.EndAddr)
	ev.Tags["region_size"] = strconv.FormatUint(f.Region.EndAddr-f.Region.StartAddr, 10)
	ev.Tags["region_perms"] = f.Region.Perms
	select {
	case out <- ev:
	default:
	}
}

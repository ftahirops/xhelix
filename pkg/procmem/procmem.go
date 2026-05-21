// Package procmem detects two memory-execution patterns that are
// classic post-exploitation indicators but were missing from the
// xhelix eBPF rule set:
//
//   1. Deleted binary still running. /proc/<pid>/exe points to a
//      path the kernel reports as "(deleted)" because the on-disk
//      file was unlinked while the process was still alive. The
//      canonical "curl|sh && rm self" dropper pattern and the
//      memfd-style replay pattern both land here. Easy to detect
//      via /proc/<pid>/exe readlink.
//
//   2. Thread executing outside any loaded module. The thread's
//      current PC (from /proc/<pid>/task/<tid>/syscall) is not
//      inside any file-backed executable mapping listed in
//      /proc/<pid>/maps. That means the thread is running shellcode
//      injected into an anonymous mapping — reflective DLL/.so
//      load, Cobalt Strike beacon, Sliver implant, etc.
//
// Both checks are periodic /proc walks. We do not use eBPF for
// these: the kernel signal is hard to capture cleanly (we'd need a
// kprobe on kernel_clone with bpf_probe_read_user for the user-
// space entry point) and the periodic-walk false-negative window
// (60s default) is acceptable because process-injection and
// deleted-binary droppers persist long enough to be caught.
//
// Honest limitations:
//   - 60s lag: an attacker who runs for <60s won't be caught.
//   - We rely on /proc/<pid>/syscall which only shows the current
//     syscall site, not the thread's full call stack. A thread
//     spending most of its time in libc read() will appear to be
//     inside libc, even if the calling function is shellcode.
//     This means we catch the *steady-state* thread (a beacon
//     polling its C2) but can miss a thread that fires shellcode
//     once and exits.
//   - JIT-heavy runtimes (Java, Node, .NET) legitimately run code
//     from anonymous executable mappings. We exempt processes
//     whose Image is in the runtimeallow set (passed in as
//     constructor arg).
package procmem

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Finding describes one suspect pid/tid produced by Scan.
type Finding struct {
	Kind     string // "deleted_exe" | "thread_outside_module"
	PID      uint32
	TID      uint32  // 0 for deleted_exe
	Comm     string
	Image    string  // canonical exe (with "(deleted)" stripped)
	UID      uint32
	Reason   string  // human-friendly explanation
	Detail   string  // PC for thread; "(deleted)" suffix for exe
}

// Allowlister is the contract we need from runtimeallow.Set. Keeping
// it an interface here lets the test pass a stub instead of pulling
// in the whole pkg/runtimeallow.
type Allowlister interface {
	MatchAny(image, comm string) bool
}

// Scanner walks /proc once per call to Scan and returns every
// finding. Stateless; safe to call concurrently.
type Scanner struct {
	allow Allowlister
}

// New returns a Scanner. allow may be nil — in that case the JIT
// exemption is disabled and every anonymous-PC thread is reported.
func New(allow Allowlister) *Scanner {
	return &Scanner{allow: allow}
}

// Scan walks /proc/[0-9]+/ and returns all findings.
func (s *Scanner) Scan() []Finding {
	var out []Finding
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		// Cheap pre-filter: read comm to fold our own PID and to
		// stamp findings.
		comm := readTrim("/proc/" + e.Name() + "/comm")
		if comm == "" {
			continue
		}
		exe, deleted := resolveExe(pid)
		if exe == "" {
			// Kernel thread or perm denied — both safe to skip.
			continue
		}
		uid := readPidUID(pid)

		// (1) Deleted-exe check.
		if deleted {
			out = append(out, Finding{
				Kind:   "deleted_exe",
				PID:    pid, Comm: comm, Image: exe, UID: uid,
				Reason: "process is running from a binary that was unlinked",
				Detail: "(deleted)",
			})
		}

		// (2) Thread-outside-module check — only when allowlist
		// doesn't exempt the runtime. JIT engines (java, node,
		// dotnet, python with pypy, etc.) legitimately execute
		// from anonymous executable mappings.
		if s.allow != nil && s.allow.MatchAny(exe, comm) {
			continue
		}
		// Build the loaded-module map list once per pid.
		ranges, err := loadExecutableRanges(pid)
		if err != nil || len(ranges) == 0 {
			continue
		}
		// Walk each TID.
		tasks, err := os.ReadDir("/proc/" + e.Name() + "/task")
		if err != nil {
			continue
		}
		for _, t := range tasks {
			tid64, err := strconv.ParseUint(t.Name(), 10, 32)
			if err != nil {
				continue
			}
			tid := uint32(tid64)
			pc, ok := currentPC(pid, tid)
			if !ok {
				continue
			}
			if pcInRanges(pc, ranges) {
				continue
			}
			// Confirm the PC is in an anonymous executable mapping
			// (otherwise it's some kernel-internal address we
			// don't model — skip to keep FP low).
			if !pcInAnonExec(pid, pc) {
				continue
			}
			out = append(out, Finding{
				Kind:  "thread_outside_module",
				PID:   pid, TID: tid, Comm: comm, Image: exe, UID: uid,
				Reason: "thread's current PC is outside any file-backed executable mapping (anonymous-exec)",
				Detail: fmt.Sprintf("pc=0x%x", pc),
			})
		}
	}
	return out
}

// ─────────────────────────── helpers ──────────────────────────────

// resolveExe returns the canonical exe path and whether the kernel
// suffixed " (deleted)" to it.
func resolveExe(pid uint32) (string, bool) {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", false
	}
	// Kernel produces "/path/to/exe (deleted)" when the original
	// dentry has been unlinked. Some readers see " (deleted)\x00"
	// but Go's Readlink strips the NUL.
	if strings.HasSuffix(link, " (deleted)") {
		return strings.TrimSuffix(link, " (deleted)"), true
	}
	return link, false
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readPidUID(pid uint32) uint32 {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			fs := strings.Fields(line)
			if len(fs) >= 2 {
				u, _ := strconv.ParseUint(fs[1], 10, 32)
				return uint32(u)
			}
		}
	}
	return 0
}

// memRange is one file-backed executable mapping.
type memRange struct {
	start, end uint64
}

// loadExecutableRanges parses /proc/<pid>/maps and returns every
// file-backed executable region. Anonymous executable regions are
// intentionally NOT included — those are exactly where injected
// shellcode runs from.
func loadExecutableRanges(pid uint32) ([]memRange, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []memRange
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fs := strings.Fields(line)
		if len(fs) < 6 {
			continue
		}
		// Field layout:
		// 0=start-end 1=perms 2=offset 3=dev 4=inode 5+=pathname
		if !strings.Contains(fs[1], "x") {
			continue
		}
		path := strings.Join(fs[5:], " ")
		// Skip anonymous and pseudo-pathnames; we explicitly want
		// file-backed only.
		if path == "" || strings.HasPrefix(path, "[") ||
			strings.HasPrefix(path, "anon_inode:") {
			continue
		}
		// Range "start-end".
		dash := strings.IndexByte(fs[0], '-')
		if dash < 0 {
			continue
		}
		start, err1 := strconv.ParseUint(fs[0][:dash], 16, 64)
		end, err2 := strconv.ParseUint(fs[0][dash+1:], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, memRange{start: start, end: end})
	}
	return out, nil
}

func pcInRanges(pc uint64, ranges []memRange) bool {
	for _, r := range ranges {
		if pc >= r.start && pc < r.end {
			return true
		}
	}
	return false
}

// pcInAnonExec returns true if pc falls inside an anonymous (no
// pathname) executable mapping in /proc/<pid>/maps. We need this
// final confirmation to keep FP low — without it, a stale syscall-
// site reading in kernel space could falsely trigger.
func pcInAnonExec(pid uint32, pc uint64) bool {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fs := strings.Fields(line)
		if len(fs) < 5 {
			continue
		}
		if !strings.Contains(fs[1], "x") {
			continue
		}
		// Anonymous if no pathname field, or if pathname starts
		// with [ (e.g. [stack], [vdso]). Note [vdso] is a special
		// kernel page — code running there is normal, exempt.
		path := ""
		if len(fs) >= 6 {
			path = strings.Join(fs[5:], " ")
		}
		if path != "" && !strings.HasPrefix(path, "[") {
			continue
		}
		if strings.HasPrefix(path, "[vdso") || strings.HasPrefix(path, "[vsyscall") {
			continue
		}
		dash := strings.IndexByte(fs[0], '-')
		if dash < 0 {
			continue
		}
		start, err1 := strconv.ParseUint(fs[0][:dash], 16, 64)
		end, err2 := strconv.ParseUint(fs[0][dash+1:], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if pc >= start && pc < end {
			return true
		}
	}
	return false
}

// currentPC reads /proc/<pid>/task/<tid>/syscall. Format:
//
//	<syscall_nr> <a1> <a2> <a3> <a4> <a5> <a6> <sp> <pc>
//
// or "running" if the thread is on-CPU (rare; we skip that case
// since we can't get a stable PC).
func currentPC(pid, tid uint32) (uint64, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/syscall", pid, tid))
	if err != nil {
		return 0, false
	}
	line := strings.TrimSpace(string(data))
	if line == "" || line == "running" {
		return 0, false
	}
	fs := strings.Fields(line)
	if len(fs) < 2 {
		return 0, false
	}
	// PC is the last field.
	pcStr := fs[len(fs)-1]
	pcStr = strings.TrimPrefix(pcStr, "0x")
	pc, err := strconv.ParseUint(pcStr, 16, 64)
	if err != nil {
		return 0, false
	}
	return pc, true
}

// Path of /proc — exposed for tests; production always uses /proc.
var procRoot = "/proc"

// resolvePidPath helps test override (kept simple; production
// hardcoded paths above).
func resolvePidPath(pid uint32, sub string) string {
	return filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), sub)
}

// Package hiddenproc detects pids that exist on the kernel side
// but are hidden from userland enumeration — the classic signature
// of LD_PRELOAD rootkits (Diamorphine, Jynx, libprocesshider, etc.).
//
// Mechanism: enumerate /proc by two independent paths and look for
// the asymmetric difference.
//
//   - "kernel view"   — direct getdents64 on /proc, no libc opendir
//   - "userland view" — Go's std os.ReadDir (which goes through libc
//     readdir on glibc systems via cgo, or via the same getdents64
//     syscall on netbsd-style stdlib; identical on a clean host)
//
// In observation-only mode (CGO_ENABLED=0, current xhelix), the two
// paths diverge only when a kernel-side rootkit hides pids. We
// also cross-check against /proc/<pid>/status existence: if a pid
// is gettable by stat but missing from at least one enumeration,
// that's the smoking gun.
//
// On a clean host, Detect() returns no findings. False positives
// are rare and racy (pid exited mid-scan); the detector emits each
// finding twice within ~1s before treating it as confirmed.
package hiddenproc

import (
	"errors"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Finding represents one suspected hidden pid.
type Finding struct {
	PID        uint32
	Comm       string // /proc/<pid>/comm content
	Exe        string // /proc/<pid>/exe target (when readable)
	Reason     string // human-readable detection note
	FirstSeen  time.Time
	Confirmed  bool // seen twice within ConfirmWindow
}

// Detector scans /proc periodically and reports hidden pids.
type Detector struct {
	// ProcRoot is the /proc mount, defaulting to "/proc". Tests
	// inject a fake tree.
	ProcRoot string

	// ConfirmWindow is the time within which a hidden-pid finding
	// must be seen twice to count as confirmed. <=0 selects 2s.
	ConfirmWindow time.Duration

	pending map[uint32]time.Time
	now     func() time.Time
}

// NewDetector returns a Detector with sane defaults.
func NewDetector() *Detector {
	return &Detector{
		ProcRoot:      "/proc",
		ConfirmWindow: 2 * time.Second,
		pending:       map[uint32]time.Time{},
		now:           time.Now,
	}
}

// Scan runs one detection pass. Returns all findings from this pass
// (whether or not confirmed). A finding is `Confirmed == true` when
// the same pid has been observed hidden in two consecutive scans
// less than ConfirmWindow apart — high-confidence signal.
func (d *Detector) Scan() ([]Finding, error) {
	// Direct syscall enumeration.
	rawPIDs, err := readProcViaGetdents(d.ProcRoot)
	if err != nil {
		return nil, err
	}

	// Standard-library enumeration. On a clean host these match
	// exactly; mismatches are either races or rootkit signatures.
	stdPIDs, err := readProcViaStdlib(d.ProcRoot)
	if err != nil {
		return nil, err
	}

	// Cross-check: any pid the stdlib didn't see but getdents did.
	rawSet := toSet(rawPIDs)
	stdSet := toSet(stdPIDs)

	var hidden []uint32
	for pid := range rawSet {
		if _, ok := stdSet[pid]; !ok {
			hidden = append(hidden, pid)
		}
	}
	// Also include the inverse — pids the stdlib sees but the
	// direct syscall doesn't. Rare but real: a kernel-side
	// rootkit hiding from getdents but leaving the inode visible.
	for pid := range stdSet {
		if _, ok := rawSet[pid]; !ok {
			hidden = append(hidden, pid)
		}
	}
	sort.Slice(hidden, func(i, j int) bool { return hidden[i] < hidden[j] })

	now := d.now()
	var out []Finding
	for _, pid := range hidden {
		// Probe /proc/<pid>/comm independently — if it's
		// readable, the pid really exists in some view.
		statPath := d.ProcRoot + "/" + strconv.FormatUint(uint64(pid), 10) + "/status"
		if _, err := os.Stat(statPath); err != nil {
			// pid evaporated; treat as race, not a finding.
			continue
		}
		commBytes, _ := os.ReadFile(d.ProcRoot + "/" + strconv.FormatUint(uint64(pid), 10) + "/comm")
		comm := strings.TrimSpace(string(commBytes))
		exe, _ := os.Readlink(d.ProcRoot + "/" + strconv.FormatUint(uint64(pid), 10) + "/exe")

		f := Finding{
			PID:    pid,
			Comm:   comm,
			Exe:    exe,
			Reason: "pid visible to direct getdents64 but absent from stdlib readdir",
		}
		if first, ok := d.pending[pid]; ok {
			f.FirstSeen = first
			if now.Sub(first) <= d.ConfirmWindow {
				f.Confirmed = true
			}
		} else {
			f.FirstSeen = now
			d.pending[pid] = now
		}
		out = append(out, f)
	}

	// Garbage-collect pending entries we didn't re-hit this scan.
	pidsHit := make(map[uint32]struct{}, len(hidden))
	for _, p := range hidden {
		pidsHit[p] = struct{}{}
	}
	for pid := range d.pending {
		if _, ok := pidsHit[pid]; !ok {
			delete(d.pending, pid)
		}
	}
	return out, nil
}

func toSet(s []uint32) map[uint32]struct{} {
	out := make(map[uint32]struct{}, len(s))
	for _, v := range s {
		out[v] = struct{}{}
	}
	return out
}

// readProcViaStdlib uses os.ReadDir — the path a Go program (and
// most LD_PRELOAD-hooked libc paths) would take.
func readProcViaStdlib(root string) ([]uint32, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	out := make([]uint32, 0, 256)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n, ok := parsePID(e.Name())
		if !ok {
			continue
		}
		out = append(out, n)
	}
	return out, nil
}

// readProcViaGetdents enumerates /proc by opening the directory
// and calling getdents64 directly — bypassing libc readdir. This
// is the kernel's truth: an LD_PRELOAD readdir hook cannot affect
// a raw syscall.
//
// Production-only on Linux. Non-Linux callers should rely on the
// stdlib path; the two will agree.
func readProcViaGetdents(root string) ([]uint32, error) {
	f, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make([]uint32, 0, 256)
	buf := make([]byte, 64*1024)
	for {
		n, err := readDirentRaw(int(f.Fd()), buf)
		if n <= 0 {
			if errors.Is(err, fs.ErrInvalid) {
				// non-Linux fallback: trust stdlib
				return readProcViaStdlib(root)
			}
			if err != nil {
				return nil, err
			}
			break
		}
		off := 0
		for off < n {
			// linux_dirent64: d_ino(8) d_off(8) d_reclen(2) d_type(1) d_name[]
			if off+19 > n {
				break
			}
			reclen := int(buf[off+16]) | int(buf[off+17])<<8
			if reclen <= 0 || off+reclen > n {
				break
			}
			// d_name is NUL-terminated; ends before reclen.
			nameStart := off + 19
			nameEnd := nameStart
			for nameEnd < off+reclen && buf[nameEnd] != 0 {
				nameEnd++
			}
			name := string(buf[nameStart:nameEnd])
			if pid, ok := parsePID(name); ok {
				out = append(out, pid)
			}
			off += reclen
		}
	}
	return out, nil
}

// parsePID returns the parsed pid + ok for purely-numeric names.
func parsePID(name string) (uint32, bool) {
	if name == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(name, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// readDirentRaw is a thin wrapper around the getdents64 syscall;
// build-tag-split for non-Linux platforms.
var readDirentRaw = func(fd int, buf []byte) (int, error) {
	return syscall.ReadDirent(fd, buf)
}

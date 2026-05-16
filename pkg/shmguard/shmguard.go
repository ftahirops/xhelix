// Package shmguard detects exec from tmpfs-backed paths.
//
// Executing from /dev/shm, /run/user/<uid>/, or any tmpfs mount is
// overwhelmingly malicious: legitimate software does not stage its
// binaries on tmpfs. The signal is high enough that a single
// exec-from-tmpfs deserves a high-severity alert without needing
// any other evidence — though the detector pairs naturally with
// pkg/lolbin and pkg/revshell for confirmation.
//
// The package is data + pure logic. A Detector is constructed
// with a snapshot of tmpfs mount paths (built once from
// /proc/mounts by the caller, and refreshed periodically — every
// few seconds is fine, mounts rarely change). Evaluating a Spawn
// is O(log N) over the mount set.
package shmguard

import (
	"bufio"
	"io"
	"sort"
	"strings"
)

// Severity buckets returned by Evaluate.
type Severity uint8

const (
	SeverityNone     Severity = 0
	SeverityMedium   Severity = 3 // tmpfs exec, no obvious aggravators
	SeverityHigh     Severity = 4 // tmpfs exec from /dev/shm specifically
	SeverityCritical Severity = 5 // tmpfs exec by root or with SUID
)

func (s Severity) String() string {
	switch s {
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "none"
}

// Spawn is the input record.
type Spawn struct {
	Exe   string // absolute path of the executed binary
	UID   uint32 // effective uid at exec; 0 = root
	SUID  bool   // exec'd with setuid bit
	Argv  []string
}

// Verdict is the detector output.
type Verdict struct {
	Severity Severity
	Mount    string   // the matching tmpfs mountpoint, if any
	Reasons  []string // human-readable list of contributing signals
}

// Detector evaluates Spawns against a snapshot of tmpfs mounts.
// Construct with NewDetector; rebuild periodically with Refresh.
//
// The struct is safe for concurrent reads. Callers should not call
// Refresh concurrently with Evaluate without external locking;
// the typical pattern is one goroutine refreshing every N seconds
// while many goroutines evaluate.
type Detector struct {
	// mounts is sorted longest-first so prefix-match returns the
	// most specific mount.
	mounts []string
}

// NewDetector builds a Detector with explicit mount paths.
// Mostly used by tests; production callers prefer FromProcMounts.
func NewDetector(mounts []string) *Detector {
	d := &Detector{}
	d.setMounts(mounts)
	return d
}

// FromProcMounts parses /proc/mounts-style content (one mount per
// line in the kernel's documented format) and returns a Detector
// containing all tmpfs mountpoints.
func FromProcMounts(r io.Reader) *Detector {
	mounts := parseTmpfsMounts(r)
	return NewDetector(mounts)
}

// Refresh replaces the mount snapshot in place. Caller must
// guarantee no concurrent Evaluate.
func (d *Detector) Refresh(mounts []string) {
	d.setMounts(mounts)
}

// Mounts returns a copy of the current tmpfs mount snapshot.
func (d *Detector) Mounts() []string {
	out := make([]string, len(d.mounts))
	copy(out, d.mounts)
	return out
}

// Evaluate returns the Verdict for s.
func (d *Detector) Evaluate(s Spawn) Verdict {
	if s.Exe == "" {
		return Verdict{}
	}
	mount := d.matchMount(s.Exe)
	if mount == "" {
		return Verdict{}
	}

	v := Verdict{Mount: mount}
	raise := func(to Severity, r string) {
		if to > v.Severity {
			v.Severity = to
		}
		v.Reasons = append(v.Reasons, r)
	}

	raise(SeverityMedium, "executed from tmpfs mount "+mount)

	// /dev/shm and /run/user/<uid>/ are the highest-signal subset.
	if mount == "/dev/shm" ||
		strings.HasPrefix(s.Exe, "/dev/shm/") ||
		strings.HasPrefix(mount, "/run/user/") {
		raise(SeverityHigh, "executed from /dev/shm or /run/user — almost always malicious")
	}

	if s.UID == 0 {
		raise(SeverityCritical, "tmpfs exec by uid 0 (root)")
	}
	if s.SUID {
		raise(SeverityCritical, "tmpfs exec via setuid bit")
	}

	return v
}

// matchMount returns the longest tmpfs mount that is a prefix
// of exe, or "" if none.
func (d *Detector) matchMount(exe string) string {
	for _, m := range d.mounts {
		if exe == m {
			return m
		}
		if strings.HasPrefix(exe, m+"/") {
			return m
		}
		if m == "/" && strings.HasPrefix(exe, "/") {
			// Pathological — root mount as tmpfs would match
			// everything. Skip; safer to not flag every exec.
			continue
		}
	}
	return ""
}

func (d *Detector) setMounts(mounts []string) {
	clean := make([]string, 0, len(mounts))
	seen := map[string]struct{}{}
	for _, m := range mounts {
		m = strings.TrimRight(m, "/")
		if m == "" || m == "/" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		clean = append(clean, m)
	}
	// Longest first.
	sort.Slice(clean, func(i, j int) bool {
		return len(clean[i]) > len(clean[j])
	})
	d.mounts = clean
}

// parseTmpfsMounts extracts mountpoints whose filesystem type is
// tmpfs, ramfs, or devtmpfs from /proc/mounts-formatted input.
// Format: "<device> <mountpoint> <fstype> <options> <dump> <pass>".
func parseTmpfsMounts(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		// /proc/mounts uses spaces with octal-escaped spaces in paths.
		// For our purpose the simple split is sufficient; tmpfs mounts
		// rarely have spaces in their path on real systems.
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		fstype := fields[2]
		if fstype == "tmpfs" || fstype == "ramfs" || fstype == "devtmpfs" {
			out = append(out, fields[1])
		}
	}
	return out
}

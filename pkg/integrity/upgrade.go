package integrity

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// AuthenticUpgradeVerdict is the result of testing whether a binary
// write was performed under a legitimate package-manager transaction.
// See docs/EGRESS_C2_DISARM_AND_BINARY_INTEGRITY_2026-05-22.md §2.5.
type AuthenticUpgradeVerdict struct {
	// Authentic is true only if every applicable test passed.
	Authentic bool
	// Manager is "dpkg" / "rpm" / "" — identifies which suite ran the
	// transaction. Empty when no tests matched any manager.
	Manager string
	// Package is the package name owning Path, when resolved.
	Package string
	// FailedTests lists the test IDs (T1..T5) that did NOT pass.
	// Empty when Authentic is true.
	FailedTests []string
	// Reason is human-readable; goes into the audit record.
	Reason string
}

// Tester runs the T1-T5 authentication policy on a (writer, path) pair.
// Apt/dpkg today; rpm is a TODO follow-on.
type Tester struct {
	// pkgManagerAllowlist (T1): binary names accepted as legitimate
	// writers of system binaries. Path basename match.
	pkgManagerAllowlist map[string]string // basename → manager name

	// dpkgLockPath (T3): the file whose held flock indicates dpkg is
	// mid-transaction. Default /var/lib/dpkg/lock-frontend.
	dpkgLockPath string

	// dpkgInfoDir (T4): where .md5sums files live. Default
	// /var/lib/dpkg/info.
	dpkgInfoDir string
}

// NewTester returns a Tester with apt/dpkg defaults.
func NewTester() *Tester {
	return &Tester{
		pkgManagerAllowlist: map[string]string{
			// dpkg / apt suite (Ubuntu / Debian targets)
			"dpkg":               "dpkg",
			"dpkg-deb":           "dpkg",
			"dpkg-divert":        "dpkg",
			"dpkg-trigger":       "dpkg",
			"apt":                "dpkg",
			"apt-get":            "dpkg",
			"aptitude":           "dpkg",
			"unattended-upgrade": "dpkg",
			"update-rc.d":        "dpkg",
			// snap (Ubuntu)
			"snap":  "snap",
			"snapd": "snap",
			// rpm suite (follow-on; we record but don't yet enforce)
			"rpm":     "rpm",
			"yum":     "rpm",
			"dnf":     "rpm",
			"zypper":  "rpm",
		},
		dpkgLockPath: "/var/lib/dpkg/lock-frontend",
		dpkgInfoDir:  "/var/lib/dpkg/info",
	}
}

// Verify runs the T1-T5 policy for the writer process at writerPID
// having just written path. The new file's SHA-256 is sha (optional —
// T4 needs it; pass "" to skip T4).
//
// Returns AuthenticUpgradeVerdict.Authentic=true only if every
// applicable test passes. The tester is conservative: in any doubt,
// not authentic. The caller (B3 execve check) treats non-authentic
// as "trigger disarm".
func (t *Tester) Verify(writerPID uint32, path, sha string) AuthenticUpgradeVerdict {
	v := AuthenticUpgradeVerdict{}

	// T1: writer identity.
	writerExe := readProcExe(writerPID)
	manager, t1pass := t.testT1(writerExe)
	v.Manager = manager
	if !t1pass {
		v.FailedTests = append(v.FailedTests, "T1")
		v.Reason = fmt.Sprintf("T1: writer %q not in package-manager allowlist", filepath.Base(writerExe))
		return v
	}

	// T2: writer lineage. The writing process's parent chain should
	// trace to one of the package-manager drivers OR be the
	// package-manager itself (unattended-upgrades.service, an apt-get
	// invocation, dpkg directly from a shell). We accept either:
	//   (a) writer's own exe is in allowlist (already satisfied T1)
	//   (b) an ancestor in /proc/<pid>/cgroup mentions a known
	//       package-manager systemd unit.
	if !t.testT2(writerPID) {
		v.FailedTests = append(v.FailedTests, "T2")
		v.Reason = "T2: writer lineage doesn't trace to an authentic package-manager driver"
		return v
	}

	// T3: upgrade window — dpkg lock held. Only enforced for dpkg
	// transactions today; rpm/snap will get their own checks later.
	if manager == "dpkg" {
		if !t.testT3() {
			v.FailedTests = append(v.FailedTests, "T3")
			v.Reason = "T3: dpkg lock-frontend not held — write happened outside a package-manager transaction"
			return v
		}
	}

	// T4: SHA validation against package manifest. Only when caller
	// supplied a SHA AND we can resolve which package owns path.
	if sha != "" && manager == "dpkg" {
		pkg, pkgErr := t.resolveDpkgPackage(path)
		if pkgErr == nil && pkg != "" {
			v.Package = pkg
			ok, expectedMD5 := t.testT4(pkg, path)
			if !ok {
				v.FailedTests = append(v.FailedTests, "T4")
				v.Reason = fmt.Sprintf("T4: dpkg md5sums mismatch for %s in package %s (expected %s)",
					path, pkg, expectedMD5)
				return v
			}
		}
	}

	// T5: origin signature. Implementation-wise: dpkg verifies repo
	// keys at install time; we record that the install succeeded but
	// don't re-verify the keyring here. Treat T5 as advisory.
	v.Authentic = true
	v.Reason = fmt.Sprintf("authentic %s upgrade (writer=%s)", manager, filepath.Base(writerExe))
	return v
}

// testT1 is exported for tests; returns (manager, pass).
func (t *Tester) testT1(writerExe string) (string, bool) {
	if writerExe == "" {
		return "", false
	}
	base := filepath.Base(writerExe)
	mgr, ok := t.pkgManagerAllowlist[base]
	return mgr, ok
}

// testT2 reads /proc/<pid>/cgroup and accepts if any ancestor unit
// looks like a known package-manager driver. Also accepts when the
// writer's exe is itself in the allowlist (set covers the
// shell-runs-apt-get-runs-dpkg case via T1 anyway).
func (t *Tester) testT2(writerPID uint32) bool {
	if writerPID == 0 {
		return false
	}
	// /proc/<pid>/cgroup includes the slice/scope hierarchy. We accept
	// when any line contains a known package-manager unit name.
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", writerPID))
	if err != nil {
		return false
	}
	cg := string(data)
	for _, hint := range []string{
		"apt-daily", "unattended-upgrades",
		"snap.snapd", "snapd.service",
		// dpkg as-invoked-via-apt usually inherits apt-get's scope:
		"apt-get", "dpkg",
		// rpm equivalents (advisory)
		"dnf", "yum", "rpm",
	} {
		if strings.Contains(cg, hint) {
			return true
		}
	}
	// Fallback: walk the parent chain. If any ancestor exe is in the
	// allowlist, that's a legit driver too.
	cur := writerPID
	for depth := 0; depth < 8 && cur != 0; depth++ {
		exe := readProcExe(cur)
		if _, ok := t.pkgManagerAllowlist[filepath.Base(exe)]; ok {
			return true
		}
		ppid := readProcPPID(cur)
		if ppid == cur || ppid == 0 {
			break
		}
		cur = ppid
	}
	return false
}

// testT3 returns true when dpkg's lock-frontend is currently held.
// We can't tell *which* process holds it from userspace without
// /proc/locks parsing — so for v1 we just check that the lock file
// exists and is locked. False positives (concurrent transaction by
// a different invocation) are acceptable; better than denying every
// upgrade because we can't prove the writer's identity holds it.
func (t *Tester) testT3() bool {
	// /proc/locks lines look like:
	//   1: POSIX  ADVISORY  WRITE 12345 fd:01:1234 0 EOF
	data, err := os.ReadFile("/proc/locks")
	if err != nil {
		return false
	}
	st, err := os.Stat(t.dpkgLockPath)
	if err != nil {
		return false
	}
	sys, ok := st.Sys().(interface{ Ino() uint64 })
	if !ok {
		// stat_t on Linux exposes Ino as uint64 via Stat_t.Ino — but
		// the type assertion above is just defensive. Use the raw
		// approach instead.
		inode := statInode(st)
		return strings.Contains(string(data), fmt.Sprintf(":%x ", inode))
	}
	return strings.Contains(string(data), fmt.Sprintf(":%x ", sys.Ino()))
}

// resolveDpkgPackage finds which dpkg package owns path. Reads
// /var/lib/dpkg/info/<pkg>.list files and matches. We cache results
// per-process by using a small map; for v1, a fresh scan is fine
// because B3 only calls this on SHA mismatch.
func (t *Tester) resolveDpkgPackage(path string) (string, error) {
	entries, err := os.ReadDir(t.dpkgInfoDir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".list") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(t.dpkgInfoDir, n))
		if err != nil {
			continue
		}
		// .list is one path per line.
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == path {
				return strings.TrimSuffix(n, ".list"), nil
			}
		}
	}
	return "", errors.New("no dpkg package owns this path")
}

// testT4 verifies the file at path has the MD5 dpkg expects for it
// in the named package. Returns (ok, expectedMD5).
func (t *Tester) testT4(pkg, path string) (bool, string) {
	md5Path := filepath.Join(t.dpkgInfoDir, pkg+".md5sums")
	data, err := os.ReadFile(md5Path)
	if err != nil {
		return false, ""
	}
	// .md5sums lines: "<md5>  <path-without-leading-slash>"
	wantPath := strings.TrimPrefix(path, "/")
	var expected string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if fields[1] == wantPath {
			expected = fields[0]
			break
		}
	}
	if expected == "" {
		return false, ""
	}
	got, err := md5File(path)
	if err != nil {
		return false, expected
	}
	return got == expected, expected
}

func md5File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readProcExe returns /proc/<pid>/exe target or "" on any error.
func readProcExe(pid uint32) string {
	if pid == 0 {
		return ""
	}
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(link, " (deleted)")
}

// readProcPPID returns the parent PID from /proc/<pid>/status.
func readProcPPID(pid uint32) uint32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			var p uint32
			_, _ = fmt.Sscanf(line, "PPid:\t%d", &p)
			return p
		}
	}
	return 0
}

// Package serviceid resolves a running process to a registered
// ProtectedService. It's the hot-path entry to protected-service
// behavior — every relevant event (exec, connect, write, etc.) asks
// the matcher "is this process a protected service?" before
// deciding what policy applies.
//
// Two-stage match:
//
//  1. Fast path: lookup by cgroup_id via Cache (set on first match).
//     This is what runs per-event in steady state.
//  2. Slow path: build an Identity from /proc, then run the registry
//     match. Result is inserted into the cache.
//
// Per PROTECTED_SERVICES_TRAP.md §8, the matcher VERIFIES the
// identity on every match (exe SHA, unit, uid). A mismatch returns
// MatchVerdict.Discrepancy non-empty so the caller emits a
// SignalDefenseEvasion — that's how binary-swap attacks are caught.
package serviceid

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

// Matcher resolves Identities to ProtectedServices, caching by
// cgroup_id for speed.
type Matcher struct {
	Reg   *protectedsvc.Registry
	Cache *Cache

	// ReadCgroup reads /proc/<pid>/cgroup. Pluggable for tests.
	ReadCgroup func(pid uint32) (string, error)
	// ReadExe reads /proc/<pid>/exe (resolved). Pluggable for tests.
	ReadExe func(pid uint32) (string, error)
	// ReadUIDGID returns the effective uid/gid for the pid.
	ReadUIDGID func(pid uint32) (uint32, uint32, error)
	// HashFile returns the SHA-256 hex of a file. Pluggable so tests
	// don't have to write real binaries.
	HashFile func(path string) (string, error)
	// ReadUnit returns the systemd unit name for the pid (parsed
	// from /proc/PID/cgroup). Empty if unavailable.
	ReadUnit func(pid uint32) (string, error)
}

// New returns a Matcher with default /proc-based probes.
func New(reg *protectedsvc.Registry) *Matcher {
	return &Matcher{
		Reg:        reg,
		Cache:      NewCache(),
		ReadCgroup: defaultReadCgroup,
		ReadExe:    defaultReadExe,
		ReadUIDGID: defaultReadUIDGID,
		HashFile:   defaultHashFile,
		ReadUnit:   defaultReadUnit,
	}
}

// MatchPID resolves a pid to a verdict. Hot path — uses cgroup_id
// cache when available.
func (m *Matcher) MatchPID(pid uint32, cgroupID uint64) protectedsvc.MatchVerdict {
	if cgroupID != 0 {
		if name, ok := m.Cache.Get(cgroupID); ok {
			if name == "" {
				// Negative cache — known not-a-protected-service.
				return protectedsvc.MatchVerdict{}
			}
			svc := m.Reg.ByName(name)
			if svc != nil {
				return protectedsvc.MatchVerdict{Matched: true, Service: svc}
			}
			// Cache stale (config reload removed the service). Fall through.
			m.Cache.Forget(cgroupID)
		}
	}

	id, err := m.identify(pid)
	if err != nil {
		return protectedsvc.MatchVerdict{}
	}
	v := m.matchIdentity(id)
	if cgroupID != 0 {
		if v.Matched && v.Discrepancy == "" {
			m.Cache.Set(cgroupID, v.Service.Name)
		} else if !v.Matched {
			// Negative cache so non-matches don't re-walk /proc.
			m.Cache.Set(cgroupID, "")
		}
	}
	return v
}

// MatchIdentity is the verification path — takes a fully-populated
// Identity (e.g. from an event enrichment layer that already read
// /proc) and returns the verdict.
func (m *Matcher) MatchIdentity(id protectedsvc.Identity) protectedsvc.MatchVerdict {
	return m.matchIdentity(id)
}

func (m *Matcher) matchIdentity(id protectedsvc.Identity) protectedsvc.MatchVerdict {
	// Try cgroup prefix first (cheapest, most specific).
	if id.CGroup != "" {
		if svc := m.Reg.MatchCgroup(id.CGroup); svc != nil {
			return m.verify(svc, id)
		}
	}
	// Fall back to unit.
	if id.Unit != "" {
		for _, svc := range m.Reg.ByUnit(id.Unit) {
			// Among candidates, prefer the one whose ExecPath matches.
			if id.ExePath != "" && svc.ExecPath != "" && id.ExePath != svc.ExecPath {
				continue
			}
			return m.verify(svc, id)
		}
	}
	return protectedsvc.MatchVerdict{}
}

// verify runs identity checks against a candidate service and
// returns the verdict. A failed check populates Discrepancy
// (Matched still false — the caller is expected to treat
// Discrepancy as Tier-1 signal evidence).
func (m *Matcher) verify(svc *protectedsvc.ProtectedService, id protectedsvc.Identity) protectedsvc.MatchVerdict {
	if svc.ExecPath != "" && id.ExePath != "" && svc.ExecPath != id.ExePath {
		return protectedsvc.MatchVerdict{
			Service:     svc,
			Discrepancy: fmt.Sprintf("exec_path mismatch: want %q, got %q", svc.ExecPath, id.ExePath),
		}
	}
	if svc.ExeSHA256 != "" && id.ExeSHA256 != "" && !strings.EqualFold(svc.ExeSHA256, id.ExeSHA256) {
		return protectedsvc.MatchVerdict{
			Service:     svc,
			Discrepancy: fmt.Sprintf("exe_sha256 mismatch on %s", svc.Name),
		}
	}
	if svc.UID != nil && *svc.UID != id.UID {
		return protectedsvc.MatchVerdict{
			Service:     svc,
			Discrepancy: fmt.Sprintf("uid mismatch: want %d, got %d", *svc.UID, id.UID),
		}
	}
	if svc.GID != nil && *svc.GID != id.GID {
		return protectedsvc.MatchVerdict{
			Service:     svc,
			Discrepancy: fmt.Sprintf("gid mismatch: want %d, got %d", *svc.GID, id.GID),
		}
	}
	return protectedsvc.MatchVerdict{Matched: true, Service: svc}
}

// identify reads /proc for the given pid and assembles an Identity.
// Returns error only on read failures the caller can't recover from
// (e.g. process gone); missing optional fields are left zero.
func (m *Matcher) identify(pid uint32) (protectedsvc.Identity, error) {
	id := protectedsvc.Identity{PID: pid}

	if uid, gid, err := m.ReadUIDGID(pid); err == nil {
		id.UID, id.GID = uid, gid
	} else if pid != 0 {
		return id, fmt.Errorf("identify uid/gid for pid %d: %w", pid, err)
	}

	if exe, err := m.ReadExe(pid); err == nil {
		id.ExePath = exe
		// Only hash when the registry actually has a SHA to compare
		// against — saves a read on most processes.
		if needsHash(m.Reg, exe) {
			if h, err := m.HashFile(exe); err == nil {
				id.ExeSHA256 = h
			}
		}
	}

	if cg, err := m.ReadCgroup(pid); err == nil {
		id.CGroup = cg
	}
	if u, err := m.ReadUnit(pid); err == nil {
		id.Unit = u
	}
	return id, nil
}

// needsHash returns true if any registered service references this
// exe path and declares an expected SHA-256. Avoids hashing every
// random binary on every process event.
func needsHash(reg *protectedsvc.Registry, exe string) bool {
	if reg == nil {
		return false
	}
	for _, s := range reg.All() {
		if s.ExecPath == exe && s.ExeSHA256 != "" {
			return true
		}
	}
	return false
}

// --- default /proc probes ---

func defaultReadCgroup(pid uint32) (string, error) {
	if pid == 0 {
		return "", errors.New("invalid pid 0")
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	// cgroup v2: a single "0::/path" line. v1 has multiple controllers.
	// We want the unified path; fall back to the first non-empty path.
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for _, ln := range lines {
		// Each line: "<hierarchy_id>:<controllers>:<path>"
		parts := strings.SplitN(ln, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" { // cgroup v2 unified
			return parts[2], nil
		}
	}
	for _, ln := range lines {
		parts := strings.SplitN(ln, ":", 3)
		if len(parts) == 3 && parts[2] != "" && parts[2] != "/" {
			return parts[2], nil
		}
	}
	return "", errors.New("no cgroup path")
}

func defaultReadExe(pid uint32) (string, error) {
	if pid == 0 {
		return "", errors.New("invalid pid 0")
	}
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}

func defaultReadUIDGID(pid uint32) (uint32, uint32, error) {
	if pid == 0 {
		return 0, 0, errors.New("invalid pid 0")
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, err
	}
	var uid, gid uint32
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "Uid:") {
			// "Uid:\treal\teffective\tsaved\tfilesystem"
			fields := strings.Fields(ln)
			if len(fields) >= 3 {
				var u uint32
				fmt.Sscanf(fields[2], "%d", &u)
				uid = u
			}
		} else if strings.HasPrefix(ln, "Gid:") {
			fields := strings.Fields(ln)
			if len(fields) >= 3 {
				var g uint32
				fmt.Sscanf(fields[2], "%d", &g)
				gid = g
			}
		}
	}
	return uid, gid, nil
}

func defaultHashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// defaultReadUnit parses the systemd unit from /proc/PID/cgroup.
// Looks for ".../system.slice/<unit-name>" or similar pattern.
func defaultReadUnit(pid uint32) (string, error) {
	cg, err := defaultReadCgroup(pid)
	if err != nil {
		return "", err
	}
	// systemd cgroup names end with the unit: ".../<unit>.service"
	// or ".../<unit>.scope".
	base := filepath.Base(cg)
	if strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".scope") {
		return base, nil
	}
	// Walk back up the path looking for the first ancestor that's a unit.
	for cg != "" && cg != "/" && cg != "." {
		base = filepath.Base(cg)
		if strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".scope") {
			return base, nil
		}
		cg = filepath.Dir(cg)
	}
	return "", nil
}

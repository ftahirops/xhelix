// Package auditwatch monitors the Linux audit framework state:
//   - auditd is still the process owning the audit socket
//   - audit rule files in /etc/audit/rules.d hash-match baseline
//   - /etc/audit/auditd.conf hashes match baseline
//
// Disabling auditd or flushing rules is a top anti-forensics move.
// The package is pure: snapshot + diff. Filesystem reads happen in
// Snap; Compare is pure data manipulation.
package auditwatch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// State is a snapshot of the audit framework configuration.
type State struct {
	// AuditdRunning is true iff /var/run/auditd.pid (or whichever
	// pid file is configured) exists AND points at a /proc entry
	// whose comm is auditd.
	AuditdRunning bool

	// AuditdPID is the audit daemon's pid, 0 if not running.
	AuditdPID uint32

	// RuleFiles maps /etc/audit/rules.d/*.rules paths to SHA-256.
	RuleFiles map[string]string

	// AuditRulesHash is the SHA-256 of /etc/audit/audit.rules
	// (the flat rules file written by augenrules). Empty if absent.
	AuditRulesHash string

	// ConfHash is the SHA-256 of /etc/audit/auditd.conf.
	ConfHash string
}

// Diff describes how a current State differs from a baseline.
type Diff struct {
	AuditdStopped   bool   // baseline running, current not
	AuditdRestarted bool   // running but different pid (informational)
	RulesAdded      []string
	RulesRemoved    []string
	RulesModified   []string // paths whose hash changed
	AuditRulesChanged bool
	ConfChanged     bool
}

// IsEmpty reports whether the diff is fully empty.
func (d Diff) IsEmpty() bool {
	return !d.AuditdStopped && !d.AuditdRestarted &&
		len(d.RulesAdded) == 0 && len(d.RulesRemoved) == 0 && len(d.RulesModified) == 0 &&
		!d.AuditRulesChanged && !d.ConfChanged
}

// HasCritical returns true for any change that materially weakens
// the audit framework (daemon down or rules removed/modified).
func (d Diff) HasCritical() bool {
	return d.AuditdStopped || len(d.RulesRemoved) > 0 ||
		len(d.RulesModified) > 0 || d.AuditRulesChanged
}

// Config controls Snap.
type Config struct {
	// ProcRoot is /proc. Defaults to "/proc".
	ProcRoot string
	// PIDFile is the auditd pid path. Defaults to "/var/run/auditd.pid".
	PIDFile string
	// RulesDir is the audit.rules.d directory.
	RulesDir string
	// AuditRulesPath is the compiled audit.rules path.
	AuditRulesPath string
	// ConfPath is the auditd.conf path.
	ConfPath string
}

// DefaultConfig returns sane defaults.
func DefaultConfig() Config {
	return Config{
		ProcRoot:       "/proc",
		PIDFile:        "/var/run/auditd.pid",
		RulesDir:       "/etc/audit/rules.d",
		AuditRulesPath: "/etc/audit/audit.rules",
		ConfPath:       "/etc/audit/auditd.conf",
	}
}

// Snap reads the current state.
func Snap(cfg Config) (State, error) {
	if cfg.ProcRoot == "" {
		cfg = mergeWithDefaults(cfg)
	}
	s := State{RuleFiles: map[string]string{}}

	if pid, ok := readAuditdPID(cfg); ok {
		s.AuditdPID = pid
		s.AuditdRunning = pidIsAuditd(cfg.ProcRoot, pid)
	}

	if err := filepath.WalkDir(cfg.RulesDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".rules") {
			return nil
		}
		if h := hashFile(p); h != "" {
			s.RuleFiles[p] = h
		}
		return nil
	}); err != nil && !errors.Is(err, fs.ErrNotExist) {
		// Non-fatal: a host without auditd installed has no rules.d.
	}

	if h := hashFile(cfg.AuditRulesPath); h != "" {
		s.AuditRulesHash = h
	}
	if h := hashFile(cfg.ConfPath); h != "" {
		s.ConfHash = h
	}
	return s, nil
}

// Compare returns the diff.
func Compare(base, cur State) Diff {
	var d Diff
	if base.AuditdRunning && !cur.AuditdRunning {
		d.AuditdStopped = true
	}
	if base.AuditdRunning && cur.AuditdRunning && base.AuditdPID != cur.AuditdPID {
		d.AuditdRestarted = true
	}

	for path, h := range cur.RuleFiles {
		bh, ok := base.RuleFiles[path]
		if !ok {
			d.RulesAdded = append(d.RulesAdded, path)
			continue
		}
		if bh != h {
			d.RulesModified = append(d.RulesModified, path)
		}
	}
	for path := range base.RuleFiles {
		if _, ok := cur.RuleFiles[path]; !ok {
			d.RulesRemoved = append(d.RulesRemoved, path)
		}
	}
	sort.Strings(d.RulesAdded)
	sort.Strings(d.RulesRemoved)
	sort.Strings(d.RulesModified)

	if base.AuditRulesHash != "" && base.AuditRulesHash != cur.AuditRulesHash {
		d.AuditRulesChanged = true
	}
	if base.ConfHash != "" && base.ConfHash != cur.ConfHash {
		d.ConfChanged = true
	}
	return d
}

// ── helpers ────────────────────────────────────────────────────

func mergeWithDefaults(cfg Config) Config {
	d := DefaultConfig()
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = d.ProcRoot
	}
	if cfg.PIDFile == "" {
		cfg.PIDFile = d.PIDFile
	}
	if cfg.RulesDir == "" {
		cfg.RulesDir = d.RulesDir
	}
	if cfg.AuditRulesPath == "" {
		cfg.AuditRulesPath = d.AuditRulesPath
	}
	if cfg.ConfPath == "" {
		cfg.ConfPath = d.ConfPath
	}
	return cfg
}

func readAuditdPID(cfg Config) (uint32, bool) {
	b, err := os.ReadFile(cfg.PIDFile)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

func pidIsAuditd(procRoot string, pid uint32) bool {
	b, err := os.ReadFile(procRoot + "/" + strconv.FormatUint(uint64(pid), 10) + "/comm")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "auditd"
}

func hashFile(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

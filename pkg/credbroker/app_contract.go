package credbroker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// AppContract is the Layer-2 contract for one application. Lives at
// /etc/xhelix/contracts.d/<name>.yaml and is shipped by the developer
// alongside their app deployment.
//
// Layer-1 (DefaultContract in contract.go) is image-regex + class —
// it covers default CLI binaries (aws, gcloud, kubectl, ...) on every
// host with no config.
//
// Layer-2 (this file) is path-anchored + binary-pinned. It says
// "binary X is allowed to open these specific sealed files." Once an
// AppContract claims a sealed path, only callers matching that
// contract can open it — even Layer-1 image-regex defaults are
// overridden for that file.
//
// Universal-by-construction: the contract describes the app, not the
// host. The same /etc/xhelix/contracts.d/my-app.yaml deployed on any
// machine produces the same authentication result.
type AppContract struct {
	// Name is the operator-visible identifier (filename stem).
	Name string `yaml:"-"`

	// Binary is the absolute path of the executable. The runtime
	// /proc/<pid>/exe link must exactly match (after stripping
	// " (deleted)").
	Binary string `yaml:"binary"`

	// SHA256Pin, if set, must match the SHA-256 of the binary file
	// on disk. Empty = TOFU (trust on first sight) — strong if the
	// host's autobaseline has already observed the binary.
	SHA256Pin string `yaml:"sha256_pin,omitempty"`

	// ParentShape is an OR list. One of:
	//   "systemd:<unit>"     ancestor cgroup contains <unit>.service
	//   "interactive_shell"  ancestor is bash/zsh/sh with a tty
	//   "cron"               ancestor is cron/crond
	//   "sshd"               ancestor is sshd (interactive remote)
	// Empty = no parent-shape requirement.
	ParentShape []string `yaml:"parent_shape,omitempty"`

	// AllowedCredentials is the absolute paths of sealed files this
	// binary may open. Match is exact (after lex-clean).
	AllowedCredentials []string `yaml:"allowed_credentials"`

	// Purpose is human-readable; not used in the decision, only audit.
	Purpose string `yaml:"purpose,omitempty"`

	// MaxOpensPerMin caps how many times this contract may authorise
	// an open in any 60-second window. Zero = no cap. Blunts a
	// hijacked-but-authentic process exfiltrating in a tight loop.
	MaxOpensPerMin int `yaml:"max_opens_per_min,omitempty"`
}

// AppContractSet is the loaded collection of Layer-2 contracts,
// indexed by sealed-file path for O(1) lookup.
type AppContractSet struct {
	mu        sync.RWMutex
	contracts []*AppContract
	byPath    map[string][]*AppContract // sealed-path → contracts authorising it

	// rate limiter state: (binaryPath + sealedPath) → recent opens
	rlMu sync.Mutex
	rl   map[string][]time.Time
}

// NewAppContractSet returns an empty set.
func NewAppContractSet() *AppContractSet {
	return &AppContractSet{
		byPath: map[string][]*AppContract{},
		rl:     map[string][]time.Time{},
	}
}

// LoadAppContractsDir reads every *.yaml under dir and merges them
// into a set. Missing dir is not an error (returns empty set).
// Per-file parse errors are collected and returned alongside the
// successfully-loaded set — the daemon should log them but boot.
func LoadAppContractsDir(dir string) (*AppContractSet, []error) {
	set := NewAppContractSet()
	var errs []error
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return set, nil
		}
		return set, []error{fmt.Errorf("read %s: %w", dir, err)}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".yaml") && !strings.HasSuffix(n, ".yml") {
			continue
		}
		path := filepath.Join(dir, n)
		c, err := loadAppContractFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		c.Name = strings.TrimSuffix(strings.TrimSuffix(n, ".yaml"), ".yml")
		set.add(c)
	}
	return set, errs
}

func loadAppContractFile(path string) (*AppContract, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c AppContract
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Binary == "" {
		return nil, fmt.Errorf("%s: missing required field: binary", path)
	}
	if len(c.AllowedCredentials) == 0 {
		return nil, fmt.Errorf("%s: allowed_credentials must list at least one path", path)
	}
	// Normalise paths.
	c.Binary = filepath.Clean(c.Binary)
	for i := range c.AllowedCredentials {
		c.AllowedCredentials[i] = filepath.Clean(c.AllowedCredentials[i])
	}
	return &c, nil
}

func (s *AppContractSet) add(c *AppContract) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contracts = append(s.contracts, c)
	for _, p := range c.AllowedCredentials {
		s.byPath[p] = append(s.byPath[p], c)
	}
}

// HasContractFor reports whether any AppContract claims sealedPath.
// When true, only matching contracts can authorise — Layer-1 image-
// regex fallback is disabled for this path.
func (s *AppContractSet) HasContractFor(sealedPath string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.byPath[filepath.Clean(sealedPath)]
	return ok
}

// MatchResult2 is the outcome of an AppContract match.
type MatchResult2 struct {
	Matched      bool
	ContractName string
	// Reason explains denial when Matched==false; explains the match
	// when Matched==true (audit).
	Reason string
}

// Match returns whether any AppContract authorises (lineage, sealedPath).
// Authentic = binary path matches the head of lineage, SHA pin matches
// (if pinned), parent shape matches (if required), rate limit not
// exceeded.
func (s *AppContractSet) Match(lineage []LineageNode, sealedPath string, now time.Time) MatchResult2 {
	if s == nil || len(lineage) == 0 {
		return MatchResult2{Reason: "no lineage"}
	}
	sealedPath = filepath.Clean(sealedPath)
	s.mu.RLock()
	candidates := s.byPath[sealedPath]
	s.mu.RUnlock()
	if len(candidates) == 0 {
		return MatchResult2{Reason: "no Layer-2 contract claims this path"}
	}
	head := lineage[0]
	for _, c := range candidates {
		if c.Binary != head.Image {
			continue
		}
		if c.SHA256Pin != "" {
			if !sha256Matches(head.Image, c.SHA256Pin) {
				return MatchResult2{
					Reason: fmt.Sprintf("contract %s: sha256_pin mismatch", c.Name),
				}
			}
		}
		if len(c.ParentShape) > 0 {
			if !parentShapeMatches(lineage, c.ParentShape) {
				return MatchResult2{
					Reason: fmt.Sprintf("contract %s: parent_shape mismatch", c.Name),
				}
			}
		}
		if c.MaxOpensPerMin > 0 {
			if !s.rateLimitAllow(c.Binary, sealedPath, c.MaxOpensPerMin, now) {
				return MatchResult2{
					Reason: fmt.Sprintf("contract %s: rate cap exceeded (>%d/min)",
						c.Name, c.MaxOpensPerMin),
				}
			}
		}
		return MatchResult2{
			Matched:      true,
			ContractName: c.Name,
			Reason:       fmt.Sprintf("Layer-2 contract %s authorised", c.Name),
		}
	}
	return MatchResult2{
		Reason: fmt.Sprintf("no Layer-2 contract matches binary %s for %s",
			head.Image, sealedPath),
	}
}

// rateLimitAllow returns true if the (binary, sealedPath) is under
// its per-minute cap, and records this open. Must be called only
// when the rest of the decision authorises — we don't want to count
// denied attempts against legit usage.
func (s *AppContractSet) rateLimitAllow(binary, sealedPath string, capPerMin int, now time.Time) bool {
	key := binary + "\x00" + sealedPath
	cutoff := now.Add(-60 * time.Second)
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	old := s.rl[key]
	pruned := old[:0]
	for _, t := range old {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	if len(pruned) >= capPerMin {
		s.rl[key] = pruned
		return false
	}
	s.rl[key] = append(pruned, now)
	return true
}

// parentShapeMatches checks if any ancestor in lineage satisfies any
// shape in shapes. OR semantics: one match is enough.
func parentShapeMatches(lineage []LineageNode, shapes []string) bool {
	for _, shape := range shapes {
		if oneShapeMatches(lineage, shape) {
			return true
		}
	}
	return false
}

func oneShapeMatches(lineage []LineageNode, shape string) bool {
	switch {
	case strings.HasPrefix(shape, "systemd:"):
		unit := strings.TrimPrefix(shape, "systemd:")
		return ancestorInUnit(lineage[0].PID, unit)
	case shape == "interactive_shell":
		for _, n := range lineage[1:] {
			if isShell(n.Comm) && hasTTY(n.PID) {
				return true
			}
		}
		return false
	case shape == "cron":
		for _, n := range lineage[1:] {
			if n.Comm == "cron" || n.Comm == "crond" {
				return true
			}
		}
		return false
	case shape == "sshd":
		for _, n := range lineage[1:] {
			if n.Comm == "sshd" {
				return true
			}
		}
		return false
	}
	return false
}

func isShell(comm string) bool {
	switch comm {
	case "bash", "zsh", "sh", "dash", "fish", "ksh":
		return true
	}
	return false
}

// ancestorInUnit walks /proc/<pid>/cgroup looking for a systemd unit
// of the given name. Best-effort; non-Linux returns false (see
// app_contract_other.go for stub).
func ancestorInUnit(pid uint32, unit string) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false
	}
	// Match both "<unit>.service" and "<unit>" forms.
	needle := unit
	if !strings.Contains(unit, ".") {
		needle = unit + ".service"
	}
	return strings.Contains(string(data), needle)
}

func hasTTY(pid uint32) bool {
	// /proc/<pid>/stat field 7 is the controlling tty (0 if none).
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s := string(data)
	// stat format has the comm in parens; find the closing paren
	// then split the rest.
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return false
	}
	fields := strings.Fields(s[i+1:])
	// After the closing paren we have: state ppid pgrp session tty_nr
	if len(fields) < 5 {
		return false
	}
	return fields[4] != "0"
}

// sha256Matches hashes the file at path and compares to hex pin.
// Result is cached by (path, inode, mtime) to avoid re-hashing on
// every open. False on any error so attackers can't bypass via races.
var (
	shaCacheMu sync.RWMutex
	shaCache   = map[string]shaCacheEntry{}
)

type shaCacheEntry struct {
	inode uint64
	mtime time.Time
	hash  string
}

func sha256Matches(path, pin string) bool {
	pinLow := strings.ToLower(strings.TrimSpace(pin))
	if h, ok := lookupShaCache(path); ok {
		return h == pinLow
	}
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	got := hex.EncodeToString(h.Sum(nil))
	storeShaCache(path, st, got)
	return got == pinLow
}

func lookupShaCache(path string) (string, bool) {
	shaCacheMu.RLock()
	e, ok := shaCache[path]
	shaCacheMu.RUnlock()
	if !ok {
		return "", false
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	ino, mtime, ok := statSig(st)
	if !ok || ino != e.inode || !mtime.Equal(e.mtime) {
		return "", false
	}
	return e.hash, true
}

func storeShaCache(path string, st os.FileInfo, hash string) {
	ino, mtime, ok := statSig(st)
	if !ok {
		return
	}
	shaCacheMu.Lock()
	shaCache[path] = shaCacheEntry{inode: ino, mtime: mtime, hash: hash}
	shaCacheMu.Unlock()
}

// Contracts returns a snapshot of loaded contracts (audit/CLI use).
func (s *AppContractSet) Contracts() []*AppContract {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*AppContract, len(s.contracts))
	copy(out, s.contracts)
	return out
}

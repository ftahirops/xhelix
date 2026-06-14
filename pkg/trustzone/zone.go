// Package trustzone implements operator-assigned per-subject (cgroup,
// uid, comm) trust labels. The egress decision engine consults zones
// when no per-binary policy applies, giving operators a blunt control
// surface like Qubes' color-coded VM zones.
//
// Zones are stored at /etc/xhelix/trustzones.yaml — a single file
// the operator hand-edits (or modifies via REST/CLI). Reload-on-tick
// every 30s; signature optional in v1.
//
// Default behavior is intentionally inert: a fresh deployment loads
// with default_label=trusted and zero assignments, which the Decide
// matrix maps to ZoneAllow for every destination class. The operator
// opts subjects into restricted/untrusted/tor_only one at a time as
// they audit their host — no traffic changes the moment the feature
// is enabled.
package trustzone

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Label is the zone name. Built-in semantics for the four canonical
// labels; operator can define custom labels for organization, but the
// default Matrix only recognises the four below — unknown labels fall
// through to ZoneAllow.
type Label string

const (
	LabelTrusted    Label = "trusted"    // default — no extra restriction
	LabelRestricted Label = "restricted" // can only reach observed-during-trusted destinations
	LabelUntrusted  Label = "untrusted"  // can only reach explicitly declared peers
	LabelTorOnly    Label = "tor_only"   // must use Tor SOCKS proxy
)

// Assignment binds a subject identity to a label. Exactly one of UID
// / CGroupUnit / CGroupClass / Comm should be set; the first matching
// Assignment wins in Lookup so the operator orders most-specific first.
type Assignment struct {
	UID         *uint32 `yaml:"uid,omitempty"          json:"uid,omitempty"`
	CGroupUnit  string  `yaml:"cgroup_unit,omitempty"  json:"cgroup_unit,omitempty"`
	CGroupClass string  `yaml:"cgroup_class,omitempty" json:"cgroup_class,omitempty"`
	Comm        string  `yaml:"comm,omitempty"         json:"comm,omitempty"`
	Label       Label   `yaml:"label"                  json:"label"`
	Comment     string  `yaml:"comment,omitempty"      json:"comment,omitempty"`
}

// Config is the YAML structure at /etc/xhelix/trustzones.yaml.
type Config struct {
	DefaultLabel Label        `yaml:"default_label"`
	Assignments  []Assignment `yaml:"assignments"`
}

// Subject is the input to Lookup — populated by pipeline from the event.
type Subject struct {
	UID         uint32
	CGroupUnit  string
	CGroupClass string
	Comm        string
}

// Manager owns the loaded zone assignments and answers lookups. All
// methods are goroutine-safe; Lookup uses RLock so the hot path doesn't
// serialize.
type Manager struct {
	mu          sync.RWMutex
	defaultLbl  Label
	assignments []Assignment
	path        string
}

// New creates an empty Manager. Call Reload to populate from disk.
func New(path string, defaultLabel Label) *Manager {
	if defaultLabel == "" {
		defaultLabel = LabelTrusted
	}
	return &Manager{
		defaultLbl: defaultLabel,
		path:       path,
	}
}

// Reload re-reads the YAML. Returns assignment count + first error.
// Missing file is NOT an error — fresh deployments start empty and
// the manager keeps its current in-memory state if the file vanishes.
func (m *Manager) Reload() (int, error) {
	if m == nil {
		return 0, errors.New("nil manager")
	}
	data, err := os.ReadFile(m.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			m.mu.Lock()
			m.assignments = nil
			m.mu.Unlock()
			return 0, err
		}
		return 0, err
	}
	var cfg Config
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return 0, fmt.Errorf("trustzone: parse %s: %w", m.path, err)
		}
	}
	m.mu.Lock()
	if cfg.DefaultLabel != "" {
		m.defaultLbl = cfg.DefaultLabel
	}
	m.assignments = cfg.Assignments
	n := len(m.assignments)
	m.mu.Unlock()
	return n, nil
}

// Default returns the current default label.
func (m *Manager) Default() Label {
	if m == nil {
		return LabelTrusted
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defaultLbl
}

// Lookup returns the label for a Subject. First matching Assignment
// wins (operator orders most-specific first). Falls back to defaultLbl.
func (m *Manager) Lookup(s Subject) Label {
	if m == nil {
		return LabelTrusted
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.assignments {
		if assignmentMatches(a, s) {
			return a.Label
		}
	}
	return m.defaultLbl
}

// assignmentMatches returns true when the Assignment selectors all
// match s. An empty Assignment (no selectors) never matches — that
// shape would silently relabel every subject on the host, which the
// operator almost never wants.
func assignmentMatches(a Assignment, s Subject) bool {
	any := false
	if a.UID != nil {
		any = true
		if *a.UID != s.UID {
			return false
		}
	}
	if a.CGroupUnit != "" {
		any = true
		if a.CGroupUnit != s.CGroupUnit {
			return false
		}
	}
	if a.CGroupClass != "" {
		any = true
		if a.CGroupClass != s.CGroupClass {
			return false
		}
	}
	if a.Comm != "" {
		any = true
		if a.Comm != s.Comm {
			return false
		}
	}
	return any
}

// All returns a snapshot of assignments for review.
func (m *Manager) All() []Assignment {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Assignment, len(m.assignments))
	copy(out, m.assignments)
	return out
}

// Add appends an assignment and persists to disk.
func (m *Manager) Add(a Assignment) error {
	if m == nil {
		return errors.New("nil manager")
	}
	if a.Label == "" {
		return errors.New("trustzone: label required")
	}
	m.mu.Lock()
	m.assignments = append(m.assignments, a)
	m.mu.Unlock()
	return m.persist()
}

// Remove deletes the n-th assignment (0-indexed).
func (m *Manager) Remove(index int) error {
	if m == nil {
		return errors.New("nil manager")
	}
	m.mu.Lock()
	if index < 0 || index >= len(m.assignments) {
		m.mu.Unlock()
		return fmt.Errorf("trustzone: index %d out of range [0,%d)", index, len(m.assignments))
	}
	m.assignments = append(m.assignments[:index], m.assignments[index+1:]...)
	m.mu.Unlock()
	return m.persist()
}

// SetDefault changes the default label and persists.
func (m *Manager) SetDefault(l Label) error {
	if m == nil {
		return errors.New("nil manager")
	}
	if l == "" {
		return errors.New("trustzone: empty label")
	}
	m.mu.Lock()
	m.defaultLbl = l
	m.mu.Unlock()
	return m.persist()
}

// persist writes the current state to disk atomically (tmpfile + rename).
// Caller must NOT hold m.mu when calling — this method takes RLock.
func (m *Manager) persist() error {
	m.mu.RLock()
	cfg := Config{
		DefaultLabel: m.defaultLbl,
		Assignments:  append([]Assignment(nil), m.assignments...),
	}
	m.mu.RUnlock()
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

// StartWatcher kicks off a periodic re-scan of the zone file. Returns
// a stop func; safe to call on a nil Manager. Reloads every 30s; logs
// nothing here (caller can wrap with logging). Errors are swallowed —
// the daemon keeps the previous good state.
func (m *Manager) StartWatcher(ctx context.Context) func() {
	if m == nil {
		return func() {}
	}
	sub, cancel := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-sub.Done():
				return
			case <-t.C:
				_, _ = m.Reload()
			}
		}
	}()
	return cancel
}

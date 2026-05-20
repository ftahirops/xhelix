package protectedsvc

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Registry holds the configured ProtectedServices for the running
// daemon. Thread-safe. Mutation is operator-driven (config reload);
// reads happen on every protected-service event.
type Registry struct {
	mu       sync.RWMutex
	byName   map[string]*ProtectedService
	byUnit   map[string][]*ProtectedService // multiple services can share a unit
	byPrefix []*ProtectedService             // sorted longest-prefix-first for cgroup match
}

// NewRegistry returns an empty Registry. Use Load() to populate.
func NewRegistry() *Registry {
	return &Registry{
		byName: map[string]*ProtectedService{},
		byUnit: map[string][]*ProtectedService{},
	}
}

// Load replaces the registry contents with svcs. Returns the first
// validation error; on error the previous contents are preserved.
func (r *Registry) Load(svcs []ProtectedService) error {
	if err := validate(svcs); err != nil {
		return err
	}

	byName := make(map[string]*ProtectedService, len(svcs))
	byUnit := map[string][]*ProtectedService{}
	prefix := make([]*ProtectedService, 0, len(svcs))

	for i := range svcs {
		s := &svcs[i]
		byName[s.Name] = s
		if s.Unit != "" {
			byUnit[s.Unit] = append(byUnit[s.Unit], s)
		}
		if s.CgroupPrefix != "" {
			prefix = append(prefix, s)
		}
	}

	// Longest prefix first so nested cgroups resolve to the inner-most
	// matching service.
	sortByPrefixDesc(prefix)

	r.mu.Lock()
	r.byName = byName
	r.byUnit = byUnit
	r.byPrefix = prefix
	r.mu.Unlock()
	return nil
}

// ByName returns the service with the given name, or nil.
func (r *Registry) ByName(name string) *ProtectedService {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byName[name]
}

// ByUnit returns every service tagged with the given systemd unit.
func (r *Registry) ByUnit(unit string) []*ProtectedService {
	r.mu.RLock()
	defer r.mu.RUnlock()
	src := r.byUnit[unit]
	if src == nil {
		return nil
	}
	out := make([]*ProtectedService, len(src))
	copy(out, src)
	return out
}

// MatchCgroup returns the service whose CgroupPrefix matches the
// longest prefix of the given cgroup path. nil if no match.
func (r *Registry) MatchCgroup(cgroup string) *ProtectedService {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.byPrefix {
		if strings.HasPrefix(cgroup, s.CgroupPrefix) {
			return s
		}
	}
	return nil
}

// All returns a snapshot of every registered service.
func (r *Registry) All() []*ProtectedService {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*ProtectedService, 0, len(r.byName))
	for _, s := range r.byName {
		out = append(out, s)
	}
	return out
}

// Count returns the number of registered services.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byName)
}

// --- validation ---

func validate(svcs []ProtectedService) error {
	seen := map[string]struct{}{}
	for i, s := range svcs {
		if s.Name == "" {
			return fmt.Errorf("protectedsvc[%d]: name is required", i)
		}
		if _, dup := seen[s.Name]; dup {
			return fmt.Errorf("protectedsvc: duplicate name %q", s.Name)
		}
		seen[s.Name] = struct{}{}

		if !validKind(s.Kind) {
			return fmt.Errorf("protectedsvc %q: unknown kind %q", s.Name, s.Kind)
		}
		if !validRole(s.Role) {
			return fmt.Errorf("protectedsvc %q: unknown role %q", s.Name, s.Role)
		}
		if s.ExecPath == "" {
			return fmt.Errorf("protectedsvc %q: exec_path is required", s.Name)
		}
		if s.ExeSHA256 != "" && len(s.ExeSHA256) != 64 {
			return fmt.Errorf("protectedsvc %q: exe_sha256 must be 64 hex chars", s.Name)
		}
		if s.CgroupPrefix == "" && s.Unit == "" {
			return fmt.Errorf("protectedsvc %q: at least one of cgroup_prefix or unit required", s.Name)
		}
	}
	return nil
}

func validKind(k ServiceKind) bool {
	for _, x := range AllKinds() {
		if k == x {
			return true
		}
	}
	return false
}

func validRole(r ServiceRole) bool {
	for _, x := range AllRoles() {
		if r == x {
			return true
		}
	}
	return false
}

// sortByPrefixDesc sorts in-place by len(CgroupPrefix) descending so
// the longest match wins. Simple insertion sort — registry sizes are
// tiny (handful of services per host).
func sortByPrefixDesc(svcs []*ProtectedService) {
	for i := 1; i < len(svcs); i++ {
		for j := i; j > 0 && len(svcs[j-1].CgroupPrefix) < len(svcs[j].CgroupPrefix); j-- {
			svcs[j-1], svcs[j] = svcs[j], svcs[j-1]
		}
	}
}

// ErrNotFound is returned when a lookup misses (kept for callers that
// want to distinguish nil-because-missing from nil-because-error).
var ErrNotFound = errors.New("protectedsvc: not found")

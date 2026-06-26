// Package systemdroot tracks a per-systemd-unit lineage root so processes
// running under a service unit get a non-admin (RootSystemd) causal root and
// their workflows can become learnable. It is the "B" slice of the Root
// Emitters work (docs/ROOT_EMITTERS_SCOPE.md).
//
// The minting + proctree attribution is done by the pipeline (it needs the
// SourceMinter + ProcTree); this package owns only the per-unit id cache and
// the "is this a real service unit?" decision, so both are pure + testable.
package systemdroot

import (
	"strings"
	"sync"

	"github.com/xhelix/xhelix/pkg/lineage"
)

// Tracker caches one lineage root id per systemd unit. Safe for the single
// dispatch goroutine; guarded anyway so a future caller can't race it.
type Tracker struct {
	mu    sync.Mutex
	units map[string]lineage.LineageID
}

// New returns an empty Tracker.
func New() *Tracker { return &Tracker{units: map[string]lineage.LineageID{}} }

// Get returns the cached root id for unit and whether one exists.
func (t *Tracker) Get(unit string) (lineage.LineageID, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	id, ok := t.units[unit]
	return id, ok
}

// Put caches the root id for unit (called after the pipeline mints it once).
func (t *Tracker) Put(unit string, id lineage.LineageID) {
	t.mu.Lock()
	t.units[unit] = id
	t.mu.Unlock()
}

// IsServiceUnit reports whether a cgroup unit name is a real service whose
// processes should carry a systemd root. Only "*.service" qualifies — slices,
// scopes, mounts, the user/session manager (user@.service) and transient
// run-* units are excluded so we don't root interactive/admin or scaffolding
// cgroups (those are admin noise, scope-lock §4).
func IsServiceUnit(unit string) bool {
	if !strings.HasSuffix(unit, ".service") {
		return false
	}
	// user@<uid>.service is the per-user systemd manager — its subtree is
	// interactive user sessions, which are admin noise, not a service workload.
	if strings.HasPrefix(unit, "user@") {
		return false
	}
	// systemd's own transient run-rXXXX.service scaffolding.
	if strings.HasPrefix(unit, "run-r") {
		return false
	}
	return true
}

// Package containerroot tracks a per-container lineage root so processes
// running inside a container payload cgroup get a non-admin (RootContainer)
// causal root and their workflows can become learnable/lockable. It is the
// container slice of the Root Emitters work — the direct analogue of
// systemdroot for Dockerised / containerd workloads (e.g. a Dockerised
// WordPress stack where php-fpm runs inside a container, not as a host unit).
//
// The minting + proctree attribution is done by the pipeline (it needs the
// SourceMinter + ProcTree); this package owns only the per-container id cache
// and the "is this a real container id?" decision, so both are pure + testable.
package containerroot

import (
	"sync"

	"github.com/xhelix/xhelix/pkg/lineage"
)

// Tracker caches one lineage root id per container id. Safe for the single
// dispatch goroutine; guarded anyway so a future caller can't race it.
type Tracker struct {
	mu         sync.Mutex
	containers map[string]lineage.LineageID
}

// New returns an empty Tracker.
func New() *Tracker { return &Tracker{containers: map[string]lineage.LineageID{}} }

// Get returns the cached root id for a container id and whether one exists.
func (t *Tracker) Get(containerID string) (lineage.LineageID, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	id, ok := t.containers[containerID]
	return id, ok
}

// Put caches the root id for a container id (called after the pipeline mints
// it once).
func (t *Tracker) Put(containerID string, id lineage.LineageID) {
	t.mu.Lock()
	t.containers[containerID] = id
	t.mu.Unlock()
}

// Len reports how many distinct containers have been anchored (health/metrics).
func (t *Tracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.containers)
}

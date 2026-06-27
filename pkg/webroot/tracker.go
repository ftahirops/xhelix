// Package webroot tracks a per-vhost lineage root so processes serving an
// inbound HTTP request get a non-admin (RootWeb) causal root and their
// workflows can become learnable. It is the "C" slice of the Root Emitters
// work (docs/ROOT_EMITTERS_SCOPE.md), driven by the eBPF ssl_read signal
// (sensor ebpf.ssl) which carries the serving PID + http_host atomically.
//
// Minting + proctree attribution is done by the pipeline (it needs the
// SourceMinter + ProcTree); this package owns only the per-vhost id cache,
// so it stays pure + testable. The cache is bounded (vhost count is normally
// config-bounded, but a hostile/misconfigured Host header space could be
// unbounded — so we cap it).
package webroot

import (
	"sync"

	"github.com/xhelix/xhelix/pkg/lineage"
)

// DefaultCap bounds the number of distinct vhost roots cached/minted. Past it,
// new vhosts are not minted (existing ones still resolve) — prevents anchor
// blow-up from a churning/spoofed Host header space.
const DefaultCap = 4096

// Tracker caches one lineage root id per vhost (Host header value).
type Tracker struct {
	mu    sync.Mutex
	cap   int
	hosts map[string]lineage.LineageID
}

// New returns a Tracker with the default cap.
func New() *Tracker { return NewWithCap(DefaultCap) }

// NewWithCap is New with an explicit cap (cap <= 0 uses the default).
func NewWithCap(cap int) *Tracker {
	if cap <= 0 {
		cap = DefaultCap
	}
	return &Tracker{cap: cap, hosts: map[string]lineage.LineageID{}}
}

// Get returns the cached root id for a vhost and whether one exists.
func (t *Tracker) Get(host string) (lineage.LineageID, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	id, ok := t.hosts[host]
	return id, ok
}

// Put caches the root id for a vhost. No-op once the cap is reached (so a
// runaway Host-header space can't blow up the anchor store).
func (t *Tracker) Put(host string, id lineage.LineageID) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.hosts[host]; !ok && len(t.hosts) >= t.cap {
		return false
	}
	t.hosts[host] = id
	return true
}

// Len reports the number of cached vhosts (test helper / observability).
func (t *Tracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.hosts)
}

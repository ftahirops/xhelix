// Package hotgraph is the in-memory causal DAG of processes that
// xhelix has seen. It is the canonical, PID-reuse-safe replacement
// for pkg/proctree, keyed on canonical.ProcKey (PID + StartTicks).
//
// The graph answers three classes of question fast:
//
//   - "Show me the ancestors of process X" — uses the parent edge.
//   - "Show me the descendants of process X" — uses children edges.
//   - "Show me every process belonging to lineage / cgroup / origin IP" —
//     uses the secondary indices.
//
// Memory budget: under 4 KB per live process (see DATA_LEAK_FABRIC.md /
// ROADMAP.md P2 performance spec). Bounded by maxNodes; the LRU
// eviction policy lands in P2.2.
//
// Concurrency: a single RWMutex guards the whole graph. The contract
// is "many concurrent readers, one writer at a time"; per-shard locks
// will land if the single mutex becomes a bottleneck under load (it
// won't at sub-µs operations).
package hotgraph

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/canonical"
	"github.com/xhelix/xhelix/pkg/lineage"
)

// State describes the liveness of a process in the graph.
type State uint8

const (
	StateLive   State = iota // process exists and has not been seen exit
	StateExited              // process exited; node retained for retention window
)

func (s State) String() string {
	switch s {
	case StateLive:
		return "live"
	case StateExited:
		return "exited"
	}
	return "unknown"
}

// ProcessNode is a single vertex in the graph. Sized for the per-live-process
// memory budget by inlining scalars and reusing strings (callers should
// intern exe path / cgroup / origin IP if they want to drop further).
type ProcessNode struct {
	Key         canonical.ProcKey
	Parent      canonical.ProcKey // zero value = unknown / root
	UID         uint32
	GID         uint32
	LoginUID    uint32
	CgroupID    uint64
	Cgroup      string
	Comm        string
	ExePath     string
	ExeSHA      string // hex string; may be "" if not yet hashed
	Argv        string // truncated argv line; not the full slice
	LineageID   lineage.LineageID
	OriginIP    string // remote IP that started the lineage, if known
	TTY         string // e.g. "pts/0"
	ContainerID string

	SpawnedAt time.Time
	ExitedAt  time.Time // zero unless State == StateExited
	State     State
	LastSeen  time.Time
}

// Graph is the live causal DAG.
type Graph struct {
	mu       sync.RWMutex
	nodes    map[canonical.ProcKey]*ProcessNode
	children map[canonical.ProcKey][]canonical.ProcKey

	// Secondary indices for "list every node tagged with X". Values
	// are pointers into nodes; entries are removed on eviction.
	byCgroup   map[uint64][]canonical.ProcKey
	byLineage  map[lineage.LineageID][]canonical.ProcKey
	byOriginIP map[string][]canonical.ProcKey
	byTTY      map[string][]canonical.ProcKey

	maxNodes int

	// Counters.
	inserts atomic.Uint64
	updates atomic.Uint64
	exits   atomic.Uint64
	evicts  atomic.Uint64
}

// Options controls Graph construction.
type Options struct {
	// MaxNodes caps the number of process nodes retained. The hard
	// LRU eviction logic lands in P2.2; for now Insert returns
	// without storing if at cap and the key is new.
	MaxNodes int
}

// New constructs an empty Graph.
func New(opts Options) *Graph {
	if opts.MaxNodes <= 0 {
		opts.MaxNodes = 65536
	}
	return &Graph{
		nodes:      make(map[canonical.ProcKey]*ProcessNode, opts.MaxNodes/4),
		children:   make(map[canonical.ProcKey][]canonical.ProcKey),
		byCgroup:   make(map[uint64][]canonical.ProcKey),
		byLineage:  make(map[lineage.LineageID][]canonical.ProcKey),
		byOriginIP: make(map[string][]canonical.ProcKey),
		byTTY:      make(map[string][]canonical.ProcKey),
		maxNodes:   opts.MaxNodes,
	}
}

// Insert adds a new node or merges fresh fields into an existing one.
// Returns true if the key was new (insert), false if it was an update.
func (g *Graph) Insert(n ProcessNode) bool {
	if n.Key.PID == 0 {
		return false
	}
	now := time.Now()
	if n.LastSeen.IsZero() {
		n.LastSeen = now
	}
	if n.SpawnedAt.IsZero() && n.State == StateLive {
		n.SpawnedAt = now
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if existing, ok := g.nodes[n.Key]; ok {
		// Merge — preserve identity fields, refresh observed state.
		// Operator's call: prefer the new value if the caller bothered
		// to set it; otherwise keep what we had.
		merged := *existing
		merged.LastSeen = n.LastSeen
		if n.Parent.PID != 0 {
			merged.Parent = n.Parent
		}
		if n.Comm != "" {
			merged.Comm = n.Comm
		}
		if n.ExePath != "" {
			merged.ExePath = n.ExePath
		}
		if n.ExeSHA != "" {
			merged.ExeSHA = n.ExeSHA
		}
		if n.Argv != "" {
			merged.Argv = n.Argv
		}
		if n.CgroupID != 0 {
			merged.CgroupID = n.CgroupID
		}
		if n.Cgroup != "" {
			merged.Cgroup = n.Cgroup
		}
		if n.LineageID != 0 {
			merged.LineageID = n.LineageID
		}
		if n.OriginIP != "" {
			merged.OriginIP = n.OriginIP
		}
		if n.TTY != "" {
			merged.TTY = n.TTY
		}
		if n.ContainerID != "" {
			merged.ContainerID = n.ContainerID
		}
		if n.State != StateLive {
			merged.State = n.State
		}
		g.nodes[n.Key] = &merged
		g.reindexLocked(existing, &merged)
		g.updates.Add(1)
		return false
	}

	if len(g.nodes) >= g.maxNodes {
		// P2.2 will replace this with LRU eviction; for now we
		// refuse new inserts when full and bump a counter.
		g.evicts.Add(1)
		return false
	}

	node := n // copy
	g.nodes[node.Key] = &node
	g.indexLocked(&node)

	if node.Parent.PID != 0 {
		g.children[node.Parent] = append(g.children[node.Parent], node.Key)
	}
	g.inserts.Add(1)
	return true
}

// MarkExit transitions a node to StateExited. Idempotent.
func (g *Graph) MarkExit(key canonical.ProcKey, at time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	n, ok := g.nodes[key]
	if !ok {
		return false
	}
	if n.State == StateExited {
		return false
	}
	n.State = StateExited
	if at.IsZero() {
		at = time.Now()
	}
	n.ExitedAt = at
	n.LastSeen = at
	g.exits.Add(1)
	return true
}

// Touch updates the LastSeen timestamp without otherwise modifying
// the node. Used by sensors that want to keep a node "warm" against
// future LRU eviction.
func (g *Graph) Touch(key canonical.ProcKey) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	n, ok := g.nodes[key]
	if !ok {
		return false
	}
	n.LastSeen = time.Now()
	return true
}

// Get returns a copy of the node for key, plus ok=false if absent.
// A copy is returned so callers can read fields without holding any
// lock; the graph's internal pointer is not exposed.
func (g *Graph) Get(key canonical.ProcKey) (ProcessNode, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[key]
	if !ok {
		return ProcessNode{}, false
	}
	return *n, true
}

// Ancestors walks the parent edges up to `depth` levels. Returns
// the chain in order [self, parent, grandparent, ...]. depth=0 means
// "self only"; depth=-1 means "all the way".
func (g *Graph) Ancestors(key canonical.ProcKey, depth int) []ProcessNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]ProcessNode, 0, 8)
	cur := key
	visited := make(map[canonical.ProcKey]struct{}, 8)
	for i := 0; depth < 0 || i <= depth; i++ {
		if _, seen := visited[cur]; seen {
			break // cycle guard
		}
		visited[cur] = struct{}{}
		n, ok := g.nodes[cur]
		if !ok {
			break
		}
		out = append(out, *n)
		if n.Parent.PID == 0 {
			break
		}
		cur = n.Parent
	}
	return out
}

// Descendants returns the transitive children of key, BFS order,
// up to `depth` levels (depth=-1 = unlimited). The returned slice
// excludes key itself.
func (g *Graph) Descendants(key canonical.ProcKey, depth int) []ProcessNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []ProcessNode
	visited := map[canonical.ProcKey]struct{}{key: {}}
	type level struct {
		k canonical.ProcKey
		d int
	}
	queue := []level{{key, 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if depth >= 0 && cur.d >= depth {
			continue
		}
		for _, ch := range g.children[cur.k] {
			if _, seen := visited[ch]; seen {
				continue
			}
			visited[ch] = struct{}{}
			if n, ok := g.nodes[ch]; ok {
				out = append(out, *n)
			}
			queue = append(queue, level{ch, cur.d + 1})
		}
	}
	return out
}

// ByLineage returns every node tagged with the given lineage id.
// Useful for "show me everything this SSH session caused".
func (g *Graph) ByLineage(id lineage.LineageID) []ProcessNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.byIndex(g.byLineage[id])
}

// ByCgroup returns every node in the given cgroup id.
func (g *Graph) ByCgroup(cgroupID uint64) []ProcessNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.byIndex(g.byCgroup[cgroupID])
}

// ByOriginIP returns every node whose lineage originated from ip.
func (g *Graph) ByOriginIP(ip string) []ProcessNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.byIndex(g.byOriginIP[ip])
}

// ByTTY returns every node attached to the given controlling TTY.
func (g *Graph) ByTTY(tty string) []ProcessNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.byIndex(g.byTTY[tty])
}

// byIndex resolves a slice of keys into a slice of node copies,
// silently skipping any keys whose nodes have been evicted. Caller
// holds the read lock.
func (g *Graph) byIndex(keys []canonical.ProcKey) []ProcessNode {
	out := make([]ProcessNode, 0, len(keys))
	for _, k := range keys {
		if n, ok := g.nodes[k]; ok {
			out = append(out, *n)
		}
	}
	// Stable order by SpawnedAt for caller convenience.
	sort.Slice(out, func(i, j int) bool {
		return out[i].SpawnedAt.Before(out[j].SpawnedAt)
	})
	return out
}

// indexLocked registers a node in every applicable secondary index.
// Caller holds the write lock.
func (g *Graph) indexLocked(n *ProcessNode) {
	if n.CgroupID != 0 {
		g.byCgroup[n.CgroupID] = append(g.byCgroup[n.CgroupID], n.Key)
	}
	if n.LineageID != 0 {
		g.byLineage[n.LineageID] = append(g.byLineage[n.LineageID], n.Key)
	}
	if n.OriginIP != "" {
		g.byOriginIP[n.OriginIP] = append(g.byOriginIP[n.OriginIP], n.Key)
	}
	if n.TTY != "" {
		g.byTTY[n.TTY] = append(g.byTTY[n.TTY], n.Key)
	}
}

// reindexLocked updates indices when a node's index-affecting fields
// change. Caller holds the write lock.
func (g *Graph) reindexLocked(prev, next *ProcessNode) {
	if prev.CgroupID != next.CgroupID {
		g.removeFromIndex(g.byCgroup, prev.CgroupID, prev.Key)
		if next.CgroupID != 0 {
			g.byCgroup[next.CgroupID] = append(g.byCgroup[next.CgroupID], next.Key)
		}
	}
	if prev.LineageID != next.LineageID {
		g.removeFromLineageIndex(prev.LineageID, prev.Key)
		if next.LineageID != 0 {
			g.byLineage[next.LineageID] = append(g.byLineage[next.LineageID], next.Key)
		}
	}
	if prev.OriginIP != next.OriginIP {
		g.removeFromStringIndex(g.byOriginIP, prev.OriginIP, prev.Key)
		if next.OriginIP != "" {
			g.byOriginIP[next.OriginIP] = append(g.byOriginIP[next.OriginIP], next.Key)
		}
	}
	if prev.TTY != next.TTY {
		g.removeFromStringIndex(g.byTTY, prev.TTY, prev.Key)
		if next.TTY != "" {
			g.byTTY[next.TTY] = append(g.byTTY[next.TTY], next.Key)
		}
	}
}

func (g *Graph) removeFromIndex(idx map[uint64][]canonical.ProcKey, k uint64, key canonical.ProcKey) {
	if k == 0 {
		return
	}
	keys := idx[k]
	for i, kk := range keys {
		if kk == key {
			idx[k] = append(keys[:i], keys[i+1:]...)
			break
		}
	}
}

func (g *Graph) removeFromLineageIndex(k lineage.LineageID, key canonical.ProcKey) {
	if k == 0 {
		return
	}
	keys := g.byLineage[k]
	for i, kk := range keys {
		if kk == key {
			g.byLineage[k] = append(keys[:i], keys[i+1:]...)
			break
		}
	}
}

func (g *Graph) removeFromStringIndex(idx map[string][]canonical.ProcKey, k string, key canonical.ProcKey) {
	if k == "" {
		return
	}
	keys := idx[k]
	for i, kk := range keys {
		if kk == key {
			idx[k] = append(keys[:i], keys[i+1:]...)
			break
		}
	}
}

// Remove drops a node and every reference to it from the graph.
// Returns true if the node was present. This is the foundation for
// the LRU eviction logic that lands in P2.2.
func (g *Graph) Remove(key canonical.ProcKey) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	n, ok := g.nodes[key]
	if !ok {
		return false
	}
	delete(g.nodes, key)
	g.removeFromIndex(g.byCgroup, n.CgroupID, key)
	g.removeFromLineageIndex(n.LineageID, key)
	g.removeFromStringIndex(g.byOriginIP, n.OriginIP, key)
	g.removeFromStringIndex(g.byTTY, n.TTY, key)
	delete(g.children, key)
	if n.Parent.PID != 0 {
		// Drop self from parent's child list.
		kids := g.children[n.Parent]
		for i, kk := range kids {
			if kk == key {
				g.children[n.Parent] = append(kids[:i], kids[i+1:]...)
				break
			}
		}
	}
	g.evicts.Add(1)
	return true
}

// Stats is the snapshot used by the LocalAPI surface.
type Stats struct {
	Nodes          int    `json:"nodes"`
	MaxNodes       int    `json:"max_nodes"`
	IndexedCgroups int    `json:"indexed_cgroups"`
	IndexedLineages int   `json:"indexed_lineages"`
	IndexedOrigins int    `json:"indexed_origins"`
	IndexedTTYs    int    `json:"indexed_ttys"`
	Inserts        uint64 `json:"inserts"`
	Updates        uint64 `json:"updates"`
	Exits          uint64 `json:"exits"`
	Evicts         uint64 `json:"evicts"`
}

// Stats returns a snapshot.
func (g *Graph) Stats() Stats {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return Stats{
		Nodes:           len(g.nodes),
		MaxNodes:        g.maxNodes,
		IndexedCgroups:  len(g.byCgroup),
		IndexedLineages: len(g.byLineage),
		IndexedOrigins:  len(g.byOriginIP),
		IndexedTTYs:     len(g.byTTY),
		Inserts:         g.inserts.Load(),
		Updates:         g.updates.Load(),
		Exits:           g.exits.Load(),
		Evicts:          g.evicts.Load(),
	}
}

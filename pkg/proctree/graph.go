// Package proctree maintains an in-memory process-tree graph keyed
// by pid, used to materialise the `tree` variable in CEL rules.
//
// The graph receives a stream of process-spawn and process-exit
// events. On overflow it evicts oldest leaf nodes by LastEvent.
// Internal nodes are never evicted while they have live children.
package proctree

import (
	"sort"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/source"
)

// Node is a single process record.
//
// Source attribution fields (PrimarySource, CausalSet) are populated by
// the pipeline as identity events mint anchors. A spawned process
// inherits its parent's PrimarySource + CausalSet (see Graph.OnSpawn);
// injection (ptrace, process_vm_writev, memfd execve) merges the
// attacker's source into the target's CausalSet so PrimarySource
// becomes Ambiguous.
type Node struct {
	PID       uint32
	PPID      uint32
	Comm      string
	Image     string
	UID       uint32
	StartNs   uint64
	Argv      []string
	CGroupID  uint64
	Container string
	Children  map[uint32]struct{}
	FirstSeen time.Time
	LastEvent time.Time

	// PrimarySource is the authoritative anchor for this process when
	// CausalSet has exactly one member. When CausalSet.Ambiguous() is
	// true, PrimarySource is the *most-recent* contributing anchor;
	// callers that need certainty must consult CausalSet.Ambiguous()
	// before treating PrimarySource as authoritative.
	PrimarySource lineage.LineageID

	// CausalSet is the bounded, deduplicated set of anchors that have
	// contributed to this process's provenance. T02 / Phase A2.
	CausalSet source.CausalSet
}

// Graph is the live view of all known pids.
type Graph struct {
	mu    sync.RWMutex
	nodes map[uint32]*Node
	cap   int
}

// New returns a Graph with the given soft cap. cap <= 0 selects
// 50 000 (Phase 2 default).
func New(cap int) *Graph {
	if cap <= 0 {
		cap = 50_000
	}
	return &Graph{nodes: make(map[uint32]*Node, 1024), cap: cap}
}

// OnSpawn records a new process.
//
// Source-attribution propagation (T02): if the spawn event did not
// pre-populate PrimarySource/CausalSet on n AND the parent has a
// PrimarySource, the child inherits both. This is the single-line
// implementation of "spawn inherits parent's source" from the v2
// source lineage spec. Identity events that DO carry an explicit
// SourceAnchorID (e.g. the sshd login that spawns the shell) override
// inheritance by populating n.PrimarySource before calling OnSpawn.
func (g *Graph) OnSpawn(n Node) {
	now := time.Now()
	if n.FirstSeen.IsZero() {
		n.FirstSeen = now
	}
	n.LastEvent = now
	if n.Children == nil {
		n.Children = make(map[uint32]struct{})
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if parent, ok := g.nodes[n.PPID]; ok {
		parent.Children[n.PID] = struct{}{}
		// Inherit only if the spawn event didn't already attribute the
		// child explicitly.
		if n.PrimarySource == 0 && parent.PrimarySource != 0 {
			n.PrimarySource = parent.PrimarySource
		}
		if n.CausalSet.IsEmpty() && !parent.CausalSet.IsEmpty() {
			n.CausalSet.Merge(parent.CausalSet)
		}
	}
	// Invariant: if PrimarySource is set, CausalSet must contain it.
	// This holds whether PrimarySource came from inheritance or from
	// an explicit spawn-time stamp.
	if n.PrimarySource != 0 {
		n.CausalSet.Add(n.PrimarySource)
	}
	g.nodes[n.PID] = &n

	if len(g.nodes) > g.cap {
		g.evictLocked()
	}
}

// AttributeSource records that the given anchor contributed to pid's
// provenance. If pid currently has no PrimarySource, it becomes id;
// otherwise id is added to the CausalSet, which may flip the actor to
// Ambiguous. Used by:
//
//   - identity events that mint a fresh anchor (sshd login, sudo, …):
//     the post-mint event is dispatched against the originating pid.
//   - file-mediated taint inheritance (T02 commit 3): reader absorbs
//     the file's last_writer_primary_source.
//   - injection events (T02 commit 4): ptrace target absorbs attacker
//     source, causing Ambiguous.
//
// No-op if id is 0 or pid is not in the graph.
func (g *Graph) AttributeSource(pid uint32, id lineage.LineageID) {
	if id == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	n, ok := g.nodes[pid]
	if !ok {
		return
	}
	if n.PrimarySource == 0 {
		n.PrimarySource = id
	} else {
		// The "most recent contributing anchor" rule from the spec.
		// PrimarySource follows the latest attribution while CausalSet
		// preserves history.
		n.PrimarySource = id
	}
	n.CausalSet.Add(id)
	n.LastEvent = time.Now()
}

// MergeCausalSet absorbs all anchors in cs into pid's CausalSet. Used
// for file-read taint inheritance (reader absorbs writer's full set).
// Returns true if any new id was added. No-op if pid not in graph.
func (g *Graph) MergeCausalSet(pid uint32, cs source.CausalSet) bool {
	if cs.IsEmpty() {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	n, ok := g.nodes[pid]
	if !ok {
		return false
	}
	return n.CausalSet.Merge(cs)
}

// SourceOf returns the (PrimarySource, CausalSet copy) for pid. The
// CausalSet copy is safe to publish — modifying it does not affect the
// graph. Returns (0, empty) if pid is not in the graph.
func (g *Graph) SourceOf(pid uint32) (lineage.LineageID, source.CausalSet) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[pid]
	if !ok {
		return 0, source.CausalSet{}
	}
	return n.PrimarySource, source.NewCausalSet(n.CausalSet.Slice()...)
}

// OnExit removes a pid; its children are reparented to PID 1 (true
// Linux semantics for an orphaned process).
func (g *Graph) OnExit(pid uint32) {
	g.mu.Lock()
	defer g.mu.Unlock()

	n, ok := g.nodes[pid]
	if !ok {
		return
	}
	if init, ok := g.nodes[1]; ok {
		for c := range n.Children {
			if cn, ok := g.nodes[c]; ok {
				cn.PPID = 1
				init.Children[c] = struct{}{}
			}
		}
	}
	delete(g.nodes, pid)
	if parent, ok := g.nodes[n.PPID]; ok {
		delete(parent.Children, pid)
	}
}

// Touch updates LastEvent for pid (called on every event for that
// pid). Cheap; the lock is held only briefly.
func (g *Graph) Touch(pid uint32) {
	now := time.Now()
	g.mu.Lock()
	if n, ok := g.nodes[pid]; ok {
		n.LastEvent = now
	}
	g.mu.Unlock()
}

// Ancestors returns the chain from pid upward to PID 1, inclusive.
// depth caps the walk; <=0 means unlimited (capped internally at 16).
func (g *Graph) Ancestors(pid uint32, depth int) []model.ProcNode {
	if depth <= 0 || depth > 16 {
		depth = 16
	}
	g.mu.RLock()
	defer g.mu.RUnlock()

	out := make([]model.ProcNode, 0, 4)
	cur := pid
	for i := 0; i < depth; i++ {
		n, ok := g.nodes[cur]
		if !ok {
			break
		}
		out = append(out, model.ProcNode{
			PID:         n.PID,
			Comm:        n.Comm,
			Argv:        n.Argv,
			UID:         n.UID,
			StartNs:     n.StartNs,
			Image:       n.Image,
			FirstAction: n.FirstSeen,
		})
		if n.PPID == 0 || n.PPID == cur {
			break
		}
		cur = n.PPID
	}
	return out
}

// Stats returns a small status snapshot for the TUI.
type Stats struct {
	NodeCount     int
	MaxDepthSeen  int
	EvictionCount uint64
}

// Count returns the live node count.
func (g *Graph) Count() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// evictLocked removes leaf nodes by oldest LastEvent until we're
// 10% under cap. Caller must hold g.mu (writable).
func (g *Graph) evictLocked() {
	target := g.cap - g.cap/10
	if len(g.nodes) <= target {
		return
	}
	type leaf struct {
		pid uint32
		ts  time.Time
	}
	leaves := make([]leaf, 0, len(g.nodes)/4)
	for pid, n := range g.nodes {
		if len(n.Children) == 0 {
			leaves = append(leaves, leaf{pid: pid, ts: n.LastEvent})
		}
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].ts.Before(leaves[j].ts) })

	for _, l := range leaves {
		n := g.nodes[l.pid]
		if n == nil {
			continue
		}
		if parent, ok := g.nodes[n.PPID]; ok {
			delete(parent.Children, l.pid)
		}
		delete(g.nodes, l.pid)
		if len(g.nodes) <= target {
			return
		}
	}
}

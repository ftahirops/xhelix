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

	"github.com/xhelix/xhelix/pkg/model"
)

// Node is a single process record.
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

	g.nodes[n.PID] = &n
	if parent, ok := g.nodes[n.PPID]; ok {
		parent.Children[n.PID] = struct{}{}
	}

	if len(g.nodes) > g.cap {
		g.evictLocked()
	}
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

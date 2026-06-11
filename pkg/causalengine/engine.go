// Package causalengine assembles human-readable causal chains on demand
// from the live substrate (P6): the hot process graph (pkg/hotgraph), the
// lineage origin store (pkg/lineage), and the ProcKey cache.
//
// Given a process (by PID, ProcKey, or lineage), it walks the graph's
// parent edges up to the root and resolves the lineage origin, producing
// an ordered "this happened because …" story:
//
//   Origin: SSH login from 203.0.113.5 (user=alice) at 14:22
//     → sshd → bash → curl   (the target process)
//
// On-demand assembly — nothing is stamped on every event; the causal
// links already exist in the graph + lineage store and are stitched only
// when queried.
package causalengine

import (
	"time"

	"github.com/xhelix/xhelix/pkg/canonical"
	"github.com/xhelix/xhelix/pkg/hotgraph"
	"github.com/xhelix/xhelix/pkg/lineage"
)

// Origin is the root cause of a chain — who/where it started.
type Origin struct {
	Type       string    `json:"type"` // ssh|web|cron|sudo|systemd|container|local|…
	User       string    `json:"user,omitempty"`
	SourceIP   string    `json:"source_ip,omitempty"`
	SourcePort uint16    `json:"source_port,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
}

// Process is one hop in the chain.
type Process struct {
	PID        uint32    `json:"pid"`
	StartTicks uint64    `json:"start_ticks"`
	Comm       string    `json:"comm"`
	ExePath    string    `json:"exe_path,omitempty"`
	ExeSHA     string    `json:"exe_sha,omitempty"`
	Cgroup     string    `json:"cgroup,omitempty"`
	UID        uint32    `json:"uid"`
	SpawnedAt  time.Time `json:"spawned_at,omitempty"`
	Exited     bool      `json:"exited"`
}

// CausalChain is the assembled story.
type CausalChain struct {
	Found     bool      `json:"found"`
	LineageID uint64    `json:"lineage_id,omitempty"`
	OriginIP  string    `json:"origin_ip,omitempty"`
	Origin    *Origin   `json:"origin,omitempty"`
	Processes []Process `json:"processes"` // ordered root → target
	Target    *Process  `json:"target,omitempty"`
}

// Engine stitches causal chains. All deps are read-only; nil-safe.
type Engine struct {
	graph    *hotgraph.Graph
	origins  *lineage.Store
	procKeys *canonical.ProcKeyCache
}

// New builds an engine over the live graph + lineage store + key cache.
func New(graph *hotgraph.Graph, origins *lineage.Store, procKeys *canonical.ProcKeyCache) *Engine {
	return &Engine{graph: graph, origins: origins, procKeys: procKeys}
}

// TraceByPID resolves a PID to its canonical key (cache-only — the process
// may have exited; it was cached at spawn) and traces it.
func (e *Engine) TraceByPID(pid uint32) CausalChain {
	if e == nil || e.graph == nil || e.procKeys == nil || pid == 0 {
		return CausalChain{}
	}
	pk, ok := e.procKeys.Get(pid)
	if !ok {
		return CausalChain{}
	}
	return e.TraceByKey(pk)
}

// TraceByKey walks parent edges from key up to the root and resolves the
// lineage origin. Processes are ordered root → target.
func (e *Engine) TraceByKey(key canonical.ProcKey) CausalChain {
	if e == nil || e.graph == nil {
		return CausalChain{}
	}
	target, ok := e.graph.Get(key)
	if !ok {
		return CausalChain{}
	}
	// Ancestors returns [self, parent, …, root]; reverse to root → self.
	anc := e.graph.Ancestors(key, -1)
	procs := make([]Process, 0, len(anc))
	for i := len(anc) - 1; i >= 0; i-- {
		procs = append(procs, toProcess(anc[i]))
	}
	chain := CausalChain{
		Found:     true,
		LineageID: uint64(target.LineageID),
		OriginIP:  target.OriginIP,
		Processes: procs,
	}
	if len(procs) > 0 {
		t := procs[len(procs)-1]
		chain.Target = &t
	}
	chain.Origin = e.originFor(target.LineageID)
	return chain
}

// TraceByLineage returns every graphed process in a lineage plus its
// origin. Useful from an incident, which carries lineage IDs but not a
// single target PID. Order is the graph's index order (not a strict tree).
func (e *Engine) TraceByLineage(id uint64) CausalChain {
	if e == nil || e.graph == nil || id == 0 {
		return CausalChain{}
	}
	nodes := e.graph.ByLineage(lineage.LineageID(id))
	if len(nodes) == 0 {
		return CausalChain{}
	}
	procs := make([]Process, 0, len(nodes))
	originIP := ""
	for _, n := range nodes {
		procs = append(procs, toProcess(n))
		if originIP == "" {
			originIP = n.OriginIP
		}
	}
	return CausalChain{
		Found: true, LineageID: id, OriginIP: originIP,
		Processes: procs, Origin: e.originFor(lineage.LineageID(id)),
	}
}

func (e *Engine) originFor(id lineage.LineageID) *Origin {
	if e.origins == nil || id == 0 {
		return nil
	}
	o, ok := e.origins.Get(id)
	if !ok {
		return nil
	}
	return &Origin{
		Type: o.Type.String(), User: o.UserName,
		SourceIP: o.SourceIP, SourcePort: o.SourcePort, StartedAt: o.CreatedAt,
	}
}

func toProcess(n hotgraph.ProcessNode) Process {
	return Process{
		PID: n.Key.PID, StartTicks: n.Key.StartTicks,
		Comm: n.Comm, ExePath: n.ExePath, ExeSHA: n.ExeSHA, Cgroup: n.Cgroup,
		UID: n.UID, SpawnedAt: n.SpawnedAt, Exited: !n.ExitedAt.IsZero(),
	}
}

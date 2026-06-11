package causalengine

import (
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/canonical"
	"github.com/xhelix/xhelix/pkg/hotgraph"
	"github.com/xhelix/xhelix/pkg/lineage"
)

func setup(t *testing.T) (*Engine, *hotgraph.Graph, *canonical.ProcKeyCache, *lineage.Store) {
	t.Helper()
	g := hotgraph.New(hotgraph.Options{MaxNodes: 1024})
	cache := canonical.NewProcKeyCache(canonical.CacheOptions{})
	origins := lineage.NewStore()
	return New(g, origins, cache), g, cache, origins
}

// buildTree wires sshd(1000) → bash(1001) → curl(1002), all lineage 42,
// origin IP set, with a recorded SSH origin.
func buildTree(g *hotgraph.Graph, cache *canonical.ProcKeyCache, origins *lineage.Store) (sshd, bash, curl canonical.ProcKey) {
	sshd = canonical.ProcKey{PID: 1000, StartTicks: 1}
	bash = canonical.ProcKey{PID: 1001, StartTicks: 2}
	curl = canonical.ProcKey{PID: 1002, StartTicks: 3}
	cache.Put(sshd)
	cache.Put(bash)
	cache.Put(curl)
	lid := lineage.LineageID(42)
	g.Insert(hotgraph.ProcessNode{Key: sshd, Comm: "sshd", LineageID: lid, OriginIP: "203.0.113.5", SpawnedAt: time.Unix(1700000000, 0)})
	g.Insert(hotgraph.ProcessNode{Key: bash, Parent: sshd, Comm: "bash", LineageID: lid, OriginIP: "203.0.113.5", SpawnedAt: time.Unix(1700000005, 0)})
	g.Insert(hotgraph.ProcessNode{Key: curl, Parent: bash, Comm: "curl", ExePath: "/usr/bin/curl", LineageID: lid, OriginIP: "203.0.113.5", SpawnedAt: time.Unix(1700000007, 0)})
	origins.Put(lineage.Origin{ID: lid, Type: lineage.RootSSH, UserName: "alice", SourceIP: "203.0.113.5", SourcePort: 42891, CreatedAt: time.Unix(1700000000, 0)})
	return
}

func TestTraceByPID_FullChain(t *testing.T) {
	e, g, cache, origins := setup(t)
	_, _, curl := buildTree(g, cache, origins)

	chain := e.TraceByPID(curl.PID)
	if !chain.Found {
		t.Fatal("chain not found for curl pid")
	}
	// Ordered root → target: sshd, bash, curl.
	if len(chain.Processes) != 3 {
		t.Fatalf("want 3 processes, got %d: %+v", len(chain.Processes), chain.Processes)
	}
	if chain.Processes[0].Comm != "sshd" || chain.Processes[2].Comm != "curl" {
		t.Errorf("wrong order: %s … %s", chain.Processes[0].Comm, chain.Processes[2].Comm)
	}
	if chain.Target == nil || chain.Target.Comm != "curl" {
		t.Errorf("target should be curl, got %+v", chain.Target)
	}
	// Origin resolved from lineage.
	if chain.Origin == nil || chain.Origin.Type != "ssh" || chain.Origin.User != "alice" || chain.Origin.SourceIP != "203.0.113.5" {
		t.Errorf("origin not resolved: %+v", chain.Origin)
	}
	if chain.LineageID != 42 {
		t.Errorf("lineage id = %d, want 42", chain.LineageID)
	}
}

func TestTraceByPID_UnknownPID(t *testing.T) {
	e, _, _, _ := setup(t)
	if e.TraceByPID(99999).Found {
		t.Error("unknown pid should not be found")
	}
}

func TestTraceByLineage(t *testing.T) {
	e, g, cache, origins := setup(t)
	buildTree(g, cache, origins)
	chain := e.TraceByLineage(42)
	if !chain.Found || len(chain.Processes) != 3 {
		t.Fatalf("lineage trace should find 3 procs, got %+v", chain)
	}
	if chain.Origin == nil || chain.Origin.Type != "ssh" {
		t.Errorf("origin missing on lineage trace: %+v", chain.Origin)
	}
}

func TestNilSafe(t *testing.T) {
	var e *Engine
	if e.TraceByPID(1).Found {
		t.Error("nil engine must be safe + not found")
	}
	e2 := New(nil, nil, nil)
	if e2.TraceByPID(1).Found || e2.TraceByLineage(1).Found {
		t.Error("engine with nil deps must be safe")
	}
}

func TestTraceByKey_NoLineageStillTraces(t *testing.T) {
	// A process with no lineage origin recorded still yields a process
	// chain (origin nil) — graph ancestry is independent of lineage.
	e, g, cache, _ := setup(t)
	a := canonical.ProcKey{PID: 1, StartTicks: 1}
	b := canonical.ProcKey{PID: 2, StartTicks: 1}
	cache.Put(a)
	cache.Put(b)
	g.Insert(hotgraph.ProcessNode{Key: a, Comm: "init"})
	g.Insert(hotgraph.ProcessNode{Key: b, Parent: a, Comm: "worker"})
	chain := e.TraceByKey(b)
	if !chain.Found || len(chain.Processes) != 2 {
		t.Fatalf("should trace ancestry without lineage, got %+v", chain)
	}
	if chain.Origin != nil {
		t.Errorf("no origin expected, got %+v", chain.Origin)
	}
}

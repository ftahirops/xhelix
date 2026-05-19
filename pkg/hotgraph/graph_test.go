package hotgraph

import (
	"sync"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/canonical"
	"github.com/xhelix/xhelix/pkg/lineage"
)

func key(pid uint32, st uint64) canonical.ProcKey {
	return canonical.ProcKey{PID: pid, StartTicks: st}
}

func TestGraph_InsertAndGet(t *testing.T) {
	g := New(Options{})
	n := ProcessNode{Key: key(100, 1), Comm: "bash", State: StateLive}
	if !g.Insert(n) {
		t.Fatal("insert should report new=true")
	}
	got, ok := g.Get(key(100, 1))
	if !ok || got.Comm != "bash" {
		t.Errorf("get: ok=%v node=%+v", ok, got)
	}
	if g.Stats().Inserts != 1 {
		t.Errorf("inserts = %d, want 1", g.Stats().Inserts)
	}
}

func TestGraph_InsertSameKeyMerges(t *testing.T) {
	g := New(Options{})
	g.Insert(ProcessNode{Key: key(100, 1), Comm: "bash"})
	// Second insert: new=false, but fields merged.
	if g.Insert(ProcessNode{Key: key(100, 1), ExePath: "/bin/bash"}) {
		t.Error("duplicate Insert should return new=false")
	}
	got, _ := g.Get(key(100, 1))
	if got.Comm != "bash" || got.ExePath != "/bin/bash" {
		t.Errorf("merge failed: %+v", got)
	}
}

func TestGraph_PIDReuseSafety(t *testing.T) {
	// Same PID, different StartTicks → different node identity.
	g := New(Options{})
	g.Insert(ProcessNode{Key: key(100, 1), Comm: "bash"})
	g.Insert(ProcessNode{Key: key(100, 999), Comm: "python"})

	if got, _ := g.Get(key(100, 1)); got.Comm != "bash" {
		t.Errorf("original entry corrupted: %+v", got)
	}
	if got, _ := g.Get(key(100, 999)); got.Comm != "python" {
		t.Errorf("new entry missing: %+v", got)
	}
	if g.Stats().Nodes != 2 {
		t.Errorf("nodes = %d, want 2 (PID reuse must not collapse keys)", g.Stats().Nodes)
	}
}

func TestGraph_AncestorsAndDescendants(t *testing.T) {
	g := New(Options{})
	// Build a 3-deep chain: sshd → bash → python
	g.Insert(ProcessNode{Key: key(10, 1), Comm: "sshd"})
	g.Insert(ProcessNode{Key: key(20, 1), Parent: key(10, 1), Comm: "bash"})
	g.Insert(ProcessNode{Key: key(30, 1), Parent: key(20, 1), Comm: "python"})

	ancestors := g.Ancestors(key(30, 1), -1)
	if len(ancestors) != 3 || ancestors[0].Comm != "python" || ancestors[2].Comm != "sshd" {
		t.Errorf("ancestors = %v", ancestors)
	}

	descendants := g.Descendants(key(10, 1), -1)
	if len(descendants) != 2 {
		t.Errorf("descendants = %d, want 2", len(descendants))
	}
}

func TestGraph_DepthLimit(t *testing.T) {
	g := New(Options{})
	g.Insert(ProcessNode{Key: key(1, 1)})
	g.Insert(ProcessNode{Key: key(2, 1), Parent: key(1, 1)})
	g.Insert(ProcessNode{Key: key(3, 1), Parent: key(2, 1)})

	if got := g.Ancestors(key(3, 1), 1); len(got) != 2 { // self + 1 parent
		t.Errorf("depth=1 ancestors = %d, want 2", len(got))
	}
}

func TestGraph_AncestorsCycleGuard(t *testing.T) {
	g := New(Options{})
	// Pathological: A → B → A (shouldn't happen IRL, but guard the walk).
	g.Insert(ProcessNode{Key: key(1, 1), Parent: key(2, 1)})
	g.Insert(ProcessNode{Key: key(2, 1), Parent: key(1, 1)})
	got := g.Ancestors(key(1, 1), -1)
	if len(got) > 2 {
		t.Errorf("cycle should terminate, got %d nodes", len(got))
	}
}

func TestGraph_Indices(t *testing.T) {
	g := New(Options{})
	g.Insert(ProcessNode{
		Key:       key(1, 1),
		CgroupID:  4242,
		LineageID: 100,
		OriginIP:  "10.0.0.5",
		TTY:       "pts/0",
		Comm:      "first",
	})
	g.Insert(ProcessNode{
		Key:       key(2, 1),
		CgroupID:  4242,
		LineageID: 100,
		Comm:      "second",
	})

	if nodes := g.ByCgroup(4242); len(nodes) != 2 {
		t.Errorf("ByCgroup = %v, want 2", len(nodes))
	}
	if nodes := g.ByLineage(lineage.LineageID(100)); len(nodes) != 2 {
		t.Errorf("ByLineage = %v, want 2", len(nodes))
	}
	if nodes := g.ByOriginIP("10.0.0.5"); len(nodes) != 1 {
		t.Errorf("ByOriginIP = %v, want 1", len(nodes))
	}
	if nodes := g.ByTTY("pts/0"); len(nodes) != 1 {
		t.Errorf("ByTTY = %v, want 1", len(nodes))
	}
}

func TestGraph_MarkExitAndTouch(t *testing.T) {
	g := New(Options{})
	g.Insert(ProcessNode{Key: key(1, 1)})

	if !g.MarkExit(key(1, 1), time.Now()) {
		t.Error("MarkExit on live node should return true")
	}
	got, _ := g.Get(key(1, 1))
	if got.State != StateExited || got.ExitedAt.IsZero() {
		t.Errorf("exit not recorded: %+v", got)
	}
	// Second MarkExit: idempotent, returns false.
	if g.MarkExit(key(1, 1), time.Now()) {
		t.Error("MarkExit on already-exited node should return false")
	}

	if !g.Touch(key(1, 1)) {
		t.Error("Touch on existing node should return true")
	}
}

func TestGraph_Remove(t *testing.T) {
	g := New(Options{})
	g.Insert(ProcessNode{Key: key(10, 1), CgroupID: 99, LineageID: 5})
	g.Insert(ProcessNode{Key: key(11, 1), Parent: key(10, 1)})

	if !g.Remove(key(10, 1)) {
		t.Error("Remove of existing should return true")
	}
	if _, ok := g.Get(key(10, 1)); ok {
		t.Error("removed node still in graph")
	}
	if len(g.ByCgroup(99)) != 0 {
		t.Error("Remove should have cleared cgroup index entry")
	}
	if len(g.ByLineage(5)) != 0 {
		t.Error("Remove should have cleared lineage index entry")
	}
}

func TestGraph_MaxNodesRefusesNewWhenFull(t *testing.T) {
	g := New(Options{MaxNodes: 2})
	if !g.Insert(ProcessNode{Key: key(1, 1)}) {
		t.Fatal("first insert should succeed")
	}
	if !g.Insert(ProcessNode{Key: key(2, 1)}) {
		t.Fatal("second insert should succeed")
	}
	if g.Insert(ProcessNode{Key: key(3, 1)}) {
		t.Error("third insert should be refused at cap")
	}
	if g.Stats().Nodes != 2 {
		t.Errorf("nodes = %d, want 2", g.Stats().Nodes)
	}
}

func TestGraph_ConcurrentInsertSafe(t *testing.T) {
	g := New(Options{MaxNodes: 200})
	var wg sync.WaitGroup
	const goroutines = 20
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				pid := uint32(i*50 + j)
				g.Insert(ProcessNode{Key: key(pid, uint64(pid)), Comm: "x"})
				g.Get(key(pid, uint64(pid)))
			}
		}()
	}
	wg.Wait()
	if g.Stats().Inserts == 0 {
		t.Error("expected nonzero inserts after concurrent run")
	}
}

func BenchmarkGraph_Insert(b *testing.B) {
	g := New(Options{MaxNodes: b.N + 100})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Insert(ProcessNode{Key: key(uint32(i), uint64(i))})
	}
}

func BenchmarkGraph_Get(b *testing.B) {
	g := New(Options{})
	g.Insert(ProcessNode{Key: key(1, 1)})
	k := key(1, 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Get(k)
	}
}

func BenchmarkGraph_Ancestors_5deep(b *testing.B) {
	g := New(Options{})
	for i := uint32(1); i <= 5; i++ {
		parent := canonical.ProcKey{}
		if i > 1 {
			parent = key(i-1, 1)
		}
		g.Insert(ProcessNode{Key: key(i, 1), Parent: parent})
	}
	k := key(5, 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Ancestors(k, -1)
	}
}

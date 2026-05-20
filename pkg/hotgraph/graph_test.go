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

func TestGraph_SweepEvictsExitedPastTTL(t *testing.T) {
	g := New(Options{ExitedRetention: 5 * time.Minute})

	// Three exited nodes with different exit times.
	now := time.Now()
	g.Insert(ProcessNode{Key: key(1, 1)})
	g.MarkExit(key(1, 1), now.Add(-10*time.Minute)) // past TTL
	g.Insert(ProcessNode{Key: key(2, 1)})
	g.MarkExit(key(2, 1), now.Add(-1*time.Minute)) // within TTL
	g.Insert(ProcessNode{Key: key(3, 1)})          // still live

	swept := g.Sweep(now)
	if swept != 1 {
		t.Errorf("swept = %d, want 1 (only key 1 past TTL)", swept)
	}
	if _, ok := g.Get(key(1, 1)); ok {
		t.Error("key 1 should have been swept (exited 10min ago, TTL 5min)")
	}
	if _, ok := g.Get(key(2, 1)); !ok {
		t.Error("key 2 should still be present (exited 1min ago, within TTL)")
	}
	if _, ok := g.Get(key(3, 1)); !ok {
		t.Error("key 3 should still be present (live node, sweep ignores)")
	}
	st := g.Stats()
	if st.EvictsExitTTL != 1 {
		t.Errorf("EvictsExitTTL = %d, want 1", st.EvictsExitTTL)
	}
	if st.SweepRuns != 1 {
		t.Errorf("SweepRuns = %d, want 1", st.SweepRuns)
	}
}

func TestGraph_PinProtectsFromSweep(t *testing.T) {
	g := New(Options{ExitedRetention: 5 * time.Minute})
	now := time.Now()
	g.Insert(ProcessNode{Key: key(1, 1)})
	g.MarkExit(key(1, 1), now.Add(-10*time.Minute)) // past TTL
	g.Pin(key(1, 1), now.Add(24*time.Hour))         // protect for 24h

	swept := g.Sweep(now)
	if swept != 0 {
		t.Errorf("pinned node should not be swept, swept=%d", swept)
	}
	if _, ok := g.Get(key(1, 1)); !ok {
		t.Error("pinned node disappeared")
	}
	if !g.IsPinned(key(1, 1)) {
		t.Error("IsPinned should report true")
	}
}

func TestGraph_PinExpiresAndAllowsSweep(t *testing.T) {
	g := New(Options{ExitedRetention: 5 * time.Minute})
	now := time.Now()
	g.Insert(ProcessNode{Key: key(1, 1)})
	g.MarkExit(key(1, 1), now.Add(-10*time.Minute))
	g.Pin(key(1, 1), now.Add(-1*time.Minute)) // pin already expired

	swept := g.Sweep(now)
	if swept != 1 {
		t.Errorf("expired pin should not protect; swept=%d, want 1", swept)
	}
	if g.IsPinned(key(1, 1)) {
		t.Error("expired pin still reporting as pinned")
	}
}

func TestGraph_PinOnlyRatchetsForward(t *testing.T) {
	g := New(Options{})
	now := time.Now()
	later := now.Add(1 * time.Hour)
	earlier := now.Add(10 * time.Minute)

	g.Insert(ProcessNode{Key: key(1, 1)})
	g.Pin(key(1, 1), later)
	g.Pin(key(1, 1), earlier) // shouldn't reduce the pin

	// Internal state: pin should still be `later`.
	g.mu.RLock()
	got := g.pins[key(1, 1)]
	g.mu.RUnlock()
	if !got.Equal(later) {
		t.Errorf("pin reduced from %v to %v", later, got)
	}
}

func TestGraph_LRUEvictsOldestNonLive(t *testing.T) {
	// MaxNodes=10, LRUHighWater=0.80 → trigger at >=8, drain to 7.
	hookFired := []EvictReason{}
	g := New(Options{
		MaxNodes: 10,
		EvictionHook: func(_ canonical.ProcKey, r EvictReason) {
			hookFired = append(hookFired, r)
		},
	})

	// Insert 7 exited nodes with ascending LastSeen.
	now := time.Now()
	for i := uint32(1); i <= 7; i++ {
		g.Insert(ProcessNode{Key: key(i, 1)})
		g.MarkExit(key(i, 1), now.Add(time.Duration(i)*time.Second))
	}
	// One live node (won't be considered by LRU).
	g.Insert(ProcessNode{Key: key(100, 1)})

	// Now at 8 nodes. Next insert hits lruHigh and triggers eviction.
	g.Insert(ProcessNode{Key: key(200, 1)})

	st := g.Stats()
	if st.EvictsLRU == 0 {
		t.Error("expected at least one LRU eviction")
	}
	// Live node and the just-inserted ones must survive.
	if _, ok := g.Get(key(100, 1)); !ok {
		t.Error("LRU should never evict live nodes")
	}
	if _, ok := g.Get(key(200, 1)); !ok {
		t.Error("freshly-inserted key should survive LRU")
	}
	// Oldest exited (key 1 with smallest LastSeen) should be gone.
	if _, ok := g.Get(key(1, 1)); ok {
		t.Error("oldest exited node should have been evicted by LRU")
	}
	// Hook fired with LRU reason.
	gotLRU := false
	for _, r := range hookFired {
		if r == EvictLRU {
			gotLRU = true
		}
	}
	if !gotLRU {
		t.Error("eviction hook never called with EvictLRU")
	}
}

func TestGraph_LRUSkipsPinned(t *testing.T) {
	g := New(Options{MaxNodes: 4}) // high=3, low=2

	now := time.Now()
	for i := uint32(1); i <= 3; i++ {
		g.Insert(ProcessNode{Key: key(i, 1)})
		g.MarkExit(key(i, 1), now.Add(time.Duration(i)*time.Second))
	}
	// Pin the oldest (key 1) — LRU must skip it.
	g.Pin(key(1, 1), now.Add(1*time.Hour))

	// This insert triggers LRU. With key 1 pinned, LRU should pick key 2.
	g.Insert(ProcessNode{Key: key(99, 1)})

	if _, ok := g.Get(key(1, 1)); !ok {
		t.Error("pinned oldest must survive LRU")
	}
	if _, ok := g.Get(key(2, 1)); ok {
		t.Error("second-oldest should have been LRU-evicted (key 1 was pinned)")
	}
}

func TestGraph_CapacityEvictionWhenAllPinnedOrLive(t *testing.T) {
	hookFired := []EvictReason{}
	g := New(Options{
		MaxNodes: 2,
		EvictionHook: func(_ canonical.ProcKey, r EvictReason) {
			hookFired = append(hookFired, r)
		},
	})

	// Fill with two live nodes (LRU can't touch them).
	g.Insert(ProcessNode{Key: key(1, 1)})
	g.Insert(ProcessNode{Key: key(2, 1)})

	// Third insert: LRU has nothing to evict (both live), hard cap kicks in.
	if g.Insert(ProcessNode{Key: key(3, 1)}) {
		t.Error("3rd insert should be refused at hard cap")
	}
	if g.Stats().EvictsCapacity == 0 {
		t.Error("EvictsCapacity counter should have bumped")
	}
	// Hook NOT fired for capacity-refusal (node was never added, so
	// removeLocked never ran — by design).
	if len(hookFired) != 0 {
		t.Errorf("hook should not fire on capacity-refusal, got %v", hookFired)
	}
}

func TestGraph_StatsCountersByReason(t *testing.T) {
	g := New(Options{MaxNodes: 100, ExitedRetention: time.Minute})
	now := time.Now()

	// Make one node, explicit Remove.
	g.Insert(ProcessNode{Key: key(1, 1)})
	g.Remove(key(1, 1))

	// One sweep eviction.
	g.Insert(ProcessNode{Key: key(2, 1)})
	g.MarkExit(key(2, 1), now.Add(-5*time.Minute))
	g.Sweep(now)

	st := g.Stats()
	if st.Evicts != 2 {
		t.Errorf("total Evicts = %d, want 2", st.Evicts)
	}
	if st.EvictsExitTTL != 1 {
		t.Errorf("EvictsExitTTL = %d, want 1", st.EvictsExitTTL)
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

package proctree

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/source"
)

func TestGraphAncestors(t *testing.T) {
	g := New(0)
	// init -> sshd -> bash -> curl
	g.OnSpawn(Node{PID: 1, PPID: 0, Comm: "init"})
	g.OnSpawn(Node{PID: 100, PPID: 1, Comm: "sshd"})
	g.OnSpawn(Node{PID: 200, PPID: 100, Comm: "bash"})
	g.OnSpawn(Node{PID: 300, PPID: 200, Comm: "curl"})

	chain := g.Ancestors(300, 0)
	if len(chain) != 4 {
		t.Fatalf("ancestors len = %d, want 4", len(chain))
	}
	want := []string{"curl", "bash", "sshd", "init"}
	for i, w := range want {
		if chain[i].Comm != w {
			t.Errorf("ancestors[%d] = %q, want %q", i, chain[i].Comm, w)
		}
	}
}

func TestGraphExitReparentsChildren(t *testing.T) {
	g := New(0)
	g.OnSpawn(Node{PID: 1, PPID: 0, Comm: "init"})
	g.OnSpawn(Node{PID: 100, PPID: 1, Comm: "sshd"})
	g.OnSpawn(Node{PID: 200, PPID: 100, Comm: "bash"})

	g.OnExit(100)

	// bash's PPID should now be 1
	chain := g.Ancestors(200, 0)
	if len(chain) != 2 {
		t.Fatalf("after exit, ancestors len = %d, want 2", len(chain))
	}
	if chain[1].Comm != "init" {
		t.Errorf("after reparent, parent = %q, want init", chain[1].Comm)
	}
}

// ─────────────────────────────────────────────────────────────────────
// T02: SourceAnchor propagation tests
// ─────────────────────────────────────────────────────────────────────

func TestSourceAttribution_InheritFromParent(t *testing.T) {
	g := New(0)
	// init has no source. sshd gets the SSH login anchor stamped.
	g.OnSpawn(Node{PID: 1, PPID: 0, Comm: "init"})
	g.OnSpawn(Node{PID: 100, PPID: 1, Comm: "sshd", PrimarySource: lineage.LineageID(42)})

	// A child shell spawned by sshd MUST inherit 42 without explicit
	// stamping (this is the core T02 propagation rule).
	g.OnSpawn(Node{PID: 200, PPID: 100, Comm: "bash"})
	primary, cs := g.SourceOf(200)
	if primary != 42 {
		t.Errorf("child PrimarySource = %d, want 42 (inherited from parent)", primary)
	}
	if cs.Len() != 1 || !cs.Contains(42) {
		t.Errorf("child CausalSet = %v, want {42}", cs.Slice())
	}

	// Spawn a grandchild — inheritance should propagate transitively.
	g.OnSpawn(Node{PID: 300, PPID: 200, Comm: "curl"})
	primary2, _ := g.SourceOf(300)
	if primary2 != 42 {
		t.Errorf("grandchild PrimarySource = %d, want 42 (transitive inherit)", primary2)
	}
}

func TestSourceAttribution_ExplicitOverridesInherit(t *testing.T) {
	g := New(0)
	g.OnSpawn(Node{PID: 100, PPID: 0, Comm: "sshd", PrimarySource: 42})
	// Spawn with an explicit source — this happens when sudo mints its
	// own anchor and the post-sudo shell is attributed to that anchor.
	g.OnSpawn(Node{PID: 200, PPID: 100, Comm: "bash", PrimarySource: 99})

	primary, _ := g.SourceOf(200)
	if primary != 99 {
		t.Errorf("explicit PrimarySource should override parent, got %d want 99", primary)
	}
}

func TestSourceAttribution_NoParentNoInherit(t *testing.T) {
	g := New(0)
	// Orphaned spawn (no known parent) — must stay unattributed.
	g.OnSpawn(Node{PID: 500, PPID: 999999, Comm: "weird"})
	primary, cs := g.SourceOf(500)
	if primary != 0 || !cs.IsEmpty() {
		t.Errorf("orphan should have no source, got primary=%d cs=%v", primary, cs.Slice())
	}
}

func TestAttributeSource_AddsToCausalSet(t *testing.T) {
	g := New(0)
	g.OnSpawn(Node{PID: 100, PPID: 0, Comm: "sshd"})

	// First attribution sets PrimarySource.
	g.AttributeSource(100, lineage.LineageID(7))
	primary, cs := g.SourceOf(100)
	if primary != 7 || cs.Len() != 1 {
		t.Errorf("after first attribution: primary=%d cs.len=%d", primary, cs.Len())
	}

	// Second attribution merges into CausalSet → Ambiguous.
	g.AttributeSource(100, lineage.LineageID(8))
	_, cs2 := g.SourceOf(100)
	if !cs2.Ambiguous() {
		t.Error("two sources should produce Ambiguous CausalSet")
	}
	if !cs2.Contains(7) || !cs2.Contains(8) {
		t.Errorf("CausalSet should contain {7,8}, got %v", cs2.Slice())
	}

	// Zero id is a no-op.
	primaryBefore, _ := g.SourceOf(100)
	g.AttributeSource(100, 0)
	primaryAfter, _ := g.SourceOf(100)
	if primaryBefore != primaryAfter {
		t.Error("AttributeSource(0) must be a no-op")
	}
}

func TestAttributeSource_MissingPidNoop(t *testing.T) {
	g := New(0)
	g.AttributeSource(99999, lineage.LineageID(7)) // must not panic
	primary, cs := g.SourceOf(99999)
	if primary != 0 || !cs.IsEmpty() {
		t.Error("AttributeSource on unknown pid should be silent no-op")
	}
}

func TestMergeCausalSet_FileMediatedTaint(t *testing.T) {
	g := New(0)
	g.OnSpawn(Node{PID: 100, PPID: 0, Comm: "reader"})

	// Simulate: file was written by some session whose anchors are {7,8,9}.
	// The reader picks up the file → its CausalSet absorbs the writer set.
	writerCS := source.NewCausalSet(7, 8, 9)
	changed := g.MergeCausalSet(100, writerCS)
	if !changed {
		t.Error("expected MergeCausalSet to report change")
	}
	_, cs := g.SourceOf(100)
	if cs.Len() != 3 {
		t.Errorf("reader CausalSet size = %d, want 3", cs.Len())
	}
	if !cs.Ambiguous() {
		t.Error("reader after merge should be Ambiguous")
	}

	// Re-merging the identical set must NOT report change.
	if g.MergeCausalSet(100, writerCS) {
		t.Error("idempotent re-merge should report no change")
	}
}

func TestMergeCausalSet_EmptyNoop(t *testing.T) {
	g := New(0)
	g.OnSpawn(Node{PID: 100, PPID: 0, Comm: "x"})
	if g.MergeCausalSet(100, source.CausalSet{}) {
		t.Error("merging empty set should report no change")
	}
}

func TestGraphEviction(t *testing.T) {
	g := New(10)
	for i := uint32(1); i <= 20; i++ {
		g.OnSpawn(Node{PID: i, PPID: 0, Comm: "x"})
	}
	if g.Count() > 10 {
		t.Errorf("count = %d, want <= 10 after eviction", g.Count())
	}
}

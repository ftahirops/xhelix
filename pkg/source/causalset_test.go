package source

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/lineage"
)

func TestCausalSet_EmptyValid(t *testing.T) {
	var c CausalSet
	if !c.IsEmpty() {
		t.Error("zero-value should be empty")
	}
	if c.Len() != 0 {
		t.Errorf("len=%d want 0", c.Len())
	}
	if c.Contains(1) {
		t.Error("empty set should not contain anything")
	}
	if c.Hash() != 0 {
		t.Errorf("empty hash should be 0, got %d", c.Hash())
	}
	if c.Ambiguous() {
		t.Error("empty set should not be ambiguous")
	}
}

func TestCausalSet_AddDedupZeroIgnored(t *testing.T) {
	var c CausalSet
	if c.Add(0) {
		t.Error("Add(0) should be no-op")
	}
	if c.Len() != 0 {
		t.Errorf("len after Add(0): %d, want 0", c.Len())
	}
	if !c.Add(5) {
		t.Error("Add(5) on empty set should return true")
	}
	if c.Add(5) {
		t.Error("Add(5) duplicate should return false")
	}
	if c.Len() != 1 {
		t.Errorf("len after dedup: %d want 1", c.Len())
	}
}

func TestCausalSet_FIFOEviction(t *testing.T) {
	var c CausalSet
	for i := 1; i <= CausalSetCap; i++ {
		c.Add(lineage.LineageID(i))
	}
	if c.Len() != CausalSetCap {
		t.Fatalf("len after fill: %d, want %d", c.Len(), CausalSetCap)
	}
	// Adding one more should drop the oldest (id=1).
	c.Add(lineage.LineageID(CausalSetCap + 1))
	if c.Len() != CausalSetCap {
		t.Errorf("len after overflow: %d, want %d", c.Len(), CausalSetCap)
	}
	if c.Contains(1) {
		t.Error("id=1 should have been FIFO-evicted")
	}
	if !c.Contains(lineage.LineageID(CausalSetCap + 1)) {
		t.Error("newest id should be present")
	}
}

func TestCausalSet_Merge(t *testing.T) {
	a := NewCausalSet(1, 2, 3)
	b := NewCausalSet(3, 4, 5)
	if !a.Merge(b) {
		t.Error("Merge should report change (added 4, 5)")
	}
	if a.Len() != 5 {
		t.Errorf("len after merge: %d, want 5", a.Len())
	}
	for _, want := range []lineage.LineageID{1, 2, 3, 4, 5} {
		if !a.Contains(want) {
			t.Errorf("missing %d after merge", want)
		}
	}
	// Re-merging the same set should be a no-op.
	if a.Merge(b) {
		t.Error("re-merging identical content should not report change")
	}
}

func TestCausalSet_HashOrderIndependent(t *testing.T) {
	a := NewCausalSet(1, 2, 3, 4)
	b := NewCausalSet(4, 3, 2, 1)
	c := NewCausalSet(1, 2, 3, 5)
	if a.Hash() != b.Hash() {
		t.Errorf("order should not affect hash: a=%d b=%d", a.Hash(), b.Hash())
	}
	if a.Hash() == c.Hash() {
		t.Errorf("different members should hash differently: a=%d c=%d", a.Hash(), c.Hash())
	}
}

func TestCausalSet_Equal(t *testing.T) {
	a := NewCausalSet(1, 2, 3)
	b := NewCausalSet(3, 2, 1)
	c := NewCausalSet(1, 2, 4)
	if !a.Equal(b) {
		t.Error("order should not affect Equal")
	}
	if a.Equal(c) {
		t.Error("different sets should not be Equal")
	}
}

func TestCausalSet_Ambiguous(t *testing.T) {
	a := NewCausalSet(7)
	if a.Ambiguous() {
		t.Error("single-source set should NOT be ambiguous")
	}
	a.Add(8)
	if !a.Ambiguous() {
		t.Error("two-source set SHOULD be ambiguous (PrimarySource conflicted)")
	}
}

func TestCausalSet_SliceCopy(t *testing.T) {
	c := NewCausalSet(10, 20, 30)
	out := c.Slice()
	if len(out) != 3 || out[0] != 10 || out[1] != 20 || out[2] != 30 {
		t.Errorf("Slice unexpected: %v", out)
	}
	// Mutating the returned slice must not affect the set.
	out[0] = 999
	if c.Contains(999) || !c.Contains(10) {
		t.Error("Slice should return a copy, not aliased storage")
	}
}

func TestCausalSet_SortedSlice(t *testing.T) {
	c := NewCausalSet(30, 10, 20)
	sorted := c.SortedSlice()
	if len(sorted) != 3 || sorted[0] != 10 || sorted[1] != 20 || sorted[2] != 30 {
		t.Errorf("SortedSlice unexpected: %v", sorted)
	}
}

package source

import (
	"math"
	"testing"
)

// helper: build a small spine tree quickly.
func mkSpine() []SpineNode {
	return []SpineNode{
		{NodeKey: "src-42", Kind: "source", Label: "alice·SSH"},
		{NodeKey: "p-200", Kind: "process", Label: "bash", ParentNodeKey: "src-42"},
		{NodeKey: "p-250", Kind: "process", Label: "sudo", ParentNodeKey: "p-200"},
		{NodeKey: "p-260", Kind: "process", Label: "bash(root)", ParentNodeKey: "p-250"},
		{NodeKey: "p-270", Kind: "process", Label: "curl", ParentNodeKey: "p-260"},
		{NodeKey: "p-280", Kind: "process", Label: "ls", ParentNodeKey: "p-200"},
	}
}

func mkGroups() []GroupNode {
	return []GroupNode{
		{NodeKey: "g-200-files", Kind: KindFileRead, ParentNodeKey: "p-200", Count: 24},
		{NodeKey: "g-200-net", Kind: KindNetConnect, ParentNodeKey: "p-200", Count: 3},
		{NodeKey: "g-260-secret", Kind: KindSecretAccess, ParentNodeKey: "p-260", Count: 1, HighSeverity: true},
	}
}

func TestLayout_EmptyInput(t *testing.T) {
	r := Layout(nil, nil)
	if len(r.Spine) != 0 || len(r.Groups) != 0 {
		t.Errorf("empty input should produce empty output: %+v", r)
	}
}

func TestLayout_RootAtOrigin(t *testing.T) {
	r := Layout([]SpineNode{{NodeKey: "src-1", Kind: "source"}}, nil)
	if len(r.Spine) != 1 {
		t.Fatalf("expected 1 positioned node, got %d", len(r.Spine))
	}
	if r.Spine[0].Y != 0 {
		t.Errorf("root y=%v, want 0", r.Spine[0].Y)
	}
	// Single-root x is centred within its own allocated slot.
	if r.Spine[0].X != float64(LayoutNodeWidth)/2 {
		t.Errorf("root x=%v, want %v", r.Spine[0].X, float64(LayoutNodeWidth)/2)
	}
}

func TestLayout_TopDownTree(t *testing.T) {
	r := Layout(mkSpine(), nil)
	if len(r.Spine) != 6 {
		t.Fatalf("expected 6 positioned spine nodes, got %d", len(r.Spine))
	}
	posByKey := map[string]PositionedSpine{}
	for _, p := range r.Spine {
		posByKey[p.NodeKey] = p
	}
	// Source at y=0; bash one level down; sudo two levels; root-bash three; curl four.
	if posByKey["src-42"].Y != 0 {
		t.Errorf("source y=%v, want 0", posByKey["src-42"].Y)
	}
	if posByKey["p-200"].Y <= posByKey["src-42"].Y {
		t.Errorf("bash should be BELOW source (higher Y)")
	}
	if posByKey["p-250"].Y <= posByKey["p-200"].Y {
		t.Errorf("sudo should be below bash")
	}
	if posByKey["p-260"].Y <= posByKey["p-250"].Y {
		t.Errorf("root-bash should be below sudo")
	}
	if posByKey["p-270"].Y <= posByKey["p-260"].Y {
		t.Errorf("curl should be below root-bash")
	}
}

func TestLayout_SiblingsDontOverlap(t *testing.T) {
	r := Layout(mkSpine(), nil)
	posByKey := map[string]PositionedSpine{}
	for _, p := range r.Spine {
		posByKey[p.NodeKey] = p
	}
	// p-250 (sudo) and p-280 (ls) are both children of p-200. They must
	// be at the same Y and their X values must differ by at least the
	// node width.
	a := posByKey["p-250"]
	b := posByKey["p-280"]
	if a.Y != b.Y {
		t.Errorf("siblings should share Y: %v vs %v", a.Y, b.Y)
	}
	if math.Abs(a.X-b.X) < float64(LayoutNodeWidth) {
		t.Errorf("siblings overlap: |%.1f - %.1f| < %d", a.X, b.X, LayoutNodeWidth)
	}
}

func TestLayout_PetalsToTheRightOfProcess(t *testing.T) {
	r := Layout(mkSpine(), mkGroups())
	posByKey := map[string]PositionedSpine{}
	for _, p := range r.Spine {
		posByKey[p.NodeKey] = p
	}
	for _, g := range r.Groups {
		parent, ok := posByKey[g.ParentNodeKey]
		if !ok {
			t.Errorf("group %s parent %s not in spine", g.NodeKey, g.ParentNodeKey)
			continue
		}
		if g.X <= parent.X {
			t.Errorf("petal %s should be RIGHT of its process (px=%.1f gx=%.1f)",
				g.NodeKey, parent.X, g.X)
		}
		expectedX := parent.X + LayoutPetalOffsetX
		if math.Abs(g.X-expectedX) > 0.001 {
			t.Errorf("petal %s X=%.1f, want %.1f", g.NodeKey, g.X, expectedX)
		}
	}
}

func TestLayout_PetalsStackedVertically(t *testing.T) {
	// PID 200 has two petals (files, net). They should stack: y-positions
	// must differ by LayoutPetalSpacingY.
	r := Layout(mkSpine(), mkGroups())
	var files, net PositionedGroup
	for _, g := range r.Groups {
		if g.NodeKey == "g-200-files" {
			files = g
		}
		if g.NodeKey == "g-200-net" {
			net = g
		}
	}
	if math.Abs((net.Y-files.Y)-float64(LayoutPetalSpacingY)) > 0.001 {
		t.Errorf("petals should stack at %d spacing: files.y=%.1f, net.y=%.1f",
			LayoutPetalSpacingY, files.Y, net.Y)
	}
}

func TestLayout_PetalsTopAlignedWithProcess(t *testing.T) {
	// The first petal on a process should share the process's Y (no
	// vertical offset for the first one — it sits in row 0).
	r := Layout(mkSpine(), mkGroups())
	posByKey := map[string]PositionedSpine{}
	for _, p := range r.Spine {
		posByKey[p.NodeKey] = p
	}
	for _, g := range r.Groups {
		if g.NodeKey != "g-200-files" {
			continue
		}
		if g.Y != posByKey["p-200"].Y {
			t.Errorf("first petal Y should equal process Y: g=%.1f p=%.1f", g.Y, posByKey["p-200"].Y)
		}
	}
}

func TestLayout_OrphanGroupIsSkipped(t *testing.T) {
	groups := []GroupNode{
		{NodeKey: "g-999-orphan", Kind: KindFileRead, ParentNodeKey: "p-99999", Count: 1},
	}
	r := Layout(mkSpine(), groups)
	for _, g := range r.Groups {
		if g.NodeKey == "g-999-orphan" {
			t.Error("orphan group should be skipped, not placed at origin")
		}
	}
}

func TestLayout_LevelPitchGrowsWithPetals(t *testing.T) {
	// If p-200 has many petals, p-250 should be pushed further down than
	// the baseline case (no petals). Run two layouts with the same spine
	// but different petal counts and compare.
	baseSpine := []SpineNode{
		{NodeKey: "src-1", Kind: "source"},
		{NodeKey: "p-1", Kind: "process", ParentNodeKey: "src-1"},
		{NodeKey: "p-2", Kind: "process", ParentNodeKey: "p-1"},
	}
	noPetals := Layout(baseSpine, nil)
	manyPetals := Layout(baseSpine, []GroupNode{
		{NodeKey: "g-1-a", ParentNodeKey: "p-1", Kind: KindFileRead},
		{NodeKey: "g-1-b", ParentNodeKey: "p-1", Kind: KindNetConnect},
		{NodeKey: "g-1-c", ParentNodeKey: "p-1", Kind: KindCapChange},
	})
	posBase := map[string]PositionedSpine{}
	for _, p := range noPetals.Spine {
		posBase[p.NodeKey] = p
	}
	posMany := map[string]PositionedSpine{}
	for _, p := range manyPetals.Spine {
		posMany[p.NodeKey] = p
	}
	if posMany["p-2"].Y <= posBase["p-2"].Y {
		t.Errorf("child should be pushed down when parent has petals: base=%.1f many=%.1f",
			posBase["p-2"].Y, posMany["p-2"].Y)
	}
}

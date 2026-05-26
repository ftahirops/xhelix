package source

import "math"

// Layout constants are in "abstract units" — the client multiplies by a
// render scale to fit the viewport. Numbers tuned so a typical session
// (~10 spine nodes, ~30 petals) renders at ~800px wide × ~600px tall at
// 1× scale.
const (
	// Vertical spacing between depth levels of the spine tree. The
	// effective per-node vertical pitch is LayoutLevelBase + petals *
	// LayoutPetalSpacingY (so a process with many petals reserves more
	// room before its children fall below).
	LayoutLevelBase    = 100
	LayoutPetalSpacingY = 36   // y-spacing between petals attached to the same process
	LayoutPetalOffsetX  = 130  // x-distance from spine node to petal column

	// Horizontal layout.
	LayoutSiblingGap = 60  // x-gap between sibling subtrees
	LayoutNodeWidth  = 110 // x-width allocated to a single spine node
)

// PositionedSpine extends SpineNode with absolute (X, Y) coordinates.
type PositionedSpine struct {
	SpineNode
	X, Y float64
}

// PositionedGroup extends GroupNode with absolute (X, Y) coordinates.
type PositionedGroup struct {
	GroupNode
	X, Y float64
}

// LayoutResult is the positioned scene the API returns. The client
// (Sigma.js + graphology) iterates the slices and adds nodes; the edges
// are derived from ParentNodeKey relationships on the client.
type LayoutResult struct {
	Spine  []PositionedSpine
	Groups []PositionedGroup
}

// Layout positions a spine + groups tree for the spine+petals
// visualization.
//
// Algorithm: classic two-pass Reingold-Tilford-lite.
//
//   Pass 1 (post-order): compute each subtree's horizontal width as
//   max(LayoutNodeWidth, sum of children widths + gaps).
//
//   Pass 2 (pre-order): assign x as the centre of the parent's allocated
//   slot, y as parent.y + level pitch (which grows with the parent's
//   petal count).
//
// After spine placement, petals are laid out as a vertical column to the
// right of each process node, indexed by GroupNode order in the input.
//
// Origin: the source anchor node lands at (0, 0). Spine grows downward
// (positive y). Petals grow rightward (positive x) from each process.
//
// Spine must contain at least one node (the source). If it's empty,
// Layout returns a zero-value LayoutResult.
func Layout(spine []SpineNode, groups []GroupNode) LayoutResult {
	if len(spine) == 0 {
		return LayoutResult{}
	}

	// Build node map + parent→children.
	type ln struct {
		spine    SpineNode
		children []*ln
		petals   int
		width    float64
		x, y     float64
	}
	nodes := make(map[string]*ln, len(spine))
	for _, s := range spine {
		nodes[s.NodeKey] = &ln{spine: s}
	}
	for _, g := range groups {
		if n, ok := nodes[g.ParentNodeKey]; ok {
			n.petals++
		}
	}
	var root *ln
	for _, s := range spine {
		n := nodes[s.NodeKey]
		if s.ParentNodeKey == "" || s.ParentNodeKey == s.NodeKey {
			root = n
			continue
		}
		if p, ok := nodes[s.ParentNodeKey]; ok {
			p.children = append(p.children, n)
		} else if root == nil {
			// First-pass orphan: treat as root. SpineFor's reparenting
			// rule should make this rare.
			root = n
		}
	}
	if root == nil {
		// Defensive: take the first spine entry as root.
		root = nodes[spine[0].NodeKey]
	}

	// Pass 1: subtree widths (post-order).
	var widthOf func(*ln) float64
	widthOf = func(n *ln) float64 {
		if len(n.children) == 0 {
			n.width = LayoutNodeWidth
			return n.width
		}
		var sum float64
		for i, c := range n.children {
			if i > 0 {
				sum += LayoutSiblingGap
			}
			sum += widthOf(c)
		}
		n.width = math.Max(LayoutNodeWidth, sum)
		return n.width
	}
	widthOf(root)

	// Pass 2: assign positions (pre-order).
	var assign func(n *ln, leftX, y float64)
	assign = func(n *ln, leftX, y float64) {
		n.x = leftX + n.width/2
		n.y = y
		if len(n.children) == 0 {
			return
		}
		// Centre children within the parent's allocated slot.
		var childTotal float64
		for i, c := range n.children {
			if i > 0 {
				childTotal += LayoutSiblingGap
			}
			childTotal += c.width
		}
		startX := leftX + (n.width-childTotal)/2
		childY := y + levelPitch(n.petals)
		cur := startX
		for _, c := range n.children {
			assign(c, cur, childY)
			cur += c.width + LayoutSiblingGap
		}
	}
	assign(root, 0, 0)

	// Build positioned spine output in the original spine order so the
	// API stream produces a stable ordering.
	posSpine := make([]PositionedSpine, 0, len(spine))
	for _, s := range spine {
		n, ok := nodes[s.NodeKey]
		if !ok {
			continue
		}
		posSpine = append(posSpine, PositionedSpine{SpineNode: s, X: n.x, Y: n.y})
	}

	// Petals: vertical column to the right of each process node.
	// Index within process is the order in `groups`.
	idxByParent := map[string]int{}
	posGroups := make([]PositionedGroup, 0, len(groups))
	for _, g := range groups {
		n, ok := nodes[g.ParentNodeKey]
		if !ok {
			// Orphan group — skip rather than place it at origin.
			continue
		}
		i := idxByParent[g.ParentNodeKey]
		idxByParent[g.ParentNodeKey]++
		posGroups = append(posGroups, PositionedGroup{
			GroupNode: g,
			X:         n.x + LayoutPetalOffsetX,
			Y:         n.y + float64(i)*LayoutPetalSpacingY,
		})
	}

	return LayoutResult{Spine: posSpine, Groups: posGroups}
}

// levelPitch returns the y-distance from a spine node to its direct
// children. Grows with petal count so a heavily-petalled process
// reserves enough room that its children don't overlap its own
// activity column.
func levelPitch(petals int) float64 {
	base := float64(LayoutLevelBase)
	// Each petal claims a slot, capped: beyond 5 petals we don't add
	// more pitch (the petals get scrolled within the side panel; the
	// graph layout doesn't need to grow unboundedly).
	if petals > 5 {
		petals = 5
	}
	return base + float64(petals)*LayoutPetalSpacingY
}

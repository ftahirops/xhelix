package source

import (
	"encoding/binary"
	"hash/fnv"
	"sort"

	"github.com/xhelix/xhelix/pkg/lineage"
)

// CausalSetCap bounds the maximum number of source anchors a CausalSet
// can hold. Set deliberately small: most processes have 1-3 contributing
// sources; values above ~16 indicate either pathological multi-source
// merging or graph poisoning and should be treated as a signal in
// themselves rather than a thing to faithfully reproduce.
//
// When Add() pushes a fresh id past the cap, the OLDEST id is dropped
// (FIFO on insertion order). This keeps the most recent attribution
// information at the cost of losing the original root in
// deeply-merged chains. Acceptable trade — the v2 source lineage
// architecture says deep merge means "primary source is ambiguous",
// which is a separate flag.
const CausalSetCap = 16

// CausalSet is the append-only, bounded, deduplicated set of SourceAnchor
// IDs that have contributed to the current actor's provenance.
//
// Empty value is valid. CausalSet is NOT safe for concurrent use; the
// caller (typically pkg/proctree under its own lock) is responsible for
// serialising access.
//
// The internal representation is a slice held in insertion order so
// Add() can implement FIFO eviction on overflow. Operations that need
// stable hashing or set semantics (Equal, Hash, Contains) sort a copy.
type CausalSet struct {
	ids []lineage.LineageID
}

// NewCausalSet constructs a CausalSet from the given ids, deduplicated
// and bounded to CausalSetCap. The first CausalSetCap unique entries
// are kept; any duplicates after that are ignored.
func NewCausalSet(ids ...lineage.LineageID) CausalSet {
	var c CausalSet
	for _, id := range ids {
		c.Add(id)
	}
	return c
}

// Len returns the number of distinct ids in the set.
func (c *CausalSet) Len() int {
	return len(c.ids)
}

// IsEmpty returns true if the set has no entries.
func (c *CausalSet) IsEmpty() bool {
	return len(c.ids) == 0
}

// Contains returns true if id is in the set.
func (c *CausalSet) Contains(id lineage.LineageID) bool {
	for _, existing := range c.ids {
		if existing == id {
			return true
		}
	}
	return false
}

// Add inserts id if not already present. If the set is at CausalSetCap
// and id is new, the OLDEST entry is dropped (FIFO eviction). Adding 0
// is a no-op — zero is not a valid LineageID.
//
// Returns true if id was newly added (i.e. caused a change to the set).
func (c *CausalSet) Add(id lineage.LineageID) bool {
	if id == 0 {
		return false
	}
	if c.Contains(id) {
		return false
	}
	if len(c.ids) >= CausalSetCap {
		// FIFO drop.
		c.ids = c.ids[1:]
	}
	c.ids = append(c.ids, id)
	return true
}

// Merge OR-merges other into c. Returns true if any id from other was
// newly added. FIFO eviction applies in insertion order.
func (c *CausalSet) Merge(other CausalSet) bool {
	changed := false
	for _, id := range other.ids {
		if c.Add(id) {
			changed = true
		}
	}
	return changed
}

// Slice returns a fresh copy of the ids in insertion order. Safe to
// publish to callers; modifications to the returned slice do not affect
// the set.
func (c *CausalSet) Slice() []lineage.LineageID {
	if len(c.ids) == 0 {
		return nil
	}
	out := make([]lineage.LineageID, len(c.ids))
	copy(out, c.ids)
	return out
}

// SortedSlice returns the ids in ascending numeric order. Used for
// hashing + equality. Caller may mutate the returned slice freely.
func (c *CausalSet) SortedSlice() []lineage.LineageID {
	if len(c.ids) == 0 {
		return nil
	}
	out := make([]lineage.LineageID, len(c.ids))
	copy(out, c.ids)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Hash returns a stable 64-bit fingerprint of the set, order-independent.
// Two CausalSets with the same members (in any insertion order) hash to
// the same value. Used as the writer_source_set_hash provenance tag for
// file-mediated causality.
func (c *CausalSet) Hash() uint64 {
	if len(c.ids) == 0 {
		return 0
	}
	sorted := c.SortedSlice()
	h := fnv.New64a()
	var buf [8]byte
	for _, id := range sorted {
		binary.LittleEndian.PutUint64(buf[:], uint64(id))
		_, _ = h.Write(buf[:])
	}
	return h.Sum64()
}

// Equal returns true if c and other have identical members, regardless
// of insertion order.
func (c *CausalSet) Equal(other CausalSet) bool {
	if len(c.ids) != len(other.ids) {
		return false
	}
	a := c.SortedSlice()
	b := other.SortedSlice()
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Ambiguous returns true if the set has at least two distinct sources.
// "PrimarySource is ambiguous" is the v2 signal that injection or
// file-mediated multi-source merging has occurred, and the rule engine
// must treat the actor's provenance as compromised.
func (c *CausalSet) Ambiguous() bool {
	return len(c.ids) >= 2
}

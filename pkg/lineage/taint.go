package lineage

import (
	"errors"
	"sync"
)

// TaintBit is a position within a TaintSet bitset. Valid values are
// 0..63 inclusive; the class registry refuses to assign more than 64.
type TaintBit uint8

// MaxTaintBits is the hard ceiling on distinct data classes a single
// daemon can track. The DLCF data catalog v1 ships ~10 classes, so
// 64 leaves comfortable room.
const MaxTaintBits = 64

// TaintSet is a bitset of data classes touched within a lineage's
// lifetime. The zero value is an empty set ("untainted").
//
// All operations are pure value transforms; concurrent mutation of a
// taint set in shared memory must be guarded by the caller (Store
// does this via its mutex).
type TaintSet uint64

// Has reports whether bit b is set.
func (t TaintSet) Has(b TaintBit) bool { return t&(1<<b) != 0 }

// With returns a new TaintSet with bit b added.
func (t TaintSet) With(b TaintBit) TaintSet { return t | (1 << b) }

// Union returns the bitwise union of two TaintSets.
func (t TaintSet) Union(o TaintSet) TaintSet { return t | o }

// Intersects reports whether any bit is set in both sets.
func (t TaintSet) Intersects(o TaintSet) bool { return t&o != 0 }

// IsEmpty reports whether the set has no bits set.
func (t TaintSet) IsEmpty() bool { return t == 0 }

// Count returns the number of set bits (popcount).
func (t TaintSet) Count() int {
	x := uint64(t)
	x = x - ((x >> 1) & 0x5555555555555555)
	x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
	x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
	return int((x * 0x0101010101010101) >> 56)
}

// Bits returns the bit positions set in t, in ascending order. Useful
// for rendering ("which classes is this lineage tainted with?").
func (t TaintSet) Bits() []TaintBit {
	out := make([]TaintBit, 0, t.Count())
	for i := TaintBit(0); i < MaxTaintBits; i++ {
		if t.Has(i) {
			out = append(out, i)
		}
	}
	return out
}

// ErrClassRegistryFull is returned when an attempt is made to register
// a new class name after 64 distinct names have already been recorded.
var ErrClassRegistryFull = errors.New("lineage: class registry full (64 max)")

// ClassRegistry maps catalog data-class names (e.g. "pii",
// "credentials") to TaintBit positions. Bits are assigned in
// first-seen order; the mapping is stable for the lifetime of the
// daemon. Safe for concurrent use.
//
// The registry is decoupled from pkg/catalog so that lineage doesn't
// import catalog (which would create a dependency cycle if catalog
// later wants to reference lineage types).
type ClassRegistry struct {
	mu     sync.RWMutex
	byName map[string]TaintBit
	byBit  [MaxTaintBits]string
	next   TaintBit
}

// NewClassRegistry constructs an empty registry. Callers typically
// register the well-known DLCF class names eagerly at startup so the
// bit assignment is deterministic across restarts that load the same
// catalog.
func NewClassRegistry() *ClassRegistry {
	return &ClassRegistry{byName: make(map[string]TaintBit, 16)}
}

// Bit returns the bit position assigned to name, allocating a new one
// if name is not yet known. Returns ErrClassRegistryFull if the
// registry is at capacity and name is new.
func (r *ClassRegistry) Bit(name string) (TaintBit, error) {
	r.mu.RLock()
	if b, ok := r.byName[name]; ok {
		r.mu.RUnlock()
		return b, nil
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	// Re-check under the write lock to handle the race where two
	// goroutines both miss on the read side.
	if b, ok := r.byName[name]; ok {
		return b, nil
	}
	if int(r.next) >= MaxTaintBits {
		return 0, ErrClassRegistryFull
	}
	b := r.next
	r.byName[name] = b
	r.byBit[b] = name
	r.next++
	return b, nil
}

// Name returns the class name associated with bit b, or "" if no
// class has been assigned to that bit.
func (r *ClassRegistry) Name(b TaintBit) string {
	if b >= MaxTaintBits {
		return ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byBit[b]
}

// SetFromNames builds a TaintSet from a slice of class names,
// registering any unknown names on demand. Returns the set and the
// first registration error, if any (the set will reflect only the
// successfully-resolved names).
func (r *ClassRegistry) SetFromNames(names []string) (TaintSet, error) {
	var ts TaintSet
	var firstErr error
	for _, n := range names {
		b, err := r.Bit(n)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ts = ts.With(b)
	}
	return ts, firstErr
}

// Names returns the registered class names in bit-position order.
// Useful for rendering and for the health.snapshot LocalAPI surface.
func (r *ClassRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, r.next)
	for i := TaintBit(0); i < r.next; i++ {
		out[i] = r.byBit[i]
	}
	return out
}

// NamesOf returns the human-readable class names corresponding to the
// bits set in t.
func (r *ClassRegistry) NamesOf(t TaintSet) []string {
	bits := t.Bits()
	out := make([]string, 0, len(bits))
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, b := range bits {
		if name := r.byBit[b]; name != "" {
			out = append(out, name)
		}
	}
	return out
}

// Size returns the number of registered classes.
func (r *ClassRegistry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return int(r.next)
}

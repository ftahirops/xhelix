package source

import (
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/lineage"
)

// FileProvenance is the bounded per-path provenance record. Stored in
// the in-memory tracker for active sessions; the v2 source-lineage
// architecture says we must NOT permanently tag every file with full
// graph detail. RecordedAt drives TTL eviction.
type FileProvenance struct {
	// LastWriterPrimary is the writer's PrimarySource at write time.
	// Used as the canonical "who last touched this" hint for operator
	// display and quick scoring.
	LastWriterPrimary lineage.LineageID

	// Set is the writer's full CausalSet at write time, bounded to
	// CausalSetCap. A reader that picks up this file MergeCausalSet's
	// this into its own provenance.
	Set CausalSet

	// SetHash is the order-independent fingerprint of Set. Used as
	// the writer_source_set_hash provenance tag for file-mediated
	// causality without copying the full set everywhere.
	SetHash uint64

	// RecordedAt is the wall-clock time of the recorded write. Drives
	// TTL eviction in SweepOlderThan.
	RecordedAt time.Time
}

// FileTaint is the bounded in-memory tracker of per-path provenance.
//
// Operations:
//
//   - RecordWrite(path, primary, set, t)  — called on FIM write events
//     for tracked high-value paths. Overwrites any prior record (writes
//     are append-style: the last writer is the relevant one).
//   - Lookup(path) — called on file-read events to fetch the writer's
//     CausalSet for taint inheritance.
//
// The tracker is bounded by Cap (FIFO eviction of oldest path on
// overflow) and TTL (entries older than the configured horizon are
// dropped on the next SweepOlderThan tick). Both bounds matter — the
// tracker must NEVER grow without limit on a busy server.
//
// Safe for concurrent use.
type FileTaint struct {
	mu    sync.RWMutex
	paths map[string]*FileProvenance
	order []string // FIFO insertion order, oldest first
	cap   int
	ttl   time.Duration
}

// DefaultFileTaintCap is the default per-tracker path budget. Tuned for
// "track ~50 high-value paths plus headroom for legitimate operator
// activity". Operators with huge custom watch sets can override via
// NewFileTaint.
const DefaultFileTaintCap = 4096

// DefaultFileTaintTTL is the default TTL for recorded provenance. After
// this horizon a write is considered too old to attribute reads to —
// the writer's session has almost certainly ended and the file has
// likely been touched by other processes since.
const DefaultFileTaintTTL = 24 * time.Hour

// NewFileTaint returns a FileTaint tracker. cap <= 0 selects
// DefaultFileTaintCap; ttl <= 0 selects DefaultFileTaintTTL.
func NewFileTaint(cap int, ttl time.Duration) *FileTaint {
	if cap <= 0 {
		cap = DefaultFileTaintCap
	}
	if ttl <= 0 {
		ttl = DefaultFileTaintTTL
	}
	return &FileTaint{
		paths: make(map[string]*FileProvenance, 256),
		order: make([]string, 0, 256),
		cap:   cap,
		ttl:   ttl,
	}
}

// RecordWrite records that path was written by primary+set at t. If
// path already has a record, it is replaced (writes are append-style).
// A primary of 0 with an empty set is treated as "no useful provenance"
// and the call is a no-op.
func (f *FileTaint) RecordWrite(path string, primary lineage.LineageID, set CausalSet, t time.Time) {
	if path == "" {
		return
	}
	if primary == 0 && set.IsEmpty() {
		return
	}
	if t.IsZero() {
		t = time.Now().UTC()
	}
	rec := &FileProvenance{
		LastWriterPrimary: primary,
		Set:               NewCausalSet(set.Slice()...),
		SetHash:           set.Hash(),
		RecordedAt:        t,
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Replace-in-place if known: keep ordering position the same so
	// FIFO eviction reflects first-seen, not last-seen.
	if _, ok := f.paths[path]; ok {
		f.paths[path] = rec
		return
	}
	// New entry: evict from head if at cap.
	for len(f.paths) >= f.cap && len(f.order) > 0 {
		head := f.order[0]
		f.order = f.order[1:]
		delete(f.paths, head)
	}
	f.paths[path] = rec
	f.order = append(f.order, path)
}

// Lookup returns the provenance for path. Returns (zero, false) if path
// is unknown or its record has expired (TTL). TTL is enforced lazily —
// the entry is left in the map until SweepOlderThan runs, but a stale
// lookup still returns false.
func (f *FileTaint) Lookup(path string) (FileProvenance, bool) {
	if path == "" {
		return FileProvenance{}, false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	rec, ok := f.paths[path]
	if !ok {
		return FileProvenance{}, false
	}
	if time.Since(rec.RecordedAt) > f.ttl {
		return FileProvenance{}, false
	}
	return *rec, true
}

// Size returns the current number of tracked paths.
func (f *FileTaint) Size() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.paths)
}

// SweepOlderThan removes entries with RecordedAt < cutoff. Returns the
// number removed. Caller drives the cadence (typically once per hour).
func (f *FileTaint) SweepOlderThan(cutoff time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	removed := 0
	kept := f.order[:0]
	for _, p := range f.order {
		rec, ok := f.paths[p]
		if !ok {
			continue
		}
		if rec.RecordedAt.Before(cutoff) {
			delete(f.paths, p)
			removed++
			continue
		}
		kept = append(kept, p)
	}
	f.order = kept
	return removed
}

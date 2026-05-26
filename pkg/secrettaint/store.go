package secrettaint

import (
	"log/slog"
	"sync"
	"time"
)

// memStore is the in-memory Store implementation. Per-lineage entries
// live in a map protected by RWMutex.
//
// State persistence: in-memory only. Daemon restart loses taint state.
// This is intentional — restart implies operator intervention; incidents
// already emitted are recorded in the forensic chain. A future enhancement
// may add a short-lived durable journal for restart recovery, but it's
// not in Phase B.2 scope.
type memStore struct {
	mu      sync.RWMutex
	entries map[uint64]*entry
	maxAge  time.Duration
}

type entry struct {
	state    TaintState
	classes  map[SecretClass]struct{}
	lastSeen time.Time
	history  []historyRecord
}

type historyRecord struct {
	at     time.Time
	kind   string // "touch" | "promote" | "inherit" | "forget"
	detail string
}

// NewStore returns a fresh in-memory Store with the given max-age TTL.
// maxAge<=0 disables TTL pruning (taint persists until process exit or
// operator override). Recommended: 12-24h for typical workloads.
func NewStore(maxAge time.Duration) Store {
	return &memStore{
		entries: make(map[uint64]*entry),
		maxAge:  maxAge,
	}
}

func (s *memStore) ObserveTouch(t Touch) {
	if t.LineageID == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.getOrCreate(t.LineageID)
	if e.state == TaintClean {
		e.state = TaintSecretTouched
	}
	e.classes[t.SecretClass] = struct{}{}
	e.lastSeen = t.At
	e.appendHistory(t.At, "touch", string(t.SecretClass))
}

func (s *memStore) StateForLineage(lineage uint64) TaintState {
	if lineage == 0 {
		return TaintClean
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[lineage]
	if !ok {
		return TaintClean
	}
	return e.state
}

func (s *memStore) ClassesForLineage(lineage uint64) []SecretClass {
	if lineage == 0 {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[lineage]
	if !ok || len(e.classes) == 0 {
		return nil
	}
	out := make([]SecretClass, 0, len(e.classes))
	for c := range e.classes {
		out = append(out, c)
	}
	return out
}

func (s *memStore) PromoteOutboundRestricted(lineage uint64, at time.Time, reason string) {
	if lineage == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[lineage]
	if !ok {
		return
	}
	if e.state >= TaintOutboundRestricted {
		return
	}
	e.state = TaintOutboundRestricted
	e.lastSeen = at
	e.appendHistory(at, "promote", "outbound_restricted: "+reason)
	slog.Info("secrettaint promote",
		"lineage", lineage, "state", e.state.String(), "reason", reason)
}

func (s *memStore) PromoteContainmentRequired(lineage uint64, at time.Time, reason string) {
	if lineage == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[lineage]
	if !ok {
		return
	}
	if e.state >= TaintContainmentRequired {
		return
	}
	e.state = TaintContainmentRequired
	e.lastSeen = at
	e.appendHistory(at, "promote", "containment_required: "+reason)
	slog.Warn("secrettaint containment required",
		"lineage", lineage, "reason", reason)
}

func (s *memStore) InheritFromParent(parentLineage, childLineage uint64) {
	if parentLineage == 0 || childLineage == 0 || parentLineage == childLineage {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	parent, ok := s.entries[parentLineage]
	if !ok || parent.state == TaintClean {
		return
	}
	child := s.getOrCreate(childLineage)
	if child.state < parent.state {
		child.state = parent.state
	}
	for c := range parent.classes {
		child.classes[c] = struct{}{}
	}
	now := time.Now().UTC()
	child.lastSeen = now
	child.appendHistory(now, "inherit", "from parent lineage")
}

func (s *memStore) ForgetLineage(lineage uint64, reason ForgetReason) bool {
	if lineage == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[lineage]
	if !ok {
		return false
	}
	wasTainted := e.state != TaintClean
	delete(s.entries, lineage)
	slog.Info("secrettaint forget",
		"lineage", lineage,
		"reason", reason.String(),
		"was_state", e.state.String(),
		"classes", len(e.classes))
	return wasTainted
}

func (s *memStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Sweep clears entries older than maxAge. Returns count reclaimed.
// Caller should run periodically (e.g. hourly).
func (s *memStore) Sweep(now time.Time) int {
	if s.maxAge <= 0 {
		return 0
	}
	cutoff := now.Add(-s.maxAge)
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for lineage, e := range s.entries {
		if e.lastSeen.Before(cutoff) {
			delete(s.entries, lineage)
			n++
			slog.Info("secrettaint forget",
				"lineage", lineage,
				"reason", ForgetTTLExpiry.String(),
				"was_state", e.state.String(),
				"age", now.Sub(e.lastSeen).String())
		}
	}
	return n
}

// History returns a copy of recent history records for lineage.
func (s *memStore) History(lineage uint64) []historyRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[lineage]
	if !ok {
		return nil
	}
	out := make([]historyRecord, len(e.history))
	copy(out, e.history)
	return out
}

func (s *memStore) getOrCreate(lineage uint64) *entry {
	e, ok := s.entries[lineage]
	if !ok {
		e = &entry{
			state:   TaintClean,
			classes: make(map[SecretClass]struct{}),
		}
		s.entries[lineage] = e
	}
	return e
}

const historyMax = 16

func (e *entry) appendHistory(at time.Time, kind, detail string) {
	e.history = append(e.history, historyRecord{at: at, kind: kind, detail: detail})
	if len(e.history) > historyMax {
		e.history = e.history[len(e.history)-historyMax:]
	}
}

// AsMemStore exposes the memStore concrete type for test/CLI code that
// needs Sweep + History. Kept off the Store interface to keep the
// interface minimal.
func AsMemStore(s Store) *memStore {
	m, _ := s.(*memStore)
	return m
}

// HistoryRecord exports the audit record for CLI consumers.
type HistoryRecord struct {
	At     time.Time
	Kind   string
	Detail string
}

// HistoryFor returns audit records for lineage (CLI helper).
func HistoryFor(s Store, lineage uint64) []HistoryRecord {
	m := AsMemStore(s)
	if m == nil {
		return nil
	}
	raw := m.History(lineage)
	out := make([]HistoryRecord, len(raw))
	for i, r := range raw {
		out[i] = HistoryRecord{At: r.at, Kind: r.kind, Detail: r.detail}
	}
	return out
}

// AllTainted returns the lineage IDs currently tracked (test + CLI).
func AllTainted(s Store) []uint64 {
	m := AsMemStore(s)
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]uint64, 0, len(m.entries))
	for l := range m.entries {
		out = append(out, l)
	}
	return out
}

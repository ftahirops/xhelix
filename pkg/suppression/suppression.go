// Package suppression is the analyst-feedback loop. When an
// operator marks a finding "benign", the same (rule, exe, dst)
// pattern stays suppressed for the configured TTL — so noisy
// rules don't keep firing once they've been triaged.
//
// Storage model: keyed by a deterministic suppression key (caller-
// controlled). Default key is (rule_id, exe_sha, dst_ip) but
// custom KeyFunc lets operators broaden ("any dst") or narrow
// ("only this exact pid") the scope.
//
// TTLs are explicit per entry, not global, so a one-off
// "suppress for 1 hour while I investigate" coexists with a
// "permanent allowlist for this CDN."
//
// Pure-Go, goroutine-safe, persistence-agnostic. Snapshot/Load
// pair lets the daemon persist suppression decisions across
// restarts.
package suppression

import (
	"sort"
	"sync"
	"time"
)

// Key identifies what to suppress. Callers usually build it via
// DefaultKey but can supply any string.
type Key string

// Reason is the operator-supplied "why this is benign" text.
type Reason string

// Entry is one active suppression.
type Entry struct {
	Key       Key
	Reason    Reason
	CreatedAt time.Time
	ExpiresAt time.Time // zero = never expires
	Operator  string    // who added it
}

// IsExpired returns true when the entry's TTL has passed.
func (e Entry) IsExpired(now time.Time) bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return now.After(e.ExpiresAt)
}

// Store is the suppression registry.
type Store struct {
	mu      sync.RWMutex
	entries map[Key]Entry
	now     func() time.Time
}

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{entries: map[Key]Entry{}, now: time.Now}
}

// Add inserts or replaces a suppression entry. ttl <=0 means
// "never expires."
func (s *Store) Add(key Key, reason Reason, ttl time.Duration, operator string) Entry {
	if key == "" {
		return Entry{}
	}
	now := s.now()
	e := Entry{
		Key: key, Reason: reason,
		CreatedAt: now,
		Operator:  operator,
	}
	if ttl > 0 {
		e.ExpiresAt = now.Add(ttl)
	}
	s.mu.Lock()
	s.entries[key] = e
	s.mu.Unlock()
	return e
}

// Remove drops a suppression entry. Returns true if anything was
// removed.
func (s *Store) Remove(key Key) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[key]; !ok {
		return false
	}
	delete(s.entries, key)
	return true
}

// Suppressed reports whether key is currently suppressed. Lazily
// evicts expired entries.
func (s *Store) Suppressed(key Key) (Entry, bool) {
	now := s.now()
	s.mu.RLock()
	e, ok := s.entries[key]
	s.mu.RUnlock()
	if !ok {
		return Entry{}, false
	}
	if e.IsExpired(now) {
		s.mu.Lock()
		// Double-check under write lock — another goroutine may
		// have refreshed in the meantime.
		if cur, ok := s.entries[key]; ok && cur.IsExpired(now) {
			delete(s.entries, key)
		}
		s.mu.Unlock()
		return Entry{}, false
	}
	return e, true
}

// List returns every active (non-expired) entry, sorted by Key.
func (s *Store) List() []Entry {
	now := s.now()
	s.mu.RLock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if !e.IsExpired(now) {
			out = append(out, e)
		}
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Sweep evicts expired entries; returns the count removed.
func (s *Store) Sweep() int {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for k, e := range s.entries {
		if e.IsExpired(now) {
			delete(s.entries, k)
			removed++
		}
	}
	return removed
}

// Snapshot returns a deep copy for persistence.
func (s *Store) Snapshot() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Load replaces all entries from a snapshot.
func (s *Store) Load(snap []Entry) {
	m := make(map[Key]Entry, len(snap))
	for _, e := range snap {
		m[e.Key] = e
	}
	s.mu.Lock()
	s.entries = m
	s.mu.Unlock()
}

// Reset clears all entries.
func (s *Store) Reset() {
	s.mu.Lock()
	s.entries = map[Key]Entry{}
	s.mu.Unlock()
}

// Len returns the active entry count.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// DefaultKey builds the canonical suppression key from rule + exe
// + dst. Empty fields render as "*" so a "rule=X exe=* dst=Y"
// suppression broadens scope intentionally.
func DefaultKey(ruleID, exeSHA, dstIP string) Key {
	if ruleID == "" {
		ruleID = "*"
	}
	if exeSHA == "" {
		exeSHA = "*"
	}
	if dstIP == "" {
		dstIP = "*"
	}
	return Key(ruleID + "|" + exeSHA + "|" + dstIP)
}

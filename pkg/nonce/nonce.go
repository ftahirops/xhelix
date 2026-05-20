// Package nonce implements single-use HMAC-signed nonces for
// replay-resistance on sensitive endpoints, per
// BEHAVIORAL_DEFENSE.md §3.3 (P-B.2). Tier-1 deterministic
// detection: a nonce is either fresh, replayed, or invalid — no
// statistical inference.
//
// Lifecycle:
//
//  1. Endpoint mints a Nonce on the request that PRECEDES a
//     sensitive action (e.g., the form-render request that will be
//     followed by the form-submit).
//  2. Browser carries the nonce token (typically embedded in the
//     form or returned as a header) to the next request.
//  3. Endpoint calls Consume on the submit. First Consume returns
//     ConsumeOK and burns the nonce. Any later Consume returns
//     ConsumeReplayed — even a millisecond later, even from the
//     same source.
//
// Why this is Tier-1: stolen cookies on their own do NOT carry a
// fresh nonce. Replaying a captured request fails the moment we
// see the nonce twice.
//
// Honest limitation: this doesn't defend against live MITM attackers
// (EvilProxy-style) that sit between the user and the app and
// observe the fresh nonce each time. For that you need WebAuthn
// (P-B.0a) which requires hardware-bound per-action signatures.
package nonce

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultTTL is the lifetime of an unused nonce.
const DefaultTTL = 5 * time.Minute

// MaxTTL caps the lifetime; longer requests are clamped on Issue.
const MaxTTL = 1 * time.Hour

// ConsumeResult is the outcome of a Consume call. Treat anything
// other than ConsumeOK as "do not proceed with the action".
type ConsumeResult uint8

const (
	// ConsumeOK — nonce verified, scope matched, fresh. Burned.
	ConsumeOK ConsumeResult = iota

	// ConsumeReplayed — nonce was already consumed once. The
	// strongest stolen-credential signal in this package.
	ConsumeReplayed

	// ConsumeExpired — nonce TTL elapsed before redemption.
	ConsumeExpired

	// ConsumeInvalidScope — caller asked to redeem at a scope
	// different from the one the nonce was minted for.
	ConsumeInvalidScope

	// ConsumeBadSignature — HMAC verification failed. Forged or
	// signed by a different key.
	ConsumeBadSignature

	// ConsumeNotIssued — signature is valid for our key but the
	// nonce id is in neither the issued set nor the consumed set.
	// Most likely a stale restart cleared in-memory state.
	ConsumeNotIssued
)

func (r ConsumeResult) String() string {
	switch r {
	case ConsumeOK:
		return "ok"
	case ConsumeReplayed:
		return "replayed"
	case ConsumeExpired:
		return "expired"
	case ConsumeInvalidScope:
		return "invalid_scope"
	case ConsumeBadSignature:
		return "bad_signature"
	case ConsumeNotIssued:
		return "not_issued"
	}
	return "unknown"
}

// Nonce is the wire format. Stable Version=1.
type Nonce struct {
	Version   int       `json:"version"`
	ID        string    `json:"id"`         // hex 32-char, time-prefixed
	Scope     string    `json:"scope"`      // route or action class
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature string    `json:"signature"`  // hex HMAC-SHA256
}

// Store is the in-memory issuer + verifier. Concurrent-safe.
type Store struct {
	mu       sync.Mutex
	issued   map[string]*Nonce        // not-yet-consumed
	consumed map[string]time.Time     // id → consumed-at (for replay detection)
	key      []byte
	maxSize  int

	issuedCount    atomic.Uint64
	okCount        atomic.Uint64
	replayedCount  atomic.Uint64
	expiredCount   atomic.Uint64
	badSig         atomic.Uint64
	notIssued      atomic.Uint64
	invalidScope   atomic.Uint64
}

// NewStore constructs a Store. Key must be ≥ 32 bytes. maxSize ≤ 0
// picks 1_000_000 — enough headroom for any realistic web workload
// inside the MaxTTL window.
func NewStore(key []byte, maxSize int) (*Store, error) {
	if len(key) < 32 {
		return nil, errors.New("nonce: HMAC key must be at least 32 bytes")
	}
	if maxSize <= 0 {
		maxSize = 1_000_000
	}
	return &Store{
		issued:   make(map[string]*Nonce, maxSize/16),
		consumed: make(map[string]time.Time, maxSize/16),
		key:      append([]byte(nil), key...),
		maxSize:  maxSize,
	}, nil
}

// GenerateKey returns a fresh 32-byte HMAC key. Operator persists it.
func GenerateKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Issue mints a new nonce for the given scope. If ttl <= 0 the
// default is used; ttl > MaxTTL is clamped.
func (s *Store) Issue(scope string, ttl time.Duration) (*Nonce, error) {
	if scope == "" {
		return nil, errors.New("nonce: scope is required")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl > MaxTTL {
		ttl = MaxTTL
	}

	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	n := &Nonce{
		Version:   1,
		ID:        id,
		Scope:     scope,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}
	n.Signature = s.sign(n)

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.issued)+len(s.consumed) >= s.maxSize {
		s.evictOldestLocked(now)
	}
	s.issued[id] = n
	s.issuedCount.Add(1)
	return n, nil
}

// Consume attempts to redeem the nonce at the given scope. Updates
// counters and returns the result. After a successful consume, the
// nonce id stays in the consumed set until Sweep removes it — that's
// how we detect replay.
func (s *Store) Consume(n *Nonce, scope string) ConsumeResult {
	if n == nil || n.Version != 1 || n.ID == "" {
		s.badSig.Add(1)
		return ConsumeBadSignature
	}

	// Signature check first. Don't reveal anything about the
	// issued/consumed sets to a caller with a bad signature.
	want := s.sign(n)
	if !hmac.Equal([]byte(want), []byte(n.Signature)) {
		s.badSig.Add(1)
		return ConsumeBadSignature
	}

	if n.Scope != scope {
		s.invalidScope.Add(1)
		return ConsumeInvalidScope
	}

	if time.Now().UTC().After(n.ExpiresAt) {
		s.expiredCount.Add(1)
		return ConsumeExpired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, replayed := s.consumed[n.ID]; replayed {
		s.replayedCount.Add(1)
		return ConsumeReplayed
	}
	if _, ok := s.issued[n.ID]; !ok {
		s.notIssued.Add(1)
		return ConsumeNotIssued
	}
	// Burn it.
	delete(s.issued, n.ID)
	s.consumed[n.ID] = time.Now().UTC()
	s.okCount.Add(1)
	return ConsumeOK
}

// Sweep removes expired nonces from both issued and consumed sets.
// Consumed entries are kept until the original nonce would have
// expired — operators may want a longer replay-window than the TTL,
// but for v1 we keep the simpler "consumed ttl == issued ttl" rule.
func (s *Store) Sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, n := range s.issued {
		if now.After(n.ExpiresAt) {
			delete(s.issued, id)
			removed++
			s.expiredCount.Add(1)
		}
	}
	// Drop consumed entries past their original TTL window.
	// We don't keep the original nonce — just the consumed-at time —
	// so use that + MaxTTL as a coarse upper bound.
	consumedCutoff := now.Add(-MaxTTL)
	for id, at := range s.consumed {
		if at.Before(consumedCutoff) {
			delete(s.consumed, id)
			removed++
		}
	}
	return removed
}

// evictOldestLocked drops the issued nonce with the earliest expiry,
// or — if all issued are fresh — drops the oldest consumed entry.
// Caller holds the lock.
func (s *Store) evictOldestLocked(now time.Time) {
	var oldestID string
	var oldestT time.Time
	for id, n := range s.issued {
		if oldestID == "" || n.ExpiresAt.Before(oldestT) {
			oldestID = id
			oldestT = n.ExpiresAt
		}
	}
	if oldestID != "" {
		delete(s.issued, oldestID)
		return
	}
	for id, at := range s.consumed {
		if oldestID == "" || at.Before(oldestT) {
			oldestID = id
			oldestT = at
		}
	}
	if oldestID != "" {
		delete(s.consumed, oldestID)
	}
}

// sign returns the HMAC-SHA256 over (version, id, scope, issued_at,
// expires_at). Anything beyond these fields is operator metadata
// that doesn't bind the signature.
func (s *Store) sign(n *Nonce) string {
	mac := hmac.New(sha256.New, s.key)
	for _, f := range []string{
		fmt.Sprintf("%d", n.Version),
		n.ID,
		n.Scope,
		fmt.Sprintf("%d", n.IssuedAt.UnixNano()),
		fmt.Sprintf("%d", n.ExpiresAt.UnixNano()),
	} {
		mac.Write([]byte(f))
		mac.Write([]byte{0x1f}) // unit separator
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// Stats is the snapshot for health.snapshot.
type Stats struct {
	Issued       int    `json:"issued_outstanding"`
	Consumed     int    `json:"consumed_in_window"`
	MaxSize      int    `json:"max_size"`
	IssuedTotal  uint64 `json:"issued_total"`
	OK           uint64 `json:"ok"`
	Replayed     uint64 `json:"replayed"`
	Expired      uint64 `json:"expired"`
	BadSig       uint64 `json:"bad_signature"`
	NotIssued    uint64 `json:"not_issued"`
	InvalidScope uint64 `json:"invalid_scope"`
}

// Stats returns counter snapshot.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	issued := len(s.issued)
	consumed := len(s.consumed)
	s.mu.Unlock()
	return Stats{
		Issued:       issued,
		Consumed:     consumed,
		MaxSize:      s.maxSize,
		IssuedTotal:  s.issuedCount.Load(),
		OK:           s.okCount.Load(),
		Replayed:     s.replayedCount.Load(),
		Expired:      s.expiredCount.Load(),
		BadSig:       s.badSig.Load(),
		NotIssued:    s.notIssued.Load(),
		InvalidScope: s.invalidScope.Load(),
	}
}

// newID returns a fresh 16-byte time-prefixed random hex string.
func newID() (string, error) {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixNano()))
	if _, err := rand.Read(b[8:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

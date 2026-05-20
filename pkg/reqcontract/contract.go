// Package reqcontract issues per-HTTP-request capability tokens —
// "Request Contracts" — that carry account / session / route / source
// identity from the L7 hop (xhelix-bridge) through eBPF socket-cookie
// correlation into kernel-level events, per BEHAVIORAL_DEFENSE.md §6.
//
// What it is NOT:
//   - It is not the perimeter. Schema validation, mTLS, OIDC live in
//     nginx / Envoy upstream. This package consumes their output.
//   - It is not the operator-issued Data Passport (pkg/passport).
//     Data Passport is operator-issued, ed25519-signed, for bulk
//     movement. Request Contract is auto-minted, HMAC-signed, per
//     request, lives for seconds.
//
// What it is:
//   - The unique runtime tag that lets every downstream sensor know
//     "this event was caused by request X for account Y on route Z".
//   - The carrier wave for every behavioral detector in
//     BEHAVIORAL_DEFENSE.md §3.
//
// Design:
//   - HMAC-SHA256 signature (symmetric — the store is the only
//     verifier; no need for ed25519 here).
//   - 30 s default TTL aligned with realistic request lifetimes;
//     hard cap 5 min.
//   - In-memory store with TTL sweep and bounded capacity.
//   - Lookup is the hot path (every kernel event hits it via the
//     correlator) — sub-microsecond target.
package reqcontract

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultTTL is the default lifetime if IssueParams.TTL is unset.
const DefaultTTL = 30 * time.Second

// MaxTTL caps the lifetime to prevent over-long-lived contracts.
const MaxTTL = 5 * time.Minute

// Contract is the per-request token. Stable wire format (Version=1);
// adding fields requires bumping Version.
type Contract struct {
	Version   int       `json:"version"`
	ID        string    `json:"id"`         // hex 32-char, time-prefixed
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`

	// Identity at time of issuance.
	Account    string `json:"account,omitempty"` // app-supplied account id, "" = anonymous
	Session    string `json:"session,omitempty"` // app-supplied session id
	Route      string `json:"route"`             // canonicalised request path
	Method     string `json:"method,omitempty"`  // GET/POST/etc.
	SchemaHash string `json:"schema_hash,omitempty"`

	// Source binding (used by session-binding detector, P-B.5).
	SourceIP  string `json:"source_ip,omitempty"`
	SourceASN string `json:"source_asn,omitempty"`
	JA3       string `json:"ja3,omitempty"`
	JA4       string `json:"ja4,omitempty"`
	UAClass   string `json:"ua_class,omitempty"`

	Signature string `json:"signature"` // hex of HMAC-SHA256 over canonical encoding
}

// IsValid reports whether the contract is well-formed and not expired.
// Does NOT verify the signature — call Store.Verify for that.
func (c *Contract) IsValid(now time.Time) bool {
	if c == nil || c.ID == "" || c.Route == "" {
		return false
	}
	return now.Before(c.ExpiresAt)
}

// IssueParams is the input to Store.Issue. Route is required.
type IssueParams struct {
	Account    string
	Session    string
	Route      string
	Method     string
	SchemaHash string
	SourceIP   string
	SourceASN  string
	JA3        string
	JA4        string
	UAClass    string
	TTL        time.Duration
}

// Store is the in-memory contract index. Concurrent-safe.
type Store struct {
	mu       sync.RWMutex
	byID     map[string]*Contract
	key      []byte
	maxSize  int

	issued    atomic.Uint64
	verified  atomic.Uint64
	rejected  atomic.Uint64
	expired   atomic.Uint64
	evicted   atomic.Uint64
	lookups   atomic.Uint64
	lookupOK  atomic.Uint64
}

// NewStore constructs a Store. The key must be at least 32 bytes for
// HMAC-SHA256 — fewer is rejected. maxSize <= 0 picks 1_000_000.
func NewStore(key []byte, maxSize int) (*Store, error) {
	if len(key) < 32 {
		return nil, errors.New("reqcontract: HMAC key must be at least 32 bytes")
	}
	if maxSize <= 0 {
		maxSize = 1_000_000
	}
	return &Store{
		byID:    make(map[string]*Contract, maxSize/16),
		key:     append([]byte(nil), key...), // defensive copy
		maxSize: maxSize,
	}, nil
}

// GenerateKey returns a cryptographically random 32-byte HMAC key.
// Convenience for callers that want to mint a fresh key at startup
// (operator persistence is their responsibility).
func GenerateKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Issue mints a fresh Contract, signs it, and stores it. Returns the
// contract pointer for the caller to forward to the app (typically
// injected as an HTTP header).
func (s *Store) Issue(p IssueParams) (*Contract, error) {
	if strings.TrimSpace(p.Route) == "" {
		return nil, errors.New("reqcontract: route is required")
	}
	ttl := p.TTL
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
	c := &Contract{
		Version:    1,
		ID:         id,
		IssuedAt:   now,
		ExpiresAt:  now.Add(ttl),
		Account:    p.Account,
		Session:    p.Session,
		Route:      p.Route,
		Method:     p.Method,
		SchemaHash: p.SchemaHash,
		SourceIP:   p.SourceIP,
		SourceASN:  p.SourceASN,
		JA3:        p.JA3,
		JA4:        p.JA4,
		UAClass:    p.UAClass,
	}
	c.Signature = s.sign(c)

	s.mu.Lock()
	if len(s.byID) >= s.maxSize {
		s.evictOldestLocked()
	}
	s.byID[c.ID] = c
	s.mu.Unlock()
	s.issued.Add(1)
	return c, nil
}

// Verify recomputes the HMAC and checks TTL. Used at trust-boundary
// crossings where a contract arrives from an untrusted hop (e.g., a
// sidecar). Records counters.
func (s *Store) Verify(c *Contract) error {
	if c == nil {
		s.rejected.Add(1)
		return errors.New("reqcontract: nil contract")
	}
	if c.Version != 1 {
		s.rejected.Add(1)
		return fmt.Errorf("reqcontract: unsupported version %d", c.Version)
	}
	want := s.sign(c)
	if !hmac.Equal([]byte(want), []byte(c.Signature)) {
		s.rejected.Add(1)
		return errors.New("reqcontract: signature mismatch")
	}
	if time.Now().UTC().After(c.ExpiresAt) {
		s.expired.Add(1)
		return errors.New("reqcontract: expired")
	}
	if c.ExpiresAt.Sub(c.IssuedAt) > MaxTTL+5*time.Second {
		s.rejected.Add(1)
		return errors.New("reqcontract: TTL exceeds maximum")
	}
	s.verified.Add(1)
	return nil
}

// Lookup is the hot path. Returns the contract pointer if present and
// not expired. Sub-microsecond target — concurrent reads under RLock.
// Expired contracts return (nil, false) and are removed lazily.
func (s *Store) Lookup(id string) (*Contract, bool) {
	s.lookups.Add(1)
	s.mu.RLock()
	c, ok := s.byID[id]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().UTC().After(c.ExpiresAt) {
		s.mu.Lock()
		delete(s.byID, id)
		s.mu.Unlock()
		s.expired.Add(1)
		return nil, false
	}
	s.lookupOK.Add(1)
	return c, true
}

// Sweep removes expired contracts. Returns count removed. Run on a
// periodic ticker — at high QPS the lazy-delete path in Lookup
// handles most cleanup, but Sweep ensures bounded memory under
// idle / bursty workloads.
func (s *Store) Sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, c := range s.byID {
		if now.After(c.ExpiresAt) {
			delete(s.byID, id)
			n++
		}
	}
	s.expired.Add(uint64(n))
	return n
}

// evictOldestLocked drops the contract with the earliest ExpiresAt.
// Caller holds the write lock. Used when at capacity.
func (s *Store) evictOldestLocked() {
	var oldestID string
	var oldestT time.Time
	for id, c := range s.byID {
		if oldestID == "" || c.ExpiresAt.Before(oldestT) {
			oldestID = id
			oldestT = c.ExpiresAt
		}
	}
	if oldestID != "" {
		delete(s.byID, oldestID)
		s.evicted.Add(1)
	}
}

// sign returns the hex-encoded HMAC-SHA256 over the contract's
// canonical encoding. Caller-side stable — same fields, same hash.
func (s *Store) sign(c *Contract) string {
	mac := hmac.New(sha256.New, s.key)
	// Canonical encoding: pipe-separated field values in declaration
	// order. Stable as long as we don't reorder the slice.
	for _, f := range []string{
		fmt.Sprintf("%d", c.Version),
		c.ID,
		fmt.Sprintf("%d", c.IssuedAt.UnixNano()),
		fmt.Sprintf("%d", c.ExpiresAt.UnixNano()),
		c.Account, c.Session, c.Route, c.Method, c.SchemaHash,
		c.SourceIP, c.SourceASN, c.JA3, c.JA4, c.UAClass,
	} {
		mac.Write([]byte(f))
		mac.Write([]byte{0x1f}) // ASCII unit-separator
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// Size returns the current number of stored contracts.
func (s *Store) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// Stats is the snapshot for health.snapshot / LocalAPI.
type Stats struct {
	Size     int    `json:"size"`
	MaxSize  int    `json:"max_size"`
	Issued   uint64 `json:"issued"`
	Verified uint64 `json:"verified"`
	Rejected uint64 `json:"rejected"`
	Expired  uint64 `json:"expired"`
	Evicted  uint64 `json:"evicted"`
	Lookups  uint64 `json:"lookups"`
	LookupOK uint64 `json:"lookup_ok"`
}

// Stats returns counter snapshot.
func (s *Store) Stats() Stats {
	return Stats{
		Size:     s.Size(),
		MaxSize:  s.maxSize,
		Issued:   s.issued.Load(),
		Verified: s.verified.Load(),
		Rejected: s.rejected.Load(),
		Expired:  s.expired.Load(),
		Evicted:  s.evicted.Load(),
		Lookups:  s.lookups.Load(),
		LookupOK: s.lookupOK.Load(),
	}
}

// newID returns a fresh 16-byte time-prefixed random hex string.
// Sortable by issuance time, collision-resistant.
func newID() (string, error) {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixNano()))
	if _, err := rand.Read(b[8:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

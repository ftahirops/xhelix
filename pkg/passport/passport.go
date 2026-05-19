// Package passport issues and verifies short-TTL ed25519-signed
// capability tokens authorising bulk movement of sensitive data, as
// described in DATA_LEAK_FABRIC.md §5.
//
// A Passport authorises ONE specific data movement:
//
//	"actor X may move up to N rows of classes {Y,Z} to destination D
//	 within TTL T, reason R, approved by A."
//
// Without a valid passport, the Egress Valve refuses outbound from
// any tainted lineage to any destination not in the static rules.
// With a valid passport, the destinations it names become temporarily
// allowed for the classes it names.
//
// Trust model: signed by an ed25519 key whose private half lives only
// inside the daemon. xhelixctl issues passports by calling the daemon's
// LocalAPI; the daemon never accepts a passport from an external
// process. The CLI is a convenience over the LocalAPI, not a separate
// trust root.
package passport

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// HardTTLMax is the absolute maximum lifetime any Passport may carry.
// Per the DLCF spec: 15 minutes. Requests for longer are clamped on
// issue.
const HardTTLMax = 15 * time.Minute

// MinTTL is the minimum lifetime — too short and the passport is
// useless. 30 seconds keeps the door open just long enough for the
// authorised tool to start a transfer.
const MinTTL = 30 * time.Second

// Passport is the signed payload. JSON-serialised, then signed
// over the canonical encoding. Field names are stable wire format —
// adding fields requires bumping Version.
type Passport struct {
	Version       int       `json:"version"` // 1
	ID            string    `json:"id"`      // 32-byte random base32, like ULID
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Actor         string    `json:"actor"`           // operator-supplied: "admin_user_91"
	Route         string    `json:"route,omitempty"` // optional: "/admin/export/orders"
	DataClasses   []string  `json:"data_classes"`    // e.g. ["pii","customer_order"]
	MaxRows       uint64    `json:"max_rows,omitempty"`
	MaxBytes      uint64    `json:"max_bytes,omitempty"`
	DestCIDRs     []string  `json:"dest_cidrs,omitempty"`
	DestIPs       []string  `json:"dest_ips,omitempty"`
	DestHostSfx   []string  `json:"dest_host_suffixes,omitempty"`
	Reason        string    `json:"reason"`        // operator-supplied
	ApprovedBy    string    `json:"approved_by"`   // second-pair-of-eyes id
}

// Signed wraps a Passport with a signature over its canonical JSON
// encoding. KeyID identifies the signing key for rotation.
type Signed struct {
	Passport  Passport `json:"passport"`
	KeyID     string   `json:"key_id"`
	Signature string   `json:"signature"` // base64(ed25519 sig of canonical JSON)
}

// IssueParams is the input to Issue. The daemon owns the private
// key; callers describe the passport they want.
type IssueParams struct {
	Actor             string
	Route             string
	DataClasses       []string
	MaxRows           uint64
	MaxBytes          uint64
	DestCIDRs         []string
	DestIPs           []string
	DestHostSuffixes  []string
	Reason            string
	ApprovedBy        string
	TTL               time.Duration
}

// Issue mints a fresh Passport, signs it with priv, and returns the
// Signed wrapper. Validates inputs (TTL clamped, classes non-empty,
// reason+actor required, at least one destination given).
func Issue(priv ed25519.PrivateKey, p IssueParams) (Signed, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Signed{}, errors.New("passport: invalid private key")
	}
	if strings.TrimSpace(p.Actor) == "" {
		return Signed{}, errors.New("passport: actor is required")
	}
	if strings.TrimSpace(p.Reason) == "" {
		return Signed{}, errors.New("passport: reason is required")
	}
	if strings.TrimSpace(p.ApprovedBy) == "" {
		return Signed{}, errors.New("passport: approved_by is required (two-person workflow)")
	}
	if len(p.DataClasses) == 0 {
		return Signed{}, errors.New("passport: at least one data_class is required")
	}
	if len(p.DestCIDRs)+len(p.DestIPs)+len(p.DestHostSuffixes) == 0 {
		return Signed{}, errors.New("passport: at least one destination (cidr, ip, or host suffix) is required")
	}
	for _, c := range p.DestCIDRs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return Signed{}, fmt.Errorf("passport: bad CIDR %q: %w", c, err)
		}
	}
	for _, ip := range p.DestIPs {
		if net.ParseIP(ip) == nil {
			return Signed{}, fmt.Errorf("passport: bad IP %q", ip)
		}
	}

	ttl := p.TTL
	if ttl < MinTTL {
		ttl = MinTTL
	}
	if ttl > HardTTLMax {
		ttl = HardTTLMax
	}

	id, err := newID()
	if err != nil {
		return Signed{}, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	pp := Passport{
		Version:     1,
		ID:          id,
		IssuedAt:    now,
		ExpiresAt:   now.Add(ttl),
		Actor:       p.Actor,
		Route:       p.Route,
		DataClasses: p.DataClasses,
		MaxRows:     p.MaxRows,
		MaxBytes:    p.MaxBytes,
		DestCIDRs:   p.DestCIDRs,
		DestIPs:     p.DestIPs,
		DestHostSfx: p.DestHostSuffixes,
		Reason:      p.Reason,
		ApprovedBy:  p.ApprovedBy,
	}
	body, err := canonical(pp)
	if err != nil {
		return Signed{}, err
	}
	sig := ed25519.Sign(priv, body)
	return Signed{
		Passport:  pp,
		KeyID:     KeyIDOf(priv.Public().(ed25519.PublicKey)),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify checks signature, version, and TTL bounds, returning the
// parsed Passport on success. Does NOT check revocation — that is
// the Store's job (callers go via Store.Verify in production).
func Verify(pub ed25519.PublicKey, s Signed) (Passport, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Passport{}, errors.New("passport: invalid public key")
	}
	if s.Passport.Version != 1 {
		return Passport{}, fmt.Errorf("passport: unsupported version %d", s.Passport.Version)
	}
	body, err := canonical(s.Passport)
	if err != nil {
		return Passport{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return Passport{}, fmt.Errorf("passport: bad signature encoding: %w", err)
	}
	if !ed25519.Verify(pub, body, sig) {
		return Passport{}, errors.New("passport: signature does not verify")
	}
	now := time.Now().UTC()
	if now.Before(s.Passport.IssuedAt.Add(-30 * time.Second)) {
		return Passport{}, errors.New("passport: issued in the future (clock skew?)")
	}
	if now.After(s.Passport.ExpiresAt) {
		return Passport{}, errors.New("passport: expired")
	}
	if s.Passport.ExpiresAt.Sub(s.Passport.IssuedAt) > HardTTLMax+5*time.Second {
		// 5-second grace allows for rounding; anything bigger means
		// a forged claim about TTL.
		return Passport{}, errors.New("passport: TTL exceeds hard maximum")
	}
	return s.Passport, nil
}

// canonical encodes the passport deterministically for signing. We
// use the standard library's JSON encoder with sorted map keys
// (encoding/json sorts map keys by default; struct fields are emitted
// in declaration order). This is stable enough for v1.
func canonical(p Passport) ([]byte, error) {
	return json.Marshal(p)
}

// KeyIDOf returns a short fingerprint of a public key for operator
// display. First 8 bytes of the public key, hex-encoded.
func KeyIDOf(pub ed25519.PublicKey) string {
	if len(pub) < 8 {
		return ""
	}
	return hex.EncodeToString(pub[:8])
}

// newID returns a fresh 16-byte time-prefixed random identifier as
// a 32-char hex string. Sortable by time, collision-resistant.
func newID() (string, error) {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixNano()))
	if _, err := rand.Read(b[8:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Store holds active (issued and not yet expired or revoked) passports
// in memory, indexed by ID and by data class for the Egress Valve hot
// path. Safe for concurrent use.
type Store struct {
	mu        sync.RWMutex
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	keyID     string
	byID      map[string]Signed
	revoked   map[string]time.Time // id → revocation time
}

// NewStore constructs a Store. priv is required for issuance; pass
// nil to make the Store verify-only (useful in tests). The public key
// is derived from priv for verification.
func NewStore(priv ed25519.PrivateKey) *Store {
	s := &Store{
		priv:    priv,
		byID:    make(map[string]Signed),
		revoked: make(map[string]time.Time),
	}
	if priv != nil {
		s.pub = priv.Public().(ed25519.PublicKey)
		s.keyID = KeyIDOf(s.pub)
	}
	return s
}

// PublicKey returns the verifier-side public key.
func (s *Store) PublicKey() ed25519.PublicKey { return s.pub }

// KeyID returns the public-key fingerprint.
func (s *Store) KeyID() string { return s.keyID }

// Issue issues a passport using the Store's private key and records
// it in the active set. Caller receives the Signed wrapper to deliver
// to whoever will present the token.
func (s *Store) Issue(p IssueParams) (Signed, error) {
	if s.priv == nil {
		return Signed{}, errors.New("passport: store has no private key (verify-only)")
	}
	signed, err := Issue(s.priv, p)
	if err != nil {
		return Signed{}, err
	}
	s.mu.Lock()
	s.byID[signed.Passport.ID] = signed
	s.mu.Unlock()
	return signed, nil
}

// Revoke marks a passport as revoked. Idempotent; revoking an unknown
// id is a no-op.
func (s *Store) Revoke(id string) {
	s.mu.Lock()
	s.revoked[id] = time.Now().UTC()
	delete(s.byID, id)
	s.mu.Unlock()
}

// VerifyActive returns nil if the passport is signed, not expired,
// and not revoked. Used by code paths that have a token from the wire.
func (s *Store) VerifyActive(signed Signed) (Passport, error) {
	s.mu.RLock()
	revokedAt, isRevoked := s.revoked[signed.Passport.ID]
	s.mu.RUnlock()
	if isRevoked {
		return Passport{}, fmt.Errorf("passport: revoked at %s", revokedAt.Format(time.RFC3339))
	}
	return Verify(s.pub, signed)
}

// ActiveDestinations satisfies the egress.PassportSource interface.
// Walks the active set and gathers every destination authorised for
// the named class. Drops expired/revoked passports along the way (so
// the Egress Valve's hot path also acts as a passive sweeper).
func (s *Store) ActiveDestinations(class string) (cidrs []*net.IPNet, hostSuffixes []string, passportID string) {
	now := time.Now().UTC()

	s.mu.RLock()
	candidates := make([]Signed, 0, len(s.byID))
	for _, sp := range s.byID {
		candidates = append(candidates, sp)
	}
	s.mu.RUnlock()

	var expired []string
	for _, sp := range candidates {
		if now.After(sp.Passport.ExpiresAt) {
			expired = append(expired, sp.Passport.ID)
			continue
		}
		matches := false
		for _, c := range sp.Passport.DataClasses {
			if c == class {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		for _, c := range sp.Passport.DestCIDRs {
			if _, n, err := net.ParseCIDR(c); err == nil {
				cidrs = append(cidrs, n)
			}
		}
		for _, ip := range sp.Passport.DestIPs {
			// Represent exact IP as a /32 (or /128) CIDR for uniformity.
			if p := net.ParseIP(ip); p != nil {
				bits := 32
				if p.To4() == nil {
					bits = 128
				}
				_, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip, bits))
				if err == nil {
					cidrs = append(cidrs, n)
				}
			}
		}
		for _, h := range sp.Passport.DestHostSfx {
			if !strings.HasPrefix(h, ".") {
				h = "." + h
			}
			hostSuffixes = append(hostSuffixes, strings.ToLower(h))
		}
		// Use the most-recently-issued passport's ID for the verdict;
		// the loop iterates in map order so this is stable per call
		// but not across calls. Good enough for diagnostics.
		passportID = sp.Passport.ID
	}

	if len(expired) > 0 {
		s.mu.Lock()
		for _, id := range expired {
			delete(s.byID, id)
		}
		s.mu.Unlock()
	}
	return
}

// List returns a snapshot of every currently-active passport (not
// expired, not revoked). Useful for passport.list LocalAPI handler.
func (s *Store) List() []Passport {
	now := time.Now().UTC()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Passport, 0, len(s.byID))
	for _, sp := range s.byID {
		if now.After(sp.Passport.ExpiresAt) {
			continue
		}
		out = append(out, sp.Passport)
	}
	return out
}

// Sweep removes expired passports and old revocation records.
// Bounded memory in long-running daemons. Returns counts removed.
func (s *Store) Sweep(now time.Time) (expired, revokedDropped int) {
	cutoff := now.Add(-24 * time.Hour)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sp := range s.byID {
		if now.After(sp.Passport.ExpiresAt) {
			delete(s.byID, id)
			expired++
		}
	}
	for id, t := range s.revoked {
		if t.Before(cutoff) {
			delete(s.revoked, id)
			revokedDropped++
		}
	}
	return
}

// Stats returns a snapshot of counters for health.snapshot.
type Stats struct {
	Active  int    `json:"active"`
	Revoked int    `json:"revoked"`
	KeyID   string `json:"key_id"`
}

// Stats returns counter snapshot.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{
		Active:  len(s.byID),
		Revoked: len(s.revoked),
		KeyID:   s.keyID,
	}
}

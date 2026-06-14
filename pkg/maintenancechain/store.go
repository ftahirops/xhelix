package maintenancechain

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store persists active grants to SQLite and provides fast in-memory
// lookup for the hot path (execguard callback on every exec event).
//
// The hot path is: ActiveFor(cgroupPath) → []Grant
// This is called synchronously in the execguard deny callback, so it
// must be sub-millisecond. We keep an in-memory cache of non-expired
// grants and update it on write. The SQLite store is the durable
// backing for restarts and the UI query surface.
type Store struct {
	db    *sql.DB
	trust map[string]ed25519.PublicKey

	mu     sync.RWMutex
	active []*Grant // in-memory hot cache, non-expired grants only
}

// Open opens or creates the grant store at the given SQLite path.
// trust is the map of allowed signer names → Ed25519 public keys.
func Open(path string, trust map[string]ed25519.PublicKey) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("maintenancechain store open: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("maintenancechain store schema: %w", err)
	}
	s := &Store{db: db, trust: trust}
	if err := s.hydrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Add mints a grant from the given params, validates it, persists it,
// and adds it to the hot cache. Returns the minted Grant.
func (s *Store) Add(p MintParams) (*Grant, error) {
	g, err := Mint(p)
	if err != nil {
		return nil, err
	}
	if err := g.Validate(s.trust); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("maintenancechain: marshal grant: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO grants (id, app_name, cgroup_match, scope, reason,
		  created_by, created_at, expires_at, signed_by, raw)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		g.ID, g.AppName, g.CgroupMatch, string(g.Scope), g.Reason,
		g.CreatedBy, g.CreatedAt.Unix(), g.ExpiresAt.Unix(),
		g.SignedBy, string(raw),
	)
	if err != nil {
		return nil, fmt.Errorf("maintenancechain: insert grant: %w", err)
	}
	s.mu.Lock()
	s.active = append(s.active, g)
	s.mu.Unlock()
	return g, nil
}

// AddSigned adds an already-signed grant (e.g., received from CI).
// Re-validates structural invariants (same constraints as Mint) before
// checking the signature, so a compromised signer cannot bypass field
// requirements by crafting a grant that skips Mint.
func (s *Store) AddSigned(g *Grant) error {
	if g == nil {
		return errors.New("maintenancechain: nil grant")
	}
	if g.AppName == "" {
		return errors.New("maintenancechain: app name required")
	}
	if g.CgroupMatch == "" {
		return errors.New("maintenancechain: cgroup match required")
	}
	if g.Reason == "" {
		return errors.New("maintenancechain: reason required")
	}
	ttl := g.ExpiresAt.Sub(g.CreatedAt)
	if ttl < time.Minute || ttl > 24*time.Hour {
		return fmt.Errorf("maintenancechain: TTL %v out of range [1m, 24h]", ttl)
	}
	if err := g.Validate(s.trust); err != nil {
		return err
	}
	raw, err := json.Marshal(g)
	if err != nil {
		return fmt.Errorf("maintenancechain: marshal grant: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT OR IGNORE INTO grants (id, app_name, cgroup_match, scope, reason,
		  created_by, created_at, expires_at, signed_by, raw)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		g.ID, g.AppName, g.CgroupMatch, string(g.Scope), g.Reason,
		g.CreatedBy, g.CreatedAt.Unix(), g.ExpiresAt.Unix(),
		g.SignedBy, string(raw),
	)
	if err != nil {
		return fmt.Errorf("maintenancechain: insert signed grant: %w", err)
	}
	s.mu.Lock()
	s.active = append(s.active, g)
	s.mu.Unlock()
	return nil
}

// Revoke marks a grant as revoked by ID. It is removed from the hot
// cache immediately so no further bypass is possible.
func (s *Store) Revoke(id string) error {
	res, err := s.db.Exec(
		`UPDATE grants SET revoked=1, revoked_at=? WHERE id=? AND revoked=0`,
		time.Now().Unix(), id,
	)
	if err != nil {
		return fmt.Errorf("maintenancechain: revoke: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("maintenancechain: grant not found or already revoked")
	}
	s.mu.Lock()
	s.removeFromCache(id)
	s.mu.Unlock()
	return nil
}

// ActiveFor returns all non-expired, non-revoked grants whose
// CgroupMatch prefix matches the given cgroup path. Called from
// execguard on every exec deny decision — must be fast.
func (s *Store) ActiveFor(cgroupPath string) []*Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Grant
	for _, g := range s.active {
		if !g.IsExpired() && g.matchesCgroup(cgroupPath) {
			out = append(out, g)
		}
	}
	return out
}

// CoversExec returns true if any active grant allows the given binary
// to be executed within the given cgroup. Hot path — no allocations
// beyond the slice scan from ActiveFor.
func (s *Store) CoversExec(cgroupPath, binaryPath string) bool {
	for _, g := range s.ActiveFor(cgroupPath) {
		if g.CoversExec(cgroupPath, binaryPath) {
			return true
		}
	}
	return false
}

// CoversWrite returns true if any active grant allows writing to the
// given path within the given cgroup.
func (s *Store) CoversWrite(cgroupPath, filePath string) bool {
	for _, g := range s.ActiveFor(cgroupPath) {
		if g.CoversWrite(cgroupPath, filePath) {
			return true
		}
	}
	return false
}

// List returns all grants (active, expired, and revoked) for a given
// app, ordered by created_at descending. Used by the UI.
func (s *Store) List(appName string) ([]*Grant, error) {
	q := `SELECT raw FROM grants WHERE app_name=? ORDER BY created_at DESC LIMIT 200`
	rows, err := s.db.QueryContext(context.Background(), q, appName)
	if err != nil {
		return nil, fmt.Errorf("maintenancechain: list: %w", err)
	}
	defer rows.Close()
	return scanGrants(rows)
}

// ListAll returns all grants across all apps (for the global
// /maintenance overview page), ordered by created_at descending.
func (s *Store) ListAll() ([]*Grant, error) {
	q := `SELECT raw FROM grants ORDER BY created_at DESC LIMIT 500`
	rows, err := s.db.QueryContext(context.Background(), q)
	if err != nil {
		return nil, fmt.Errorf("maintenancechain: list all: %w", err)
	}
	defer rows.Close()
	return scanGrants(rows)
}

// Sweep removes in-memory cache entries that have expired. Call once
// per minute from a background goroutine. Does NOT delete from SQLite —
// expired grants are kept for the audit trail.
func (s *Store) Sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.active)
	kept := s.active[:0]
	for _, g := range s.active {
		if !now.After(g.ExpiresAt) {
			kept = append(kept, g)
		}
	}
	s.active = kept
	return before - len(s.active)
}

// RegisterTrustKey adds a trusted signer key at runtime. Used to inject
// the auto-generated UI signing key after the store is opened, without
// requiring operators to pre-place key files.
func (s *Store) RegisterTrustKey(name string, pub ed25519.PublicKey) {
	s.mu.Lock()
	if s.trust == nil {
		s.trust = make(map[string]ed25519.PublicKey)
	}
	s.trust[name] = pub
	s.mu.Unlock()
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

// hydrate loads all non-expired, non-revoked grants from SQLite into
// the in-memory cache on startup.
func (s *Store) hydrate() error {
	now := time.Now().Unix()
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT raw FROM grants WHERE expires_at > ? AND revoked=0`, now)
	if err != nil {
		return fmt.Errorf("maintenancechain: hydrate: %w", err)
	}
	defer rows.Close()
	grants, err := scanGrants(rows)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.active = grants
	s.mu.Unlock()
	return nil
}

func (s *Store) removeFromCache(id string) {
	n := 0
	for _, g := range s.active {
		if g.ID != id {
			s.active[n] = g
			n++
		}
	}
	s.active = s.active[:n]
}

func scanGrants(rows *sql.Rows) ([]*Grant, error) {
	var out []*Grant
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var g Grant
		if err := json.Unmarshal([]byte(raw), &g); err != nil {
			continue // skip malformed rows
		}
		out = append(out, &g)
	}
	return out, rows.Err()
}

const schema = `
CREATE TABLE IF NOT EXISTS grants (
  id          TEXT PRIMARY KEY,
  app_name    TEXT NOT NULL,
  cgroup_match TEXT NOT NULL,
  scope       TEXT NOT NULL,
  reason      TEXT NOT NULL,
  created_by  TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  signed_by   TEXT NOT NULL,
  revoked     INTEGER NOT NULL DEFAULT 0,
  revoked_at  INTEGER,
  raw         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_grants_app ON grants(app_name);
CREATE INDEX IF NOT EXISTS idx_grants_expiry ON grants(expires_at);
`

// Package maintenancechain implements signed, time-boxed capability grants
// that temporarily unlock red-zone behaviors for known-good operations
// (deploys, package updates, backups).
//
// A Grant is the primitive: it names an app, scopes a cgroup prefix,
// declares which exec paths and write paths are temporarily allowed,
// carries a TTL, and is signed with an Ed25519 key so it cannot be
// forged or extended without the signing key.
//
// The store (store.go) persists active grants to SQLite and provides
// the ActiveFor(cgroupPath) query that execguard calls before every
// red-zone block decision.
package maintenancechain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Scope names the category of maintenance operation. Each scope carries
// a default set of allowed behaviors so operators don't need to specify
// every path manually for common operations.
type Scope string

const (
	ScopeDeploy  Scope = "deploy"   // shell + write in service cgroup
	ScopeUpdate  Scope = "update"   // package manager + network
	ScopeBackup  Scope = "backup"   // read of sensitive paths
	ScopeCustom  Scope = "custom"   // operator-defined
)

// Grant is a signed, time-boxed capability grant for one app/cgroup.
// The canonical JSON (CanonicalBytes) is what the Ed25519 signature
// covers — every field except Signature and ID.
type Grant struct {
	ID          string    `json:"id"`           // ULID, assigned at mint
	AppName     string    `json:"app"`          // e.g. "billing-api"
	CgroupMatch string    `json:"cgroup_match"` // prefix, e.g. "/system.slice/php-fpm.service"
	Scope       Scope     `json:"scope"`
	AllowExec   []string  `json:"allow_exec,omitempty"`  // absolute paths, empty = scope defaults
	AllowWrite  []string  `json:"allow_write,omitempty"` // absolute path prefixes
	Reason      string    `json:"reason"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	SignedBy    string    `json:"signed_by"` // key name, e.g. "ops" or "ci-prod"
	Signature   []byte    `json:"sig,omitempty"`
}

// MintParams holds the inputs for creating a new grant.
type MintParams struct {
	AppName     string
	CgroupMatch string
	Scope       Scope
	AllowExec   []string
	AllowWrite  []string
	Reason      string
	CreatedBy   string
	TTL         time.Duration
	SignerName  string
	SignerKey   ed25519.PrivateKey
}

// Mint creates and signs a new Grant. Returns an error if any required
// field is missing or the TTL is out of the allowed range (1m–24h).
func Mint(p MintParams) (*Grant, error) {
	if p.AppName == "" {
		return nil, errors.New("maintenancechain: app name required")
	}
	if p.CgroupMatch == "" {
		return nil, errors.New("maintenancechain: cgroup match required")
	}
	if p.Reason == "" {
		return nil, errors.New("maintenancechain: reason required")
	}
	if p.TTL < time.Minute || p.TTL > 24*time.Hour {
		return nil, fmt.Errorf("maintenancechain: TTL %v out of range [1m, 24h]", p.TTL)
	}
	if p.SignerKey == nil {
		return nil, errors.New("maintenancechain: signer key required")
	}
	now := time.Now().UTC()
	g := &Grant{
		ID:          newID(),
		AppName:     p.AppName,
		CgroupMatch: p.CgroupMatch,
		Scope:       p.Scope,
		AllowExec:   p.AllowExec,
		AllowWrite:  p.AllowWrite,
		Reason:      p.Reason,
		CreatedBy:   p.CreatedBy,
		CreatedAt:   now,
		ExpiresAt:   now.Add(p.TTL),
		SignedBy:    p.SignerName,
	}
	// Apply scope defaults if AllowExec/AllowWrite not explicitly set.
	if len(g.AllowExec) == 0 {
		g.AllowExec = scopeDefaultExec(p.Scope)
	}
	if len(g.AllowWrite) == 0 {
		g.AllowWrite = scopeDefaultWrite(p.Scope)
	}
	canonical, err := g.canonicalBytes()
	if err != nil {
		return nil, fmt.Errorf("maintenancechain: canonical encode: %w", err)
	}
	g.Signature = ed25519.Sign(p.SignerKey, canonical)
	return g, nil
}

// Validate verifies the grant's signature and expiry against the
// provided trust root. Returns a non-nil error if invalid or expired.
func (g *Grant) Validate(trust map[string]ed25519.PublicKey) error {
	if g == nil {
		return errors.New("maintenancechain: nil grant")
	}
	if time.Now().UTC().After(g.ExpiresAt) {
		return fmt.Errorf("maintenancechain: grant %s expired at %s", g.ID, g.ExpiresAt)
	}
	pub, ok := trust[g.SignedBy]
	if !ok {
		return fmt.Errorf("maintenancechain: unknown signer %q", g.SignedBy)
	}
	canonical, err := g.canonicalBytes()
	if err != nil {
		return fmt.Errorf("maintenancechain: canonical encode: %w", err)
	}
	if !ed25519.Verify(pub, canonical, g.Signature) {
		return fmt.Errorf("maintenancechain: invalid signature on grant %s", g.ID)
	}
	return nil
}

// CoversExec returns true if this grant allows executing the given
// binary path within the given cgroup. The cgroup path must match
// CgroupMatch as a prefix.
func (g *Grant) CoversExec(cgroupPath, binaryPath string) bool {
	if !g.matchesCgroup(cgroupPath) {
		return false
	}
	for _, allowed := range g.AllowExec {
		if allowed == binaryPath {
			return true
		}
		if strings.HasSuffix(allowed, "*") && strings.HasPrefix(binaryPath, allowed[:len(allowed)-1]) {
			return true
		}
	}
	return false
}

// CoversWrite returns true if this grant allows writing to the given
// path within the given cgroup.
func (g *Grant) CoversWrite(cgroupPath, filePath string) bool {
	if !g.matchesCgroup(cgroupPath) {
		return false
	}
	for _, prefix := range g.AllowWrite {
		if strings.HasPrefix(filePath, prefix) {
			return true
		}
	}
	return false
}

// Remaining returns how much time is left on this grant.
func (g *Grant) Remaining() time.Duration {
	r := time.Until(g.ExpiresAt)
	if r < 0 {
		return 0
	}
	return r
}

// IsExpired reports whether the grant has passed its expiry time.
func (g *Grant) IsExpired() bool {
	return time.Now().UTC().After(g.ExpiresAt)
}

func (g *Grant) matchesCgroup(cgroupPath string) bool {
	if g.CgroupMatch == "" {
		// Mint requires non-empty; empty on a deserialized grant is
		// rejected here rather than silently matching everything.
		return false
	}
	return cgroupPath == g.CgroupMatch ||
		strings.HasPrefix(cgroupPath, g.CgroupMatch+"/")
}

// canonicalBytes returns the JSON encoding of the grant with Signature
// zeroed out — this is the byte slice that is signed and verified.
func (g *Grant) canonicalBytes() ([]byte, error) {
	type canonical struct {
		ID          string    `json:"id"`
		AppName     string    `json:"app"`
		CgroupMatch string    `json:"cgroup_match"`
		Scope       Scope     `json:"scope"`
		AllowExec   []string  `json:"allow_exec"`
		AllowWrite  []string  `json:"allow_write"`
		Reason      string    `json:"reason"`
		CreatedBy   string    `json:"created_by"`
		CreatedAt   time.Time `json:"created_at"`
		ExpiresAt   time.Time `json:"expires_at"`
		SignedBy    string    `json:"signed_by"`
	}
	return json.Marshal(canonical{
		ID:          g.ID,
		AppName:     g.AppName,
		CgroupMatch: g.CgroupMatch,
		Scope:       g.Scope,
		AllowExec:   g.AllowExec,
		AllowWrite:  g.AllowWrite,
		Reason:      g.Reason,
		CreatedBy:   g.CreatedBy,
		CreatedAt:   g.CreatedAt,
		ExpiresAt:   g.ExpiresAt,
		SignedBy:    g.SignedBy,
	})
}

// scopeDefaultExec returns the default allowed exec paths for a scope.
func scopeDefaultExec(s Scope) []string {
	switch s {
	case ScopeDeploy:
		return []string{
			"/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash",
			"/usr/bin/rsync", "/usr/bin/git", "/usr/bin/install",
		}
	case ScopeUpdate:
		return []string{
			"/usr/bin/apt-get", "/usr/bin/apt", "/usr/bin/dpkg",
			"/usr/bin/pip", "/usr/bin/pip3", "/usr/bin/npm",
			"/usr/bin/yarn",
		}
	case ScopeBackup:
		return []string{
			"/usr/bin/tar", "/usr/bin/gzip", "/usr/bin/gpg",
			"/usr/bin/rsync", "/usr/bin/mysqldump", "/usr/bin/pg_dump",
		}
	}
	return nil // ScopeCustom: caller must specify
}

// scopeDefaultWrite returns the default allowed write prefixes for a scope.
func scopeDefaultWrite(s Scope) []string {
	switch s {
	case ScopeDeploy:
		return []string{"/srv/", "/opt/", "/var/www/", "/app/", "/home/"}
	case ScopeUpdate:
		return []string{"/var/lib/dpkg/", "/var/cache/apt/", "/tmp/", "/var/tmp/"}
	case ScopeBackup:
		return []string{"/var/backups/", "/tmp/", "/mnt/"}
	}
	return nil
}

// newID generates a random 16-byte ID encoded as base64 (URL-safe, no padding).
// Not a full ULID but sufficient for grant IDs — random + time component.
func newID() string {
	b := make([]byte, 16)
	ts := time.Now().UnixMilli()
	b[0] = byte(ts >> 40)
	b[1] = byte(ts >> 32)
	b[2] = byte(ts >> 24)
	b[3] = byte(ts >> 16)
	b[4] = byte(ts >> 8)
	b[5] = byte(ts)
	_, _ = rand.Read(b[6:])
	return base64.RawURLEncoding.EncodeToString(b)
}

package maintenancechain

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) (*Store, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	trust := map[string]ed25519.PublicKey{"ops": pub}
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "grants.db"), trust)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, pub, priv
}

func TestStore_AddAndList(t *testing.T) {
	s, _, priv := openTestStore(t)

	g, err := s.Add(MintParams{
		AppName:     "billing-api",
		CgroupMatch: "/system.slice/php-fpm.service",
		Scope:       ScopeDeploy,
		Reason:      "v1.4.2 deploy",
		CreatedBy:   "admin",
		TTL:         30 * time.Minute,
		SignerName:  "ops",
		SignerKey:   priv,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if g.ID == "" {
		t.Error("expected non-empty ID")
	}

	grants, err := s.List("billing-api")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(grants))
	}
	if grants[0].ID != g.ID {
		t.Errorf("expected grant ID %q, got %q", g.ID, grants[0].ID)
	}
}

func TestStore_Revoke(t *testing.T) {
	s, _, priv := openTestStore(t)

	g, err := s.Add(MintParams{
		AppName:     "app",
		CgroupMatch: "/x",
		Scope:       ScopeDeploy,
		Reason:      "r",
		TTL:         time.Hour,
		SignerName:  "ops",
		SignerKey:   priv,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Grant should be in active cache
	active := s.ActiveFor("/x")
	if len(active) != 1 {
		t.Fatalf("expected 1 active grant, got %d", len(active))
	}

	if err := s.Revoke(g.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Should be removed from cache immediately
	active = s.ActiveFor("/x")
	if len(active) != 0 {
		t.Errorf("expected 0 active grants after revoke, got %d", len(active))
	}

	// Double revoke should error
	if err := s.Revoke(g.ID); err == nil {
		t.Error("expected error on double revoke")
	}
}

func TestStore_CoversExec(t *testing.T) {
	s, _, priv := openTestStore(t)

	_, err := s.Add(MintParams{
		AppName:     "app",
		CgroupMatch: "/system.slice/php-fpm.service",
		Scope:       ScopeDeploy,
		Reason:      "r",
		TTL:         time.Hour,
		SignerName:  "ops",
		SignerKey:   priv,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Deploy scope allows /bin/bash
	if !s.CoversExec("/system.slice/php-fpm.service", "/bin/bash") {
		t.Error("expected bash covered by deploy scope")
	}
	// Wrong cgroup
	if s.CoversExec("/system.slice/nginx.service", "/bin/bash") {
		t.Error("expected deny for wrong cgroup")
	}
	// Not in deploy scope
	if s.CoversExec("/system.slice/php-fpm.service", "/usr/bin/curl") {
		t.Error("expected curl denied under deploy scope")
	}
}

func TestStore_CoversWrite(t *testing.T) {
	s, _, priv := openTestStore(t)

	_, err := s.Add(MintParams{
		AppName:     "app",
		CgroupMatch: "/system.slice/php-fpm.service",
		Scope:       ScopeDeploy,
		Reason:      "r",
		TTL:         time.Hour,
		SignerName:  "ops",
		SignerKey:   priv,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	if !s.CoversWrite("/system.slice/php-fpm.service", "/var/www/html/index.php") {
		t.Error("expected /var/www/ write covered by deploy scope")
	}
	if s.CoversWrite("/system.slice/php-fpm.service", "/etc/cron.d/evil") {
		t.Error("expected /etc/cron.d/ write denied")
	}
}

func TestStore_Sweep(t *testing.T) {
	s, _, priv := openTestStore(t)

	// Add a grant with minimum TTL
	g, err := s.Add(MintParams{
		AppName:     "app",
		CgroupMatch: "/x",
		Scope:       ScopeDeploy,
		Reason:      "r",
		TTL:         time.Minute,
		SignerName:  "ops",
		SignerKey:   priv,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	_ = g

	s.mu.Lock()
	// Fast-forward expiry
	s.active[0].ExpiresAt = time.Now().Add(-time.Second)
	s.mu.Unlock()

	removed := s.Sweep(time.Now())
	if removed != 1 {
		t.Errorf("expected Sweep to remove 1, got %d", removed)
	}
	if len(s.ActiveFor("/x")) != 0 {
		t.Error("expected empty active cache after sweep")
	}
}

func TestStore_Hydrate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	trust := map[string]ed25519.PublicKey{"ops": pub}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "grants.db")

	// First store: add a grant
	s1, err := Open(dbPath, trust)
	if err != nil {
		t.Fatalf("open s1: %v", err)
	}
	g, err := s1.Add(MintParams{
		AppName:     "app",
		CgroupMatch: "/x",
		Scope:       ScopeDeploy,
		Reason:      "r",
		TTL:         time.Hour,
		SignerName:  "ops",
		SignerKey:   priv,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	s1.Close()

	// Second store: should hydrate from DB
	s2, err := Open(dbPath, trust)
	if err != nil {
		t.Fatalf("open s2: %v", err)
	}
	defer s2.Close()

	active := s2.ActiveFor("/x")
	if len(active) != 1 {
		t.Fatalf("expected 1 hydrated grant, got %d", len(active))
	}
	if active[0].ID != g.ID {
		t.Errorf("hydrated grant ID mismatch: want %q got %q", g.ID, active[0].ID)
	}
}

func TestStore_ListAll(t *testing.T) {
	s, _, priv := openTestStore(t)

	for i, app := range []string{"app-a", "app-b", "app-c"} {
		_ = i
		_, err := s.Add(MintParams{
			AppName:     app,
			CgroupMatch: "/x",
			Scope:       ScopeDeploy,
			Reason:      "r",
			TTL:         time.Hour,
			SignerName:  "ops",
			SignerKey:   priv,
		})
		if err != nil {
			t.Fatalf("Add %s: %v", app, err)
		}
	}

	all, err := s.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 grants, got %d", len(all))
	}
}

func TestStore_AddSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	trust := map[string]ed25519.PublicKey{"ci": pub}
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "grants.db"), trust)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	g, err := Mint(MintParams{
		AppName:     "app",
		CgroupMatch: "/x",
		Scope:       ScopeDeploy,
		Reason:      "CI deploy",
		TTL:         time.Hour,
		SignerName:  "ci",
		SignerKey:   priv,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if err := s.AddSigned(g); err != nil {
		t.Fatalf("AddSigned: %v", err)
	}

	// Duplicate should be silently ignored (INSERT OR IGNORE)
	if err := s.AddSigned(g); err != nil {
		t.Errorf("second AddSigned should be idempotent: %v", err)
	}
}

// TestStore_AddSigned_RejectsStructuralBypass ensures that AddSigned
// re-validates required fields so a compromised signer cannot craft a
// match-all grant by bypassing Mint's guards.
func TestStore_AddSigned_RejectsStructuralBypass(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	trust := map[string]ed25519.PublicKey{"ci": pub}
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "grants.db"), trust)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()

	crafted := func(modify func(*Grant)) *Grant {
		g := &Grant{
			ID:          newID(),
			AppName:     "app",
			CgroupMatch: "/x",
			Scope:       ScopeCustom,
			Reason:      "legit",
			CreatedAt:   now,
			ExpiresAt:   now.Add(time.Hour),
			SignedBy:    "ci",
		}
		modify(g)
		cb, _ := g.canonicalBytes()
		g.Signature = ed25519.Sign(priv, cb)
		return g
	}

	cases := []struct {
		name string
		g    *Grant
	}{
		{"empty cgroup", crafted(func(g *Grant) { g.CgroupMatch = "" })},
		{"empty app", crafted(func(g *Grant) { g.AppName = "" })},
		{"empty reason", crafted(func(g *Grant) { g.Reason = "" })},
		{"ttl too short", crafted(func(g *Grant) { g.ExpiresAt = now.Add(30 * time.Second) })},
		{"ttl too long", crafted(func(g *Grant) { g.ExpiresAt = now.Add(25 * time.Hour) })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.AddSigned(tc.g); err == nil {
				t.Error("expected rejection, got nil")
			}
		})
	}
}

// TestMatchesCgroup_NoUnanchoredPrefix ensures a grant for service A
// cannot be bypassed by a different service whose name merely shares
// the same prefix.
func TestMatchesCgroup_NoUnanchoredPrefix(t *testing.T) {
	_, priv := genKey(t)
	g, _ := Mint(MintParams{
		AppName:     "app",
		CgroupMatch: "/system.slice/php-fpm.service",
		Scope:       ScopeCustom,
		AllowExec:   []string{"/bin/bash"},
		Reason:      "r",
		TTL:         time.Minute,
		SignerName:  "ops",
		SignerKey:   priv,
	})

	// Must NOT match a service that merely shares the prefix without "/"
	if g.CoversExec("/system.slice/php-fpm-malicious.service", "/bin/bash") {
		t.Error("unanchored prefix bypass: php-fpm-malicious matched php-fpm grant")
	}
	// Must match exact and child
	if !g.CoversExec("/system.slice/php-fpm.service", "/bin/bash") {
		t.Error("exact match failed")
	}
	if !g.CoversExec("/system.slice/php-fpm.service/1234", "/bin/bash") {
		t.Error("child cgroup match failed")
	}
}

// TestMatchesCgroup_EmptyNeverMatchesAll ensures an empty CgroupMatch
// (which Mint rejects but could appear in a crafted AddSigned) does
// not become a match-all wildcard.
func TestMatchesCgroup_EmptyNeverMatchesAll(t *testing.T) {
	g := &Grant{CgroupMatch: ""}
	if g.matchesCgroup("/any/cgroup") {
		t.Error("empty CgroupMatch should never match")
	}
	if g.matchesCgroup("") {
		t.Error("empty CgroupMatch should not match empty cgroup either")
	}
}

func TestStore_ActiveFor_CgroupPrefix(t *testing.T) {
	s, _, priv := openTestStore(t)

	_, err := s.Add(MintParams{
		AppName:     "app",
		CgroupMatch: "/system.slice/php-fpm.service",
		Scope:       ScopeDeploy,
		Reason:      "r",
		TTL:         time.Hour,
		SignerName:  "ops",
		SignerKey:   priv,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Exact match
	if len(s.ActiveFor("/system.slice/php-fpm.service")) != 1 {
		t.Error("expected grant for exact cgroup match")
	}
	// Child cgroup
	if len(s.ActiveFor("/system.slice/php-fpm.service/1")) != 1 {
		t.Error("expected grant for child cgroup")
	}
	// Unrelated
	if len(s.ActiveFor("/system.slice/nginx.service")) != 0 {
		t.Error("expected no grant for unrelated cgroup")
	}
}

// Ensure test cleanup doesn't leave temp DB files if test panics
func TestStore_DBPathPermission(t *testing.T) {
	trust := map[string]ed25519.PublicKey{}
	_, err := Open(os.DevNull, trust)
	// DevNull may succeed or fail depending on OS, but should not panic
	if err == nil {
		t.Log("DevNull open succeeded (expected on some systems)")
	}
}

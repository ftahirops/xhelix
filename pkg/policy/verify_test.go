package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/catalog"
	"github.com/xhelix/xhelix/pkg/reqcontract"
)

const tierYAML = `
version: 1
sensitivity_points: {pii: 20, customer_order: 30, credentials: 100}
routes:
  - match: ["/public/home"]
    allowed_classes: [pii]
    protection_tier: L1
  - match: ["/admin/"]
    allowed_classes: [pii]
    protection_tier: L2
  - match: ["/admin/profile"]
    allowed_classes: [pii]
    protection_tier: L3
  - match: ["/admin/dashboard"]
    allowed_classes: [pii, customer_order]
    protection_tier: L4
  - match: ["/admin/export/orders"]
    allowed_classes: [pii, customer_order]
    protection_tier: L5
  - match: ["/admin/delete/backup"]
    allowed_classes: [pii]
    protection_tier: L6
  - match: ["/admin/short-ttl"]
    allowed_classes: [pii]
    protection_tier: L3
    webauthn_max_age_seconds: 10
  - match: ["/no-policy"]
    allowed_classes: [pii]
`

func loadTier(t testing.TB) *catalog.Catalog {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "cat.yaml")
	if err := os.WriteFile(p, []byte(tierYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := catalog.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func contract(now time.Time, opts ...func(*reqcontract.Contract)) *reqcontract.Contract {
	c := &reqcontract.Contract{
		Version: 1, ID: "abc", Route: "/x",
		IssuedAt: now, ExpiresAt: now.Add(30 * time.Second),
	}
	for _, f := range opts {
		f(c)
	}
	return c
}

func withWebAuthn(ts time.Time) func(*reqcontract.Contract) {
	return func(c *reqcontract.Contract) { c.WebAuthnTS = ts }
}
func withDBSC() func(*reqcontract.Contract) {
	return func(c *reqcontract.Contract) { c.DBSCBound = true }
}

func TestCheck_NoCatalog_Allows(t *testing.T) {
	v := Check(nil, "/anything", contract(time.Now()))
	if v.Decision != DecisionAllow {
		t.Errorf("nil catalog should allow: %+v", v)
	}
}

func TestCheck_NoPolicyOnRoute_Allows(t *testing.T) {
	cat := loadTier(t)
	v := Check(cat, "/no-policy", contract(time.Now()))
	if v.Decision != DecisionAllow {
		t.Errorf("undeclared route should allow: %+v", v)
	}
}

func TestCheck_L1_Allows_WithContract(t *testing.T) {
	cat := loadTier(t)
	v := Check(cat, "/public/home", contract(time.Now()))
	if v.Decision != DecisionAllow {
		t.Errorf("L1 with contract should allow: %+v", v)
	}
}

func TestCheck_L1_Denies_Anonymous(t *testing.T) {
	cat := loadTier(t)
	v := Check(cat, "/public/home", nil)
	if v.Decision != DecisionDeny {
		t.Error("L1 without contract should deny")
	}
}

func TestCheck_L2_RequiresContract(t *testing.T) {
	cat := loadTier(t)
	v := Check(cat, "/admin/", contract(time.Now()))
	if v.Decision != DecisionAllow {
		t.Errorf("L2 with contract should allow: %+v", v)
	}
	v = Check(cat, "/admin/", nil)
	if v.Decision != DecisionDeny {
		t.Error("L2 without contract should deny")
	}
}

func TestCheck_L3_RequiresFreshWebAuthn(t *testing.T) {
	cat := loadTier(t)
	now := time.Now()

	// No WebAuthn → deny
	v := Check(cat, "/admin/profile", contract(now))
	if v.Decision != DecisionDeny {
		t.Errorf("L3 no WebAuthn should deny: %+v", v)
	}

	// Fresh WebAuthn (just now) → allow
	v = Check(cat, "/admin/profile", contract(now, withWebAuthn(now)))
	if v.Decision != DecisionAllow {
		t.Errorf("L3 fresh WebAuthn should allow: %+v", v)
	}

	// Stale WebAuthn (10 min old, default L3 max = 5 min) → deny
	v = Check(cat, "/admin/profile", contract(now, withWebAuthn(now.Add(-10*time.Minute))))
	if v.Decision != DecisionDeny {
		t.Errorf("L3 stale WebAuthn should deny: %+v", v)
	}
}

func TestCheck_L3_OperatorOverrideMaxAge(t *testing.T) {
	cat := loadTier(t)
	now := time.Now()

	// /admin/short-ttl has webauthn_max_age_seconds: 10
	// 5s old → allow
	v := Check(cat, "/admin/short-ttl", contract(now, withWebAuthn(now.Add(-5*time.Second))))
	if v.Decision != DecisionAllow {
		t.Errorf("5s old, 10s window: should allow: %+v", v)
	}
	// 20s old → deny
	v = Check(cat, "/admin/short-ttl", contract(now, withWebAuthn(now.Add(-20*time.Second))))
	if v.Decision != DecisionDeny {
		t.Errorf("20s old, 10s window: should deny: %+v", v)
	}
}

func TestCheck_L4_RequiresDBSC(t *testing.T) {
	cat := loadTier(t)
	now := time.Now()

	// WebAuthn fresh but no DBSC → deny
	v := Check(cat, "/admin/dashboard", contract(now, withWebAuthn(now)))
	if v.Decision != DecisionDeny {
		t.Errorf("L4 without DBSC should deny: %+v", v)
	}

	// With DBSC → allow
	v = Check(cat, "/admin/dashboard", contract(now, withWebAuthn(now), withDBSC()))
	if v.Decision != DecisionAllow {
		t.Errorf("L4 with WebAuthn + DBSC should allow: %+v", v)
	}
}

func TestCheck_L5_PassesVerifierIfAllAboveSatisfied(t *testing.T) {
	cat := loadTier(t)
	now := time.Now()
	v := Check(cat, "/admin/export/orders", contract(now, withWebAuthn(now), withDBSC()))
	if v.Decision != DecisionAllow {
		t.Errorf("L5 with proofs should allow at verifier (passport check is Egress Valve): %+v", v)
	}
}

func TestCheck_L6_PassesVerifier(t *testing.T) {
	cat := loadTier(t)
	now := time.Now()
	v := Check(cat, "/admin/delete/backup", contract(now, withWebAuthn(now), withDBSC()))
	if v.Decision != DecisionAllow {
		t.Errorf("L6 v1 verifier should allow with proofs (P-CJ.4 enforces two-person): %+v", v)
	}
}

func TestCheck_MissingProofsListed(t *testing.T) {
	cat := loadTier(t)
	v := Check(cat, "/admin/dashboard", contract(time.Now())) // L4, no WebAuthn, no DBSC
	if len(v.MissingProofs) == 0 {
		t.Error("expected MissingProofs to be populated on deny")
	}
}

func TestCheck_TierStringInVerdict(t *testing.T) {
	cat := loadTier(t)
	v := Check(cat, "/admin/export/orders", nil)
	if v.RequiredTierStr != "L5" {
		t.Errorf("RequiredTierStr = %q, want L5", v.RequiredTierStr)
	}
}

func BenchmarkCheck_L5_Allow(b *testing.B) {
	cat := loadTier(b)
	now := time.Now()
	c := contract(now, withWebAuthn(now), withDBSC())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Check(cat, "/admin/export/orders", c)
	}
}

func BenchmarkCheck_NoPolicy(b *testing.B) {
	cat := loadTier(b)
	c := contract(time.Now())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Check(cat, "/no-policy", c)
	}
}

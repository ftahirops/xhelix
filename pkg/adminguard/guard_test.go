package adminguard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xhelix/xhelix/pkg/geoip"
)

const sampleYAML = `
version: 1
rules:
  - name: corp-network
    route_patterns: ["/wp-admin/", "/admin/"]
    allowed_cidrs:
      - "10.0.0.0/8"
      - "192.0.2.0/24"

  - name: bastion-only
    route_patterns: ["/admin/export/"]
    allowed_ips:
      - "192.0.2.10"

  - name: corp-vpn-asn
    route_patterns: ["/sso/login"]
    allowed_asns:
      - "AS64500"
`

func writeTmp(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "admin.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeGeo is a tiny test provider that lets us assert ASN matching.
type fakeGeo struct {
	byIP map[string]geoip.Result
}

func (f *fakeGeo) Lookup(ip string) (geoip.Result, bool) {
	r, ok := f.byIP[ip]
	return r, ok
}

func TestCheck_UnknownRoute_Allows(t *testing.T) {
	g := New(nil)
	if err := g.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}
	v := g.Check("/public/home", "8.8.8.8")
	if v.Decision != DecisionAllow {
		t.Errorf("non-admin route should allow, got %+v", v)
	}
}

func TestCheck_AdminRoute_FromCorpCIDR_Allows(t *testing.T) {
	g := New(nil)
	if err := g.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}
	v := g.Check("/wp-admin/admin.php", "10.0.5.5")
	if v.Decision != DecisionAllow {
		t.Errorf("admin from corp CIDR should allow, got %+v", v)
	}
	if v.MatchedRule != "corp-network" {
		t.Errorf("MatchedRule = %q, want corp-network", v.MatchedRule)
	}
}

func TestCheck_AdminRoute_FromInternet_Denies(t *testing.T) {
	g := New(nil)
	if err := g.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}
	v := g.Check("/wp-admin/admin.php", "8.8.8.8")
	if v.Decision != DecisionDeny {
		t.Errorf("admin from internet should deny, got %+v", v)
	}
	if v.DenyingRule == "" {
		t.Error("DenyingRule should be populated on deny")
	}
}

func TestCheck_OverlappingRules_AllMustAllow(t *testing.T) {
	g := New(nil)
	if err := g.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}
	// /admin/export/orders matches BOTH corp-network and bastion-only.
	// corp CIDR satisfies corp-network but NOT bastion-only.
	v := g.Check("/admin/export/orders", "10.0.5.5")
	if v.Decision != DecisionDeny {
		t.Errorf("overlapping rule should deny if any rule unsatisfied, got %+v", v)
	}
	if v.DenyingRule != "bastion-only" {
		t.Errorf("DenyingRule = %q, want bastion-only", v.DenyingRule)
	}

	// Bastion IP satisfies both rules.
	v = g.Check("/admin/export/orders", "192.0.2.10")
	if v.Decision != DecisionAllow {
		t.Errorf("bastion IP should satisfy both rules, got %+v", v)
	}
}

func TestCheck_ASNRule_WithGeoIP(t *testing.T) {
	geo := &fakeGeo{byIP: map[string]geoip.Result{
		"203.0.113.5": {ASN: "AS64500", Country: "US"},
		"203.0.113.6": {ASN: "AS99999", Country: "US"},
	}}
	g := New(geo)
	if err := g.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}
	// IP not in any CIDR but ASN 64500 is in allow-list for /admin/sso.
	v := g.Check("/sso/login", "203.0.113.5")
	if v.Decision != DecisionAllow {
		t.Errorf("matching ASN should allow, got %+v", v)
	}
	if v.ResolvedASN != "AS64500" {
		t.Errorf("ResolvedASN = %q, want AS64500", v.ResolvedASN)
	}

	v = g.Check("/admin/sso", "203.0.113.6")
	if v.Decision != DecisionDeny {
		t.Errorf("wrong ASN should deny, got %+v", v)
	}
}

func TestCheck_ASNRule_WithoutGeoIP(t *testing.T) {
	// Same policy, no geoip provider. ASN rule silently can't match;
	// IP also isn't in any CIDR/IP allow-list → deny.
	g := New(nil)
	if err := g.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}
	v := g.Check("/sso/login", "203.0.113.5")
	if v.Decision != DecisionDeny {
		t.Errorf("no geoip + IP not in CIDR/IP list should deny, got %+v", v)
	}
}

func TestCheck_BadSourceIP_Denies(t *testing.T) {
	g := New(nil)
	if err := g.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}
	v := g.Check("/wp-admin/admin.php", "not-an-ip")
	if v.Decision != DecisionDeny {
		t.Error("unparseable IP should deny (fail-closed)")
	}
}

func TestCheck_ExactRouteMatch(t *testing.T) {
	yaml := `
version: 1
rules:
  - name: exact-route
    route_patterns: ["/admin/special"]
    allowed_cidrs: ["10.0.0.0/8"]
`
	g := New(nil)
	if err := g.Load(writeTmp(t, yaml)); err != nil {
		t.Fatal(err)
	}
	// Exact match.
	if v := g.Check("/admin/special", "10.0.1.1"); v.Decision != DecisionAllow {
		t.Errorf("exact match should allow: %+v", v)
	}
	// Sub-path: NOT a prefix match (no trailing slash → exact only).
	if v := g.Check("/admin/special/sub", "10.0.1.1"); v.Decision != DecisionAllow {
		// /admin/special/sub doesn't match any rule → not admin → allow.
		t.Errorf("sub-path of exact rule should not be governed, expected allow: %+v", v)
	}
	if v := g.Check("/admin/special", "8.8.8.8"); v.Decision != DecisionDeny {
		t.Errorf("exact match from outside should deny: %+v", v)
	}
}

func TestParse_RejectsEmptyAllowList(t *testing.T) {
	bad := `
version: 1
rules:
  - name: oops
    route_patterns: ["/admin/"]
`
	_, err := parse([]byte(bad))
	if err == nil {
		t.Error("empty allow-list should be rejected (would deny everything)")
	}
}

func TestParse_RejectsMissingPatterns(t *testing.T) {
	bad := `
version: 1
rules:
  - name: oops
    allowed_cidrs: ["10.0.0.0/8"]
`
	_, err := parse([]byte(bad))
	if err == nil {
		t.Error("missing route_patterns should be rejected")
	}
}

func TestReload_PicksUpChanges(t *testing.T) {
	g := New(nil)
	path := writeTmp(t, sampleYAML)
	if err := g.Load(path); err != nil {
		t.Fatal(err)
	}
	// Initially: 8.8.8.8 denied on /wp-admin/.
	if v := g.Check("/wp-admin/x", "8.8.8.8"); v.Decision != DecisionDeny {
		t.Fatalf("expected initial deny")
	}

	updated := `
version: 1
rules:
  - name: open-now
    route_patterns: ["/wp-admin/"]
    allowed_cidrs: ["0.0.0.0/0"]
`
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := g.Reload(); err != nil {
		t.Fatal(err)
	}
	if v := g.Check("/wp-admin/x", "8.8.8.8"); v.Decision != DecisionAllow {
		t.Errorf("after permissive reload, expected allow: %+v", v)
	}
}

func TestReload_FailedPreservesLive(t *testing.T) {
	g := New(nil)
	path := writeTmp(t, sampleYAML)
	if err := g.Load(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not yaml: {{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := g.Reload(); err == nil {
		t.Error("reload of garbage should error")
	}
	// Original rules still in effect.
	if v := g.Check("/wp-admin/x", "8.8.8.8"); v.Decision != DecisionDeny {
		t.Error("failed reload must not clobber live rules")
	}
}

func TestStats_Counters(t *testing.T) {
	g := New(nil)
	if err := g.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}
	g.Check("/wp-admin/x", "10.0.1.1") // allow
	g.Check("/wp-admin/x", "8.8.8.8")  // deny
	g.Check("/public/x", "8.8.8.8")    // allow (non-admin)

	s := g.Stats()
	if s.Checks != 3 || s.Allowed != 2 || s.Denied != 1 {
		t.Errorf("stats = %+v, want checks=3 allowed=2 denied=1", s)
	}
}

func BenchmarkCheck_Allow(b *testing.B) {
	g := New(nil)
	_ = g.Load(writeTmpB(b, sampleYAML))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Check("/wp-admin/x", "10.0.1.1")
	}
}

func BenchmarkCheck_NonAdminRoute(b *testing.B) {
	g := New(nil)
	_ = g.Load(writeTmpB(b, sampleYAML))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Check("/public/home", "8.8.8.8")
	}
}

func writeTmpB(b *testing.B, body string) string {
	b.Helper()
	dir := b.TempDir()
	p := filepath.Join(dir, "admin.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		b.Fatal(err)
	}
	return p
}

package catalog

import (
	"os"
	"path/filepath"
	"testing"
)

const validYAML = `
version: 1
sensitivity_points:
  pii: 20
  credentials: 100
  payment_token: 300
  api_key: 1000
  source_code: 50
  backup: 200
  public: 1

tables:
  - match: [wp_users, wp_usermeta]
    classes: [pii]
  - match: [wp_woocommerce_orders]
    classes: [pii, payment_token]

paths:
  - glob: "/etc/xhelix/keys/*.pem"
    classes: [credentials]
  - glob: "/srv/backups/*.tar.gz"
    classes: [backup]
  - glob: "/var/www/**/.git/config"
    classes: [source_code]

secrets:
  - name: aws_access_key
    regex: "AKIA[0-9A-Z]{16}"
    classes: [api_key]
  - name: github_token
    regex: "ghp_[A-Za-z0-9]{36}"
    classes: [api_key]

routes:
  - match: ["/product/search"]
    allowed_classes: [public]
  - match: ["/admin/export/orders"]
    allowed_classes: [pii, payment_token]
`

func writeTmp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "catalog.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_Valid(t *testing.T) {
	p := writeTmp(t, validYAML)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	st := c.Stats()
	if st.Classes < 7 {
		t.Errorf("expected ≥7 classes, got %d", st.Classes)
	}
	if st.Tables != 3 { // wp_users, wp_usermeta, wp_woocommerce_orders
		t.Errorf("tables = %d, want 3", st.Tables)
	}
	if st.PathGlobs != 3 {
		t.Errorf("path_globs = %d, want 3", st.PathGlobs)
	}
	if st.SecretPatterns != 2 {
		t.Errorf("secret_patterns = %d, want 2", st.SecretPatterns)
	}
	if st.Routes != 2 {
		t.Errorf("routes = %d, want 2", st.Routes)
	}
	if st.Source != p {
		t.Errorf("source = %q, want %q", st.Source, p)
	}
}

func TestPointsFor(t *testing.T) {
	c, err := Load(writeTmp(t, validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.PointsFor(ClassPII); got != 20 {
		t.Errorf("PII = %d, want 20", got)
	}
	if got := c.PointsFor(ClassAPIKey); got != 1000 {
		t.Errorf("api_key = %d, want 1000", got)
	}
	// Canary always present, always heavy, even if unset in YAML.
	if got := c.PointsFor(ClassCanary); got < 1000 {
		t.Errorf("canary should be heavy, got %d", got)
	}
	if got := c.PointsFor("unknown"); got != 0 {
		t.Errorf("unknown class should be 0, got %d", got)
	}
}

func TestClassesForTable_CaseInsensitive(t *testing.T) {
	c, _ := Load(writeTmp(t, validYAML))

	for _, name := range []string{"wp_users", "WP_USERS", "Wp_Users"} {
		got := c.ClassesForTable(name)
		if len(got) != 1 || got[0] != ClassPII {
			t.Errorf("ClassesForTable(%q) = %v, want [pii]", name, got)
		}
	}

	if c.ClassesForTable("nonexistent") != nil {
		t.Error("nonexistent table should return nil")
	}

	orders := c.ClassesForTable("wp_woocommerce_orders")
	if len(orders) != 2 {
		t.Errorf("orders table = %v, want 2 classes", orders)
	}
}

func TestClassesForPath(t *testing.T) {
	c, _ := Load(writeTmp(t, validYAML))

	cases := map[string]DataClass{
		"/etc/xhelix/keys/agent.pem": ClassCredentials,
		"/srv/backups/2026-01.tar.gz": ClassBackup,
	}
	for path, want := range cases {
		got := c.ClassesForPath(path)
		if len(got) != 1 || got[0] != want {
			t.Errorf("ClassesForPath(%q) = %v, want [%s]", path, got, want)
		}
	}

	if c.ClassesForPath("/tmp/random.txt") != nil {
		t.Error("unmatched path should return nil")
	}
}

func TestClassesForSecret(t *testing.T) {
	c, _ := Load(writeTmp(t, validYAML))

	name, classes, ok := c.ClassesForSecret("hello AKIAIOSFODNN7EXAMPLE world")
	if !ok || name != "aws_access_key" {
		t.Errorf("expected aws_access_key match, got name=%q ok=%v", name, ok)
	}
	if len(classes) != 1 || classes[0] != ClassAPIKey {
		t.Errorf("expected [api_key], got %v", classes)
	}

	if _, _, ok := c.ClassesForSecret("nothing sensitive here"); ok {
		t.Error("benign string should not match any secret regex")
	}
}

func TestRouteAllows(t *testing.T) {
	c, _ := Load(writeTmp(t, validYAML))

	// /product/search: public only.
	allowed, hasPolicy := c.RouteAllows("/product/search", ClassPublic)
	if !hasPolicy || !allowed {
		t.Errorf("/product/search should allow public: allowed=%v hasPolicy=%v", allowed, hasPolicy)
	}
	allowed, hasPolicy = c.RouteAllows("/product/search", ClassPII)
	if !hasPolicy || allowed {
		t.Errorf("/product/search should NOT allow pii: allowed=%v hasPolicy=%v", allowed, hasPolicy)
	}

	// Unconfigured route: hasPolicy=false.
	_, hasPolicy = c.RouteAllows("/some/random/route", ClassPII)
	if hasPolicy {
		t.Error("unconfigured route should report hasPolicy=false")
	}
}

func TestParse_BadVersion(t *testing.T) {
	_, err := Load(writeTmp(t, "version: 99\nsensitivity_points: {}\n"))
	if err == nil {
		t.Error("expected error for bad version")
	}
}

func TestParse_UnknownClassRejected(t *testing.T) {
	bad := `
version: 1
sensitivity_points:
  pii: 20
tables:
  - match: [users]
    classes: [pii, frobnicated]
`
	_, err := Load(writeTmp(t, bad))
	if err == nil {
		t.Error("unknown class should fail validation")
	}
}

func TestParse_BadRegexRejected(t *testing.T) {
	bad := `
version: 1
sensitivity_points: {api_key: 1000}
secrets:
  - name: broken
    regex: "[unclosed"
    classes: [api_key]
`
	_, err := Load(writeTmp(t, bad))
	if err == nil {
		t.Error("bad regex should fail validation")
	}
}

func TestReload_PicksUpChanges(t *testing.T) {
	p := writeTmp(t, validYAML)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.PointsFor(ClassPII) != 20 {
		t.Fatalf("initial PII points should be 20")
	}

	updated := `
version: 1
sensitivity_points:
  pii: 999
`
	if err := os.WriteFile(p, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if c.PointsFor(ClassPII) != 999 {
		t.Errorf("after reload PII = %d, want 999", c.PointsFor(ClassPII))
	}
}

func TestReload_BadFileLeavesOldDataIntact(t *testing.T) {
	p := writeTmp(t, validYAML)
	c, _ := Load(p)

	// Overwrite with garbage.
	if err := os.WriteFile(p, []byte("not yaml: {{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Reload(); err == nil {
		t.Error("Reload should fail on garbage")
	}
	// Original still queryable.
	if c.PointsFor(ClassPII) != 20 {
		t.Errorf("Reload failure should not clobber live catalog")
	}
}

func BenchmarkClassesForTable(b *testing.B) {
	c, _ := Load(writeTmp(&testing.T{}, validYAML))
	for i := 0; i < b.N; i++ {
		_ = c.ClassesForTable("wp_users")
	}
}

func BenchmarkPointsFor(b *testing.B) {
	c, _ := Load(writeTmp(&testing.T{}, validYAML))
	for i := 0; i < b.N; i++ {
		_ = c.PointsFor(ClassPII)
	}
}

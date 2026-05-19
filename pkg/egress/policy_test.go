package egress

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/xhelix/xhelix/pkg/lineage"
)

const sampleYAML = `
version: 1
rules:
  - class: backup
    name: backup-mirror
    cidrs: ["10.20.30.0/24"]
    ips: ["192.0.2.5"]
    host_suffixes: [".backups.internal"]

  - class: pii
    name: ops-dashboard
    cidrs: ["10.99.0.0/16"]
`

func writeTmp(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "egress.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func registryWith(t *testing.T, classes ...string) (*lineage.ClassRegistry, map[string]lineage.TaintBit) {
	r := lineage.NewClassRegistry()
	bits := make(map[string]lineage.TaintBit)
	for _, c := range classes {
		b, err := r.Bit(c)
		if err != nil {
			t.Fatal(err)
		}
		bits[c] = b
	}
	return r, bits
}

func TestPolicy_UntaintedAlwaysAllowed(t *testing.T) {
	reg, _ := registryWith(t, "pii")
	p := New(reg)
	if err := p.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}
	v := p.Allow(lineage.TaintSet(0), net.ParseIP("1.2.3.4"), "", 443)
	if v.Decision != DecisionAllow {
		t.Errorf("untainted should allow: %+v", v)
	}
}

func TestPolicy_TaintedDeniedByDefault(t *testing.T) {
	// Empty policy + tainted lineage = deny.
	reg, bits := registryWith(t, "backup")
	p := New(reg)
	ts := lineage.TaintSet(0).With(bits["backup"])
	v := p.Allow(ts, net.ParseIP("8.8.8.8"), "dns.google", 53)
	if v.Decision != DecisionDeny {
		t.Errorf("tainted with no rule should deny: %+v", v)
	}
}

func TestPolicy_AllowsViaCIDR(t *testing.T) {
	reg, bits := registryWith(t, "backup", "pii")
	p := New(reg)
	if err := p.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}

	ts := lineage.TaintSet(0).With(bits["backup"])
	v := p.Allow(ts, net.ParseIP("10.20.30.55"), "", 22)
	if v.Decision != DecisionAllow {
		t.Errorf("dest in CIDR should allow: %+v", v)
	}
	if v.MatchedRule == "" {
		t.Error("matched rule should be set")
	}
}

func TestPolicy_AllowsViaExactIP(t *testing.T) {
	reg, bits := registryWith(t, "backup")
	p := New(reg)
	if err := p.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}
	ts := lineage.TaintSet(0).With(bits["backup"])
	v := p.Allow(ts, net.ParseIP("192.0.2.5"), "", 22)
	if v.Decision != DecisionAllow {
		t.Errorf("exact IP match should allow: %+v", v)
	}
}

func TestPolicy_AllowsViaHostSuffix(t *testing.T) {
	reg, bits := registryWith(t, "backup")
	p := New(reg)
	if err := p.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}
	ts := lineage.TaintSet(0).With(bits["backup"])
	v := p.Allow(ts, net.ParseIP("203.0.113.10"), "node1.backups.internal", 22)
	if v.Decision != DecisionAllow {
		t.Errorf("host-suffix match should allow: %+v", v)
	}
}

func TestPolicy_AllClassesMustBeSatisfied(t *testing.T) {
	reg, bits := registryWith(t, "backup", "pii")
	p := New(reg)
	if err := p.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}
	// Lineage carries BOTH backup and pii; destination is in backup's
	// allowed CIDR but not pii's. The "any class fails" rule must
	// deny.
	ts := lineage.TaintSet(0).With(bits["backup"]).With(bits["pii"])
	v := p.Allow(ts, net.ParseIP("10.20.30.55"), "", 22)
	if v.Decision != DecisionDeny {
		t.Errorf("unsatisfied class should deny even if another class is OK: %+v", v)
	}
}

type fakePassport struct {
	class   string
	cidr    *net.IPNet
	id      string
}

func (f *fakePassport) ActiveDestinations(class string) ([]*net.IPNet, []string, string) {
	if class != f.class {
		return nil, nil, ""
	}
	return []*net.IPNet{f.cidr}, nil, f.id
}

func TestPolicy_PassportProvidesDestination(t *testing.T) {
	reg, bits := registryWith(t, "customer_order")
	p := New(reg)
	// No static rules for customer_order — only the passport will
	// authorise the destination.
	_, cidr, _ := net.ParseCIDR("198.51.100.0/24")
	p.AttachPassportSource(&fakePassport{class: "customer_order", cidr: cidr, id: "passport-abc"})

	ts := lineage.TaintSet(0).With(bits["customer_order"])
	v := p.Allow(ts, net.ParseIP("198.51.100.7"), "", 443)
	if v.Decision != DecisionAllow {
		t.Errorf("passport should authorise dest: %+v", v)
	}
	if v.Passport != "passport-abc" {
		t.Errorf("verdict.Passport = %q, want passport-abc", v.Passport)
	}
}

func TestPolicy_Reload_PicksUpChanges(t *testing.T) {
	reg, bits := registryWith(t, "backup")
	p := New(reg)
	path := writeTmp(t, sampleYAML)
	if err := p.Load(path); err != nil {
		t.Fatal(err)
	}

	// Replace with a more permissive policy.
	updated := `
version: 1
rules:
  - class: backup
    cidrs: ["0.0.0.0/0"]
`
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}

	ts := lineage.TaintSet(0).With(bits["backup"])
	v := p.Allow(ts, net.ParseIP("8.8.8.8"), "", 443)
	if v.Decision != DecisionAllow {
		t.Errorf("after reload to allow-all CIDR, expected allow: %+v", v)
	}
}

func TestPolicy_Reload_FailedLeavesLiveIntact(t *testing.T) {
	reg, bits := registryWith(t, "backup")
	p := New(reg)
	path := writeTmp(t, sampleYAML)
	if err := p.Load(path); err != nil {
		t.Fatal(err)
	}

	// Garbage YAML.
	if err := os.WriteFile(path, []byte("not yaml: {{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(); err == nil {
		t.Error("reload of garbage should fail")
	}

	// Original rules still effective.
	ts := lineage.TaintSet(0).With(bits["backup"])
	v := p.Allow(ts, net.ParseIP("10.20.30.55"), "", 22)
	if v.Decision != DecisionAllow {
		t.Error("failed reload should not erase prior rules")
	}
}

func TestPolicy_Stats(t *testing.T) {
	reg, bits := registryWith(t, "backup")
	p := New(reg)
	if err := p.Load(writeTmp(t, sampleYAML)); err != nil {
		t.Fatal(err)
	}
	ts := lineage.TaintSet(0).With(bits["backup"])
	p.Allow(ts, net.ParseIP("10.20.30.55"), "", 22) // allow
	p.Allow(ts, net.ParseIP("8.8.8.8"), "", 53)     // deny
	p.Allow(lineage.TaintSet(0), net.ParseIP("8.8.8.8"), "", 53) // allow (untainted)

	st := p.Stats()
	if st.Checks != 3 || st.Allowed != 2 || st.Denied != 1 {
		t.Errorf("stats = %+v, want checks=3 allowed=2 denied=1", st)
	}
	if st.ClassCount != 2 || st.RuleCount != 2 {
		t.Errorf("stats counts = %+v, want class=2 rule=2", st)
	}
}

func BenchmarkPolicy_Allow_Hot(b *testing.B) {
	r := lineage.NewClassRegistry()
	bit, _ := r.Bit("backup")
	p := New(r)
	_ = p.Load(writeTmpB(b, sampleYAML))
	ts := lineage.TaintSet(0).With(bit)
	ip := net.ParseIP("10.20.30.55")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Allow(ts, ip, "", 22)
	}
}

func writeTmpB(b *testing.B, body string) string {
	b.Helper()
	dir := b.TempDir()
	p := filepath.Join(dir, "egress.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		b.Fatal(err)
	}
	return p
}

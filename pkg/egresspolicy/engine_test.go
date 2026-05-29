package egresspolicy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func newTestStoreWithPolicy(t *testing.T, p Policy) (*Store, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	dir := t.TempDir()
	s, err := NewStore(dir, pub)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	sp, err := Sign(p, "operator-test", priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := s.Save(sp); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if n, err := s.Reload(); err != nil || n != 1 {
		t.Fatalf("Reload: n=%d err=%v", n, err)
	}
	return s, priv
}

func TestEngineNoPolicyReturnsObserve(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	s, err := NewStore(t.TempDir(), pub)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	e := New(s, ModeObserve)
	d := e.Decide(Request{Binary: "/bin/anything", DestIP: net.ParseIP("1.2.3.4"), DestPort: 443})
	if d.Action != ActionObserve {
		t.Fatalf("want Observe, got %s", d.Action)
	}
	if d.PolicyID != "" {
		t.Fatalf("expected empty PolicyID, got %q", d.PolicyID)
	}
}

func TestEngineNilSafe(t *testing.T) {
	var e *Engine
	d := e.Decide(Request{Binary: "/bin/x"})
	if d.Action != ActionObserve {
		t.Fatalf("nil engine should return Observe, got %s", d.Action)
	}
}

func TestEngineAllowAny(t *testing.T) {
	p := samplePolicy()
	p.Mode = ModeAllowAny
	p.Allow = nil
	p.Deny = nil
	p.OnlyUIDs = nil
	s, _ := newTestStoreWithPolicy(t, p)
	e := New(s, ModeObserve)
	d := e.Decide(Request{Binary: p.Binary, UID: 0, DestIP: net.ParseIP("8.8.8.8"), DestPort: 443})
	if d.Action != ActionAllow || d.Mode != ModeAllowAny {
		t.Fatalf("AllowAny mode: got action=%s mode=%s", d.Action, d.Mode)
	}
}

func TestEngineDenyDefaultAllowMatches(t *testing.T) {
	p := samplePolicy()
	p.OnlyUIDs = nil
	p.Deny = nil
	s, _ := newTestStoreWithPolicy(t, p)
	e := New(s, ModeObserve)
	req := Request{
		Binary:    p.Binary,
		DestIP:    net.ParseIP("1.1.1.1"),
		DestPort:  443,
		Protocol:  "tcp",
		DestClass: "cloudflare",
	}
	d := e.Decide(req)
	if d.Action != ActionAllow {
		t.Fatalf("expected Allow via cloudflare rule, got %s (%s)", d.Action, d.MatchedBy)
	}
}

func TestEngineDenyDefaultNoMatchDenies(t *testing.T) {
	p := samplePolicy()
	p.OnlyUIDs = nil
	p.Deny = nil
	s, _ := newTestStoreWithPolicy(t, p)
	e := New(s, ModeObserve)
	d := e.Decide(Request{
		Binary:    p.Binary,
		DestIP:    net.ParseIP("8.8.8.8"),
		DestPort:  53,
		Protocol:  "udp",
		DestClass: "google",
	})
	if d.Action != ActionDeny {
		t.Fatalf("expected Deny (no allow matched), got %s", d.Action)
	}
}

func TestEngineDenyOverridesAllow(t *testing.T) {
	p := samplePolicy()
	p.OnlyUIDs = nil
	// Wide allow + targeted deny.
	p.Allow = []Rule{{Ports: []uint16{443}}}
	p.Deny = []Rule{{DestCIDR: "203.0.113.0/24"}}
	s, _ := newTestStoreWithPolicy(t, p)
	e := New(s, ModeObserve)
	d := e.Decide(Request{
		Binary:   p.Binary,
		DestIP:   net.ParseIP("203.0.113.5"),
		DestPort: 443,
		Protocol: "tcp",
	})
	if d.Action != ActionDeny {
		t.Fatalf("deny should override allow, got %s", d.Action)
	}
}

func TestEngineTorOnly(t *testing.T) {
	p := Policy{
		SchemaVersion: SchemaVersion,
		Binary:        "/usr/bin/torbrowser",
		Mode:          ModeTorOnly,
		Signer:        "operator-test",
	}
	s, _ := newTestStoreWithPolicy(t, p)
	e := New(s, ModeObserve)

	// Allow: 127.0.0.1:9050
	d := e.Decide(Request{Binary: p.Binary, DestIP: net.ParseIP("127.0.0.1"), DestPort: 9050})
	if d.Action != ActionAllow {
		t.Fatalf("tor loopback should allow, got %s", d.Action)
	}
	// Deny: anything else
	d = e.Decide(Request{Binary: p.Binary, DestIP: net.ParseIP("1.2.3.4"), DestPort: 443})
	if d.Action != ActionDeny {
		t.Fatalf("non-tor should deny, got %s", d.Action)
	}
	// Deny: localhost wrong port
	d = e.Decide(Request{Binary: p.Binary, DestIP: net.ParseIP("127.0.0.1"), DestPort: 8080})
	if d.Action != ActionDeny {
		t.Fatalf("localhost non-9050 should deny, got %s", d.Action)
	}
}

func TestEngineUIDScope(t *testing.T) {
	p := samplePolicy()
	p.Mode = ModeAllowAny
	p.Allow = nil
	p.Deny = nil
	p.OnlyUIDs = []uint32{1000}
	s, _ := newTestStoreWithPolicy(t, p)
	e := New(s, ModeObserve)
	// In-scope UID -> Allow.
	if d := e.Decide(Request{Binary: p.Binary, UID: 1000}); d.Action != ActionAllow {
		t.Fatalf("uid=1000 should match, got %s", d.Action)
	}
	// Out-of-scope UID -> Observe (default).
	if d := e.Decide(Request{Binary: p.Binary, UID: 33}); d.Action != ActionObserve {
		t.Fatalf("uid=33 out of scope should observe, got %s", d.Action)
	}
}

func TestEngineExceptUIDScope(t *testing.T) {
	p := samplePolicy()
	p.Mode = ModeAllowAny
	p.Allow = nil
	p.Deny = nil
	p.OnlyUIDs = nil
	p.ExceptUIDs = []uint32{0}
	s, _ := newTestStoreWithPolicy(t, p)
	e := New(s, ModeObserve)
	if d := e.Decide(Request{Binary: p.Binary, UID: 0}); d.Action != ActionObserve {
		t.Fatalf("uid=0 excepted should observe, got %s", d.Action)
	}
	if d := e.Decide(Request{Binary: p.Binary, UID: 1000}); d.Action != ActionAllow {
		t.Fatalf("uid=1000 not excepted should allow, got %s", d.Action)
	}
}

func TestMatchRuleFields(t *testing.T) {
	r := Rule{
		DestCIDR:  "10.0.0.0/8",
		Ports:     []uint16{443, 8443},
		Protocols: []string{"tcp"},
		SNI:       "*.example.com",
	}
	good := Request{
		DestIP:   net.ParseIP("10.1.2.3"),
		DestPort: 443,
		Protocol: "tcp",
		SNI:      "api.example.com",
	}
	if !matchRule(r, good) {
		t.Fatalf("good req should match")
	}
	bad := good
	bad.DestIP = net.ParseIP("11.1.1.1")
	if matchRule(r, bad) {
		t.Fatalf("wrong CIDR should not match")
	}
	bad = good
	bad.DestPort = 22
	if matchRule(r, bad) {
		t.Fatalf("wrong port should not match")
	}
	bad = good
	bad.SNI = "evil.com"
	if matchRule(r, bad) {
		t.Fatalf("wrong SNI should not match")
	}
}

func TestMatchHostnameWildcard(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", true}, // bare apex matches
		{"*.example.com", "evil.com", false},
		{".example.com", "deep.api.example.com", true},
		{"exact.com", "exact.com", true},
		{"exact.com", "sub.exact.com", false},
		{"EXACT.com", "exact.com", true},
	}
	for _, c := range cases {
		if got := matchHostname(c.pattern, c.host); got != c.want {
			t.Errorf("matchHostname(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestStoreReloadAfterDelete(t *testing.T) {
	s, _ := newTestStoreWithPolicy(t, samplePolicy())
	if got := s.Get("/usr/bin/curl"); got == nil {
		t.Fatalf("expected policy after save")
	}
	if err := s.Delete("/usr/bin/curl"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := s.Get("/usr/bin/curl"); got != nil {
		t.Fatalf("expected nil after delete")
	}
	// Reload from disk — file should be gone too.
	files, _ := os.ReadDir(s.dir)
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".yaml" {
			t.Fatalf("yaml file should have been removed: %s", f.Name())
		}
	}
}

func TestStoreWatcherStops(t *testing.T) {
	s, _ := newTestStoreWithPolicy(t, samplePolicy())
	ctx, cancel := context.WithCancel(context.Background())
	stop := s.StartWatcher(ctx)
	cancel()
	stop() // must not panic on double-stop
	stop()
}

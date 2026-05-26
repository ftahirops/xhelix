package egressguard

import (
	"strings"
	"testing"
	"time"
)

// fakeProfileLookup is a test-only ProfileLookup.
type fakeProfileLookup struct {
	byRole map[string][]string
}

func (f *fakeProfileLookup) UpstreamHostsForRole(role string) []string {
	return f.byRole[role]
}

func mkGuard(t *testing.T, profiles ProfileLookup, mode Mode) *guard {
	t.Helper()
	return NewGuard(newObserveBackend(mode), profiles, mode).(*guard)
}

// ─────────────────────────────────────────────────────────────────
// Decision logic
// ─────────────────────────────────────────────────────────────────

func TestDecide_LoopbackAlwaysAllowed(t *testing.T) {
	g := mkGuard(t, nil, ModeShadow)
	d, _ := g.Decide(Request{
		AppRole: "nginx-reverse-proxy",
		DestIP:  "127.0.0.1",
		DestPort: 8080,
	})
	if d != EgressAllow {
		t.Errorf("loopback: got %s, want allow", d)
	}
}

// TestDecide_MetadataIPNotTreatedAsPrivate is the regression test for
// the Phase C.3 soak finding (2026-05-26): 169.254.169.254 sits in
// link-local space but is the cloud metadata endpoint and must NOT
// receive the loopback/private bypass.
func TestDecide_MetadataIPNotTreatedAsPrivate(t *testing.T) {
	g := mkGuard(t, nil, ModeShadow)
	d, reason := g.Decide(Request{
		AppRole:  "nginx-reverse-proxy",
		DestIP:   "169.254.169.254",
		DestPort: 80,
	})
	// Protected role + raw IP (no SNI) → should deny, NOT allow as private.
	if d != EgressDeny {
		t.Errorf("metadata IP for protected role: got %s (reason=%s), want deny", d, reason)
	}
	if strings.Contains(reason, "private") {
		t.Errorf("metadata IP should not be classified as private: reason=%q", reason)
	}
}

func TestDecide_PrivateRangeAlwaysAllowed(t *testing.T) {
	g := mkGuard(t, nil, ModeShadow)
	cases := []string{"10.0.0.5", "192.168.1.1", "172.20.5.5"}
	for _, ip := range cases {
		d, _ := g.Decide(Request{
			AppRole: "nginx-reverse-proxy",
			DestIP:  ip,
		})
		if d != EgressAllow {
			t.Errorf("private %q: got %s, want allow", ip, d)
		}
	}
}

func TestDecide_ProtectedRoleRawIPDenies(t *testing.T) {
	g := mkGuard(t, nil, ModeShadow)
	d, reason := g.Decide(Request{
		AppRole:  "nginx-reverse-proxy",
		DestIP:   "203.0.113.5",
		DestPort: 443,
		// No SNI, no DNSName — raw IP
	})
	if d != EgressDeny {
		t.Errorf("protected role + raw IP: got %s, want deny (reason: %s)", d, reason)
	}
}

func TestDecide_ProtectedRoleWithSNIIsNotRawIP(t *testing.T) {
	g := mkGuard(t, nil, ModeShadow)
	d, _ := g.Decide(Request{
		AppRole:  "nginx-reverse-proxy",
		DestIP:   "203.0.113.5",
		DestPort: 443,
		SNI:      "api.example.com",
	})
	// SNI present → not a raw IP egress → falls through to "unprofiled" allow.
	if d == EgressDeny {
		t.Errorf("protected role + SNI present: should not deny raw-IP, got deny")
	}
}

func TestDecide_UnprotectedRoleRawIPAllowed(t *testing.T) {
	g := mkGuard(t, nil, ModeShadow)
	d, _ := g.Decide(Request{
		AppRole:  "user-shell",
		DestIP:   "203.0.113.5",
		DestPort: 443,
	})
	if d != EgressAllow {
		t.Errorf("unprotected role + raw IP: got %s, want allow", d)
	}
}

func TestDecide_OutboundRestrictedTaintDenies(t *testing.T) {
	g := mkGuard(t, nil, ModeShadow)
	d, _ := g.Decide(Request{
		AppRole:     "user-shell",
		DestIP:      "203.0.113.5",
		SecretTaint: "outbound_restricted",
	})
	if d != EgressDeny {
		t.Errorf("outbound_restricted taint: got %s, want deny", d)
	}
}

func TestDecide_ContainmentRequiredTaintDenies(t *testing.T) {
	g := mkGuard(t, nil, ModeShadow)
	d, _ := g.Decide(Request{
		AppRole:     "anything",
		DestIP:      "203.0.113.5",
		SecretTaint: "containment_required",
	})
	if d != EgressDeny {
		t.Errorf("containment_required: got %s, want deny", d)
	}
}

func TestDecide_SecretTouchedAloneDoesNotDeny(t *testing.T) {
	// secret_touched alone is NOT a deny trigger — only the promoted
	// states (outbound_restricted, containment_required) are.
	g := mkGuard(t, nil, ModeShadow)
	d, _ := g.Decide(Request{
		AppRole:     "user-shell",
		DestIP:      "203.0.113.5",
		SNI:         "api.github.com",
		SecretTaint: "secret_touched",
	})
	if d == EgressDeny {
		t.Errorf("secret_touched (not promoted): should not deny, got deny")
	}
}

func TestDecide_DeclaredPeerAllowed(t *testing.T) {
	profiles := &fakeProfileLookup{
		byRole: map[string][]string{
			"nginx-reverse-proxy": {"backend.internal:8080"},
		},
	}
	g := mkGuard(t, profiles, ModeShadow)
	d, _ := g.Decide(Request{
		AppRole:  "nginx-reverse-proxy",
		DestIP:   "203.0.113.5",
		DestPort: 8080,
		DNSName:  "backend.internal",
	})
	if d != EgressAllow {
		t.Errorf("declared peer: got %s, want allow", d)
	}
}

func TestDecide_UndeclaredPeerReturnsVerify(t *testing.T) {
	profiles := &fakeProfileLookup{
		byRole: map[string][]string{
			"nginx-reverse-proxy": {"backend.internal:8080"},
		},
	}
	g := mkGuard(t, profiles, ModeShadow)
	d, _ := g.Decide(Request{
		AppRole:  "nginx-reverse-proxy",
		DestIP:   "203.0.113.5",
		DestPort: 443,
		DNSName:  "evil.example.com",
	})
	if d != EgressVerify {
		t.Errorf("undeclared peer: got %s, want verify", d)
	}
}

func TestDecide_WildcardHostMatch(t *testing.T) {
	profiles := &fakeProfileLookup{
		byRole: map[string][]string{
			"api-worker": {"*.example.com:443"},
		},
	}
	g := mkGuard(t, profiles, ModeShadow)
	d, _ := g.Decide(Request{
		AppRole:  "api-worker",
		DNSName:  "api.example.com",
		DestPort: 443,
	})
	if d != EgressAllow {
		t.Errorf("wildcard match: got %s, want allow", d)
	}
}

func TestDecide_WildcardPort(t *testing.T) {
	profiles := &fakeProfileLookup{
		byRole: map[string][]string{
			"api-worker": {"api.example.com:*"},
		},
	}
	g := mkGuard(t, profiles, ModeShadow)
	for _, port := range []uint16{80, 443, 8080} {
		d, _ := g.Decide(Request{
			AppRole: "api-worker", DNSName: "api.example.com", DestPort: port,
		})
		if d != EgressAllow {
			t.Errorf("port wildcard %d: got %s, want allow", port, d)
		}
	}
}

// ─────────────────────────────────────────────────────────────────
// ApplyDeny + cache + shadow vs enforce
// ─────────────────────────────────────────────────────────────────

func TestApplyDeny_ShadowModeDoesNotPushToBackend(t *testing.T) {
	// Use observe backend so we can detect "no push happened" by no error.
	g := mkGuard(t, nil, ModeShadow)
	if err := g.ApplyDeny(42, "203.0.113.5:443", time.Minute); err != nil {
		t.Errorf("shadow ApplyDeny errored: %v", err)
	}
}

func TestApplyDeny_DenyCacheSuppressesDuplicate(t *testing.T) {
	g := mkGuard(t, nil, ModeShadow)
	g.ApplyDeny(1, "203.0.113.5:443", time.Minute)
	g.ApplyDeny(1, "203.0.113.5:443", time.Minute) // duplicate
	g.ApplyDeny(2, "203.0.113.5:443", time.Minute) // different lineage
	if g.cache.Size() != 2 {
		t.Errorf("cache size after dedupe: %d, want 2", g.cache.Size())
	}
}

func TestApplyDeny_DenyCacheExpiry(t *testing.T) {
	g := mkGuard(t, nil, ModeShadow)
	g.ApplyDeny(1, "203.0.113.5:443", 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	// has() should report expired
	if g.cache.has(1, "203.0.113.5:443") {
		t.Error("cache entry should expire")
	}
}

// ─────────────────────────────────────────────────────────────────
// Protected-role runtime configuration
// ─────────────────────────────────────────────────────────────────

func TestSetProtectedRoles_RuntimeUpdate(t *testing.T) {
	g := mkGuard(t, nil, ModeShadow)
	g.SetProtectedRoles([]string{"custom-role-a", "custom-role-b"})
	roles := g.ProtectedRoles()
	if len(roles) != 2 {
		t.Errorf("after set: %d roles, want 2 (%v)", len(roles), roles)
	}
	// nginx-reverse-proxy was in default but not in custom set
	d, _ := g.Decide(Request{AppRole: "nginx-reverse-proxy", DestIP: "203.0.113.5"})
	if d == EgressDeny {
		t.Error("after replace: nginx-reverse-proxy should NOT be protected anymore")
	}
	d, _ = g.Decide(Request{AppRole: "custom-role-a", DestIP: "203.0.113.5"})
	if d != EgressDeny {
		t.Error("after replace: custom-role-a SHOULD be protected (raw-IP egress)")
	}
}

// ─────────────────────────────────────────────────────────────────
// destKey + matchesDeclaredPeer helpers
// ─────────────────────────────────────────────────────────────────

func TestDestKey_PreferenceOrder(t *testing.T) {
	cases := []struct {
		r    Request
		want string
	}{
		{Request{SNI: "a.com", DestPort: 443}, "a.com:443"},
		{Request{DNSName: "b.com", DestPort: 80}, "b.com:80"},
		{Request{DestIP: "1.2.3.4", DestPort: 22}, "1.2.3.4:22"},
		{Request{SNI: "a", DNSName: "b", DestIP: "1", DestPort: 1}, "a:1"},
		{Request{}, ""},
	}
	for _, c := range cases {
		if got := destKey(c.r); got != c.want {
			t.Errorf("destKey(%+v) = %q, want %q", c.r, got, c.want)
		}
	}
}

func TestHostMatch_Exact(t *testing.T) {
	if !hostMatch("example.com", "example.com") {
		t.Error("exact match should work")
	}
	if hostMatch("example.com", "other.com") {
		t.Error("non-match should fail")
	}
}

func TestHostMatch_Wildcard(t *testing.T) {
	if !hostMatch("*.example.com", "api.example.com") {
		t.Error("wildcard should match")
	}
	if !hostMatch("*.example.com", "deep.api.example.com") {
		t.Error("wildcard should match nested")
	}
	if hostMatch("*.example.com", "example.com") {
		t.Error("wildcard should NOT match bare apex")
	}
}

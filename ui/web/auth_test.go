package web

import (
	"crypto/sha256"
	"net"
	"net/http/httptest"
	"testing"
)

func mustCIDR(t *testing.T, raw string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(raw)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", raw, err)
	}
	return n
}

func TestTokenOKRejectsQueryToken(t *testing.T) {
	sum := sha256.Sum256([]byte("secret-token"))
	g := &AuthGuard{token: sum[:]}

	req := httptest.NewRequest("GET", "http://xhelix.local/ui?token=secret-token", nil)
	if g.tokenOK(req) {
		t.Fatal("query token should be rejected")
	}

	req = httptest.NewRequest("GET", "http://xhelix.local/ui", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	if !g.tokenOK(req) {
		t.Fatal("authorization header token should be accepted")
	}
}

func TestClientIPIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	g := &AuthGuard{
		cfg: AuthConfig{
			TrustForwardedFor: true,
			TrustedProxies:    []*net.IPNet{mustCIDR(t, "127.0.0.1/32")},
		},
	}
	req := httptest.NewRequest("GET", "http://xhelix.local/ui", nil)
	req.RemoteAddr = "203.0.113.10:4242"
	req.Header.Set("X-Forwarded-For", "198.51.100.9")

	if got := g.clientIP(req).String(); got != "203.0.113.10" {
		t.Fatalf("clientIP = %s, want peer IP 203.0.113.10", got)
	}
}

func TestClientIPAcceptsForwardedHeadersFromTrustedProxy(t *testing.T) {
	g := &AuthGuard{
		cfg: AuthConfig{
			TrustForwardedFor: true,
			TrustedProxies:    []*net.IPNet{mustCIDR(t, "127.0.0.1/32")},
		},
	}
	req := httptest.NewRequest("GET", "http://xhelix.local/ui", nil)
	req.RemoteAddr = "127.0.0.1:4242"
	req.Header.Set("X-Forwarded-For", "198.51.100.9, 127.0.0.1")

	if got := g.clientIP(req).String(); got != "198.51.100.9" {
		t.Fatalf("clientIP = %s, want forwarded client IP 198.51.100.9", got)
	}
}

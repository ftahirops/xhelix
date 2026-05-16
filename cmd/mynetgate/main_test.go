package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseAllowlistIPandCIDR(t *testing.T) {
	nets, err := parseAllowlist("127.0.0.1, 10.0.0.0/24, ::1")
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 3 {
		t.Fatalf("want 3 nets, got %d", len(nets))
	}
	cases := []struct {
		ip string
		ok bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", false},
		{"10.0.0.55", true},
		{"10.0.1.1", false},
		{"::1", true},
		{"2001:db8::1", false},
	}
	for _, c := range cases {
		got := ipAllowed(net.ParseIP(c.ip), nets)
		if got != c.ok {
			t.Errorf("%s: got %v want %v", c.ip, got, c.ok)
		}
	}
}

func TestParseAllowlistEmpty(t *testing.T) {
	if _, err := parseAllowlist(""); err == nil {
		t.Fatal("empty allow-list must error")
	}
	if _, err := parseAllowlist("not-an-ip"); err == nil {
		t.Fatal("garbage allow-list must error")
	}
}

func TestWithIPAllowlistBlocks(t *testing.T) {
	nets, _ := parseAllowlist("127.0.0.1/32")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	called := false
	h := withIPAllowlist(nets, log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	// Allowed peer.
	r := httptest.NewRequest("GET", "/api/v1/ping", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !called {
		t.Fatalf("allowed peer should pass; code=%d called=%v", w.Code, called)
	}

	// Blocked peer.
	called = false
	r = httptest.NewRequest("GET", "/api/v1/ping", nil)
	r.RemoteAddr = "10.0.0.5:11111"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || called {
		t.Fatalf("non-allowlisted peer should 403; code=%d called=%v", w.Code, called)
	}
}

func TestWithCORSEchoesAllowedOriginOnly(t *testing.T) {
	allowed := []string{"http://example.com"}
	h := withCORS(allowed, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://example.com" {
		t.Errorf("allowed origin not echoed; got %q", got)
	}

	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "http://evil.com")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("disallowed origin must not be echoed; got %q", got)
	}
}

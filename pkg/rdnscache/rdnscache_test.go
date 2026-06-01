package rdnscache

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCache_HitMissTTLNegative(t *testing.T) {
	calls := 0
	now := time.Unix(1000, 0)
	c := New(time.Minute, 16, func(_ context.Context, ip string) (string, error) {
		calls++
		if ip == "9.9.9.9" {
			return "", errors.New("nxdomain")
		}
		return "host.example.com.", nil
	})
	c.now = func() time.Time { return now }

	// miss then hit
	if n, ok := c.Lookup(context.Background(), "1.2.3.4"); !ok || n != "host.example.com." {
		t.Fatalf("first lookup: %q ok=%v", n, ok)
	}
	if _, _ = c.Lookup(context.Background(), "1.2.3.4"); calls != 1 {
		t.Fatalf("second lookup should hit cache, calls=%d want 1", calls)
	}
	// negative cached: one resolve, then served from cache
	if _, ok := c.Lookup(context.Background(), "9.9.9.9"); ok {
		t.Fatal("9.9.9.9 should be negative")
	}
	if _, ok := c.Lookup(context.Background(), "9.9.9.9"); ok || calls != 2 {
		t.Fatalf("negative not cached: ok=%v calls=%d want 2", ok, calls)
	}
	// TTL expiry forces re-resolve
	now = now.Add(2 * time.Minute)
	if _, _ = c.Lookup(context.Background(), "1.2.3.4"); calls != 3 {
		t.Fatalf("expired entry should re-resolve, calls=%d want 3", calls)
	}
	h, m := c.Stats()
	if h == 0 || m == 0 {
		t.Fatalf("stats not tracked: hits=%d misses=%d", h, m)
	}
}

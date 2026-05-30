package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/xhubfleet"
)

// TestTrustPersist_SaveReload proves trust state survives a fresh ranker
// constructed from the same data dir: a Trusted host can still teach.
func TestTrustPersist_SaveReload(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC)

	r1 := xhubfleet.NewTrustRanker(xhubfleet.DefaultTrustPolicy())
	// Drive a host to Trusted via injected times (3 + 7 = 10 day policy).
	const host = "web-1"
	r1.See(host, now.Add(-20*24*time.Hour))
	r1.See(host, now)
	if got := r1.Evaluate(host, now); got != xhubfleet.TrustTrusted {
		t.Fatalf("setup: host should be Trusted, got %q", got)
	}
	if err := saveTrust(dir, r1); err != nil {
		t.Fatalf("saveTrust: %v", err)
	}

	// Fresh ranker, same dir.
	r2 := xhubfleet.NewTrustRanker(xhubfleet.DefaultTrustPolicy())
	if !r2.CanTeach(host) { // sanity: empty before load
		// expected: cannot teach yet
	} else {
		t.Fatalf("pre-load: fresh ranker should not know %q", host)
	}
	if err := loadTrust(dir, r2); err != nil {
		t.Fatalf("loadTrust: %v", err)
	}
	if !r2.CanTeach(host) {
		t.Fatalf("after reload: %q should be able to teach", host)
	}
}

// TestTrustPersist_MissingFileOK confirms loading from an empty dir is a
// no-op, not an error.
func TestTrustPersist_MissingFileOK(t *testing.T) {
	dir := t.TempDir()
	r := xhubfleet.NewTrustRanker(xhubfleet.DefaultTrustPolicy())
	if err := loadTrust(dir, r); err != nil {
		t.Fatalf("loadTrust on empty dir should be nil, got %v", err)
	}
	if len(r.All()) != 0 {
		t.Fatalf("expected no records after loading empty dir")
	}
}

// TestTrustPersist_AtomicPath confirms the save target is the documented
// trust.json under the data dir.
func TestTrustPersist_AtomicPath(t *testing.T) {
	dir := t.TempDir()
	r := xhubfleet.NewTrustRanker(xhubfleet.DefaultTrustPolicy())
	r.See("h", time.Now())
	if err := saveTrust(dir, r); err != nil {
		t.Fatalf("saveTrust: %v", err)
	}
	if _, err := readFileOK(filepath.Join(dir, "trust.json")); err != nil {
		t.Fatalf("trust.json not written: %v", err)
	}
}

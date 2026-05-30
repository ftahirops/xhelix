package xhubfleet

import (
	"testing"
	"time"
)

// TestTrustRanker_AgePromotion drives a single host through the policy
// thresholds with injected times: < MinObservedDays → Untrusted (cannot
// teach); >= MinObservedDays+MinCandidateDays with low alerts → Trusted
// (can teach).
func TestTrustRanker_AgePromotion(t *testing.T) {
	p := DefaultTrustPolicy() // 3 observed + 7 candidate = 10 days
	r := NewTrustRanker(p)
	const host = "web-1"
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Day 0: first sighting.
	r.See(host, t0)
	if got := r.Evaluate(host, t0); got != TrustUntrusted {
		t.Fatalf("day 0: got %q want %q", got, TrustUntrusted)
	}
	if r.CanTeach(host) {
		t.Fatalf("day 0: CanTeach should be false")
	}

	// Day 2: still inside observation window.
	d2 := t0.Add(2 * 24 * time.Hour)
	r.See(host, d2)
	if got := r.Evaluate(host, d2); got != TrustUntrusted {
		t.Fatalf("day 2: got %q want %q", got, TrustUntrusted)
	}
	if r.CanTeach(host) {
		t.Fatalf("day 2: CanTeach should be false")
	}

	// Day 4: past observation, inside candidate window.
	d4 := t0.Add(4 * 24 * time.Hour)
	r.See(host, d4)
	if got := r.Evaluate(host, d4); got != TrustCandidate {
		t.Fatalf("day 4: got %q want %q", got, TrustCandidate)
	}
	if r.CanTeach(host) {
		t.Fatalf("day 4: CanTeach should be false (candidate)")
	}

	// Day 11: past full trust period, low alerts → Trusted.
	d11 := t0.Add(11 * 24 * time.Hour)
	r.See(host, d11)
	if got := r.Evaluate(host, d11); got != TrustTrusted {
		t.Fatalf("day 11: got %q want %q", got, TrustTrusted)
	}
	if !r.CanTeach(host) {
		t.Fatalf("day 11: CanTeach should be true (trusted)")
	}
}

// TestTrustRanker_Restore proves a fresh ranker reloads persisted records
// as-is, including a Trusted host that can immediately teach.
func TestTrustRanker_Restore(t *testing.T) {
	now := time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC)
	records := []HostRecord{
		{HostTag: "trusted-1", FirstSeen: now.Add(-20 * 24 * time.Hour), LastSeen: now, Trust: TrustTrusted, Reason: "reloaded"},
		{HostTag: "new-1", FirstSeen: now, LastSeen: now, Trust: TrustUntrusted},
	}
	r := NewTrustRanker(DefaultTrustPolicy())
	r.Restore(records)

	if !r.CanTeach("trusted-1") {
		t.Fatalf("trusted-1 should be able to teach after Restore")
	}
	if r.CanTeach("new-1") {
		t.Fatalf("new-1 should not be able to teach after Restore")
	}
	all := r.All()
	if len(all) != 2 {
		t.Fatalf("Restore: got %d records want 2", len(all))
	}
}

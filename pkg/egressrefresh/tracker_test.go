package egressrefresh

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTrackerWithinGraceSortedDeduped(t *testing.T) {
	tr := NewTracker()
	tr.Observe("u", []string{"10.0.0.2/32", "10.0.0.1/32", "10.0.0.2/32"}, t0)
	got := tr.WithinGrace("u", t0, time.Hour)
	if !eq(got, []string{"10.0.0.1/32", "10.0.0.2/32"}) {
		t.Errorf("got %v", got)
	}
}

func TestTrackerKeepsIPsWithinGrace(t *testing.T) {
	tr := NewTracker()
	tr.Observe("u", []string{"10.0.0.1/32"}, t0)
	// 5 min later, NOT re-observed, grace 10 min -> still present.
	got := tr.WithinGrace("u", t0.Add(5*time.Minute), 10*time.Minute)
	if !eq(got, []string{"10.0.0.1/32"}) {
		t.Errorf("ip should survive within grace, got %v", got)
	}
}

func TestTrackerDropsAfterGrace(t *testing.T) {
	tr := NewTracker()
	tr.Observe("u", []string{"10.0.0.1/32"}, t0)
	// 15 min later, grace 10 min -> dropped.
	got := tr.WithinGrace("u", t0.Add(15*time.Minute), 10*time.Minute)
	if len(got) != 0 {
		t.Errorf("ip should expire after grace, got %v", got)
	}
}

func TestTrackerReobserveExtendsGrace(t *testing.T) {
	tr := NewTracker()
	tr.Observe("u", []string{"10.0.0.1/32"}, t0)
	tr.Observe("u", []string{"10.0.0.1/32"}, t0.Add(8*time.Minute)) // refreshed
	got := tr.WithinGrace("u", t0.Add(15*time.Minute), 10*time.Minute)
	if !eq(got, []string{"10.0.0.1/32"}) {
		t.Errorf("re-observed ip should persist, got %v", got)
	}
}

func TestTrackerForget(t *testing.T) {
	tr := NewTracker()
	tr.Observe("u", []string{"10.0.0.1/32"}, t0)
	tr.Forget("u")
	if got := tr.WithinGrace("u", t0, time.Hour); len(got) != 0 {
		t.Errorf("forgotten unit should be empty, got %v", got)
	}
}

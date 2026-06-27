package webroot

import "testing"

func TestTracker_GetPut(t *testing.T) {
	tr := New()
	if _, ok := tr.Get("site-a.com"); ok {
		t.Fatal("unseen vhost must not be cached")
	}
	if !tr.Put("site-a.com", 7) {
		t.Fatal("Put under cap should succeed")
	}
	id, ok := tr.Get("site-a.com")
	if !ok || id != 7 {
		t.Errorf("Get after Put = (%d,%v), want (7,true)", id, ok)
	}
	if _, ok := tr.Get("site-b.com"); ok {
		t.Error("site-b.com must be independent")
	}
}

func TestTracker_CapStopsNewVhosts(t *testing.T) {
	tr := NewWithCap(2)
	if !tr.Put("a", 1) || !tr.Put("b", 2) {
		t.Fatal("first two Puts should succeed")
	}
	if tr.Put("c", 3) {
		t.Error("Put past cap should be refused for a NEW vhost")
	}
	if tr.Len() != 2 {
		t.Errorf("Len=%d, want 2 (bounded)", tr.Len())
	}
	// updating an already-cached vhost is still allowed at cap
	if !tr.Put("a", 9) {
		t.Error("updating an existing vhost at cap should succeed")
	}
	if id, _ := tr.Get("a"); id != 9 {
		t.Errorf("a=%d, want 9 after update", id)
	}
}

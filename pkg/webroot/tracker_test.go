package webroot

import (
	"context"
	"testing"

	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/model"
)

// fakeMinter records the identity event it was handed and mints a fresh,
// monotonically increasing anchor id each call.
type fakeMinter struct {
	next lineage.LineageID
	last model.Event
	n    int
}

func (f *fakeMinter) MintFromEvent(_ context.Context, ev model.Event) (lineage.LineageID, error) {
	f.n++
	f.next++
	f.last = ev
	return f.next, nil
}

func TestTracker_NextSeqMonotonic(t *testing.T) {
	tr := New()
	if a, b, c := tr.NextSeq("h"), tr.NextSeq("h"), tr.NextSeq("h"); a != 1 || b != 2 || c != 3 {
		t.Errorf("NextSeq(h) = %d,%d,%d, want 1,2,3", a, b, c)
	}
	// Independent per host.
	if got := tr.NextSeq("other"); got != 1 {
		t.Errorf("NextSeq(other) = %d, want 1 (independent counter)", got)
	}
}

func TestTracker_MintRequestOncePerRid(t *testing.T) {
	tr := New()
	fm := &fakeMinter{}
	ev := model.Event{PID: 9001, Tags: map[string]string{
		"http_host": "site-a.com", "http_uri": "/wp-login.php",
	}}

	id, minted := tr.MintRequest(context.Background(), fm, ev, "f9001-1-0")
	if !minted || id == 0 {
		t.Fatalf("first MintRequest = (%d,%v), want non-zero + true", id, minted)
	}
	// The identity event handed to the minter must carry the web mint tags.
	if fm.last.Tags["service"] != "web" || fm.last.Tags["http_host"] != "site-a.com" ||
		fm.last.Tags["request_id"] != "f9001-1-0" {
		t.Errorf("mint identity event tags = %v, want service=web + host + request_id", fm.last.Tags)
	}

	// Same rid must NOT mint again (mint-once); returns the cached id, false.
	id2, minted2 := tr.MintRequest(context.Background(), fm, ev, "f9001-1-0")
	if minted2 || id2 != id {
		t.Errorf("repeat MintRequest = (%d,%v), want (%d,false)", id2, minted2, id)
	}
	if fm.n != 1 {
		t.Errorf("minter called %d times, want exactly 1 (mint-once per rid)", fm.n)
	}

	// A distinct rid mints a fresh anchor.
	id3, minted3 := tr.MintRequest(context.Background(), fm, ev, "f9001-2-1")
	if !minted3 || id3 == id {
		t.Errorf("distinct-rid MintRequest = (%d,%v), want fresh anchor + true", id3, minted3)
	}
}

func TestTracker_MintRequestCapBounded(t *testing.T) {
	tr := NewWithCap(1)
	fm := &fakeMinter{}
	ev := model.Event{PID: 1, Tags: map[string]string{"http_host": "h"}}
	if _, ok := tr.MintRequest(context.Background(), fm, ev, "r1"); !ok {
		t.Fatal("first MintRequest under cap should mint")
	}
	if id, ok := tr.MintRequest(context.Background(), fm, ev, "r2"); ok || id != 0 {
		t.Errorf("MintRequest past cap = (%d,%v), want (0,false)", id, ok)
	}
}

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

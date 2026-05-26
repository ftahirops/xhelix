package source

import (
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/lineage"
)

func TestFileTaint_RecordLookup_RoundTrip(t *testing.T) {
	ft := NewFileTaint(100, time.Hour)
	cs := NewCausalSet(1, 2, 3)
	ft.RecordWrite("/etc/passwd", 42, cs, time.Now())

	got, ok := ft.Lookup("/etc/passwd")
	if !ok {
		t.Fatal("Lookup should find /etc/passwd")
	}
	if got.LastWriterPrimary != 42 {
		t.Errorf("LastWriterPrimary = %d, want 42", got.LastWriterPrimary)
	}
	if !got.Set.Equal(cs) {
		t.Errorf("Set = %v, want %v", got.Set.Slice(), cs.Slice())
	}
	if got.SetHash != cs.Hash() {
		t.Errorf("SetHash mismatch")
	}
}

func TestFileTaint_UnknownPath(t *testing.T) {
	ft := NewFileTaint(100, time.Hour)
	_, ok := ft.Lookup("/nope")
	if ok {
		t.Error("Lookup on empty tracker must return false")
	}
}

func TestFileTaint_EmptyPathNoop(t *testing.T) {
	ft := NewFileTaint(100, time.Hour)
	ft.RecordWrite("", 1, NewCausalSet(1), time.Now())
	if ft.Size() != 0 {
		t.Errorf("empty path should not be recorded, size=%d", ft.Size())
	}
}

func TestFileTaint_ZeroProvenanceNoop(t *testing.T) {
	ft := NewFileTaint(100, time.Hour)
	ft.RecordWrite("/x", 0, CausalSet{}, time.Now())
	if ft.Size() != 0 {
		t.Errorf("zero primary + empty set should not be recorded")
	}
}

func TestFileTaint_ReplaceInPlace(t *testing.T) {
	ft := NewFileTaint(100, time.Hour)
	ft.RecordWrite("/x", 1, NewCausalSet(1), time.Now())
	ft.RecordWrite("/x", 2, NewCausalSet(2, 3), time.Now())

	got, _ := ft.Lookup("/x")
	if got.LastWriterPrimary != 2 {
		t.Errorf("replace failed: got primary=%d, want 2", got.LastWriterPrimary)
	}
	if ft.Size() != 1 {
		t.Errorf("replace should not double-count: size=%d, want 1", ft.Size())
	}
}

func TestFileTaint_FIFOEvictionAtCap(t *testing.T) {
	const cap = 3
	ft := NewFileTaint(cap, time.Hour)
	ft.RecordWrite("/a", 1, NewCausalSet(1), time.Now())
	ft.RecordWrite("/b", 2, NewCausalSet(2), time.Now())
	ft.RecordWrite("/c", 3, NewCausalSet(3), time.Now())
	ft.RecordWrite("/d", 4, NewCausalSet(4), time.Now())

	if ft.Size() != cap {
		t.Errorf("after overflow: size=%d, want %d", ft.Size(), cap)
	}
	// /a was oldest and should be evicted.
	if _, ok := ft.Lookup("/a"); ok {
		t.Error("/a should have been FIFO-evicted")
	}
	if _, ok := ft.Lookup("/d"); !ok {
		t.Error("/d should be present (newest)")
	}
}

func TestFileTaint_TTLExpiryOnLookup(t *testing.T) {
	ft := NewFileTaint(100, 10*time.Millisecond)
	ft.RecordWrite("/x", 1, NewCausalSet(1), time.Now().Add(-time.Hour))
	if _, ok := ft.Lookup("/x"); ok {
		t.Error("stale entry must not be returned by Lookup (lazy TTL)")
	}
}

func TestFileTaint_SweepRemovesOld(t *testing.T) {
	ft := NewFileTaint(100, time.Hour)
	old := time.Now().Add(-2 * time.Hour)
	now := time.Now()
	ft.RecordWrite("/old1", 1, NewCausalSet(1), old)
	ft.RecordWrite("/old2", 2, NewCausalSet(2), old)
	ft.RecordWrite("/new", 3, NewCausalSet(3), now)

	removed := ft.SweepOlderThan(now.Add(-time.Hour))
	if removed != 2 {
		t.Errorf("Sweep removed=%d, want 2", removed)
	}
	if ft.Size() != 1 {
		t.Errorf("after sweep: size=%d, want 1", ft.Size())
	}
	if _, ok := ft.Lookup("/new"); !ok {
		t.Error("/new should survive sweep")
	}
}

func TestFileTaint_ConcurrentAccessNoRace(t *testing.T) {
	ft := NewFileTaint(1000, time.Hour)
	done := make(chan struct{})
	for w := 0; w < 4; w++ {
		go func(seed int) {
			for i := 0; i < 250; i++ {
				path := "/p" + string(rune('a'+(i%26)))
				ft.RecordWrite(path, 1, NewCausalSet(lineage.LineageID(seed*1000+i+1)), time.Now())
				_, _ = ft.Lookup(path)
			}
			done <- struct{}{}
		}(w)
	}
	for w := 0; w < 4; w++ {
		<-done
	}
	if ft.Size() <= 0 {
		t.Error("tracker should have entries after concurrent writes")
	}
}

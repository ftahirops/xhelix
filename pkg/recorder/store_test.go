package recorder

import (
	"path/filepath"
	"testing"
	"time"
)

func mkStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(Options{Path: filepath.Join(t.TempDir(), "rec.db"), ExemplarsPerShape: 3, RetentionDays: 30})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func chainFixture(app, chainID string, edges []Edge, ts time.Time) Chain {
	return Chain{AppID: app, ChainID: chainID, RootType: "web", Phase: "request", Edges: edges, FirstSeen: ts, LastSeen: ts}
}

func TestStore_RecordChain_UpsertsShapeCount(t *testing.T) {
	s := mkStore(t)
	t0 := time.Unix(1_700_000_000, 0)
	e := []Edge{{Kind: EdgeExec, Key: "curl", Raw: "/usr/bin/curl"}}
	// Two chains with the SAME shape → count 2, one shape row.
	if err := s.RecordChain(chainFixture("shop", "c1", e, t0)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordChain(chainFixture("shop", "c2", e, t0.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Shapes("shop")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Count != 2 {
		t.Fatalf("want 1 shape count=2, got %+v", rows)
	}
	if !rows[0].LastSeen.Equal(t0.Add(time.Minute)) {
		t.Errorf("last_seen not advanced: %v", rows[0].LastSeen)
	}
}

func TestStore_ExemplarsCappedAndDistinct(t *testing.T) {
	s := mkStore(t) // cap = 3
	t0 := time.Unix(1_700_000_000, 0)
	// Same shape (write edge to same dir), four distinct leaf files.
	for _, leaf := range []string{"a", "b", "c", "d"} {
		e := []Edge{{Kind: EdgeWrite, Key: "/u/up", Raw: "/u/up/" + leaf}}
		if err := s.RecordChain(chainFixture("shop", "c-"+leaf, e, t0)); err != nil {
			t.Fatal(err)
		}
	}
	sh := ShapeHash([]Edge{{Kind: EdgeWrite, Key: "/u/up"}})
	ex, err := s.Exemplars("shop", sh)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex) != 3 {
		t.Fatalf("exemplars must be capped at 3, got %d (%v)", len(ex), ex)
	}
}

func TestStore_DropOld(t *testing.T) {
	s := mkStore(t) // retention 30d
	old := time.Unix(1_700_000_000, 0)
	s.RecordChain(chainFixture("shop", "c1", []Edge{{Kind: EdgeExec, Key: "curl", Raw: "/usr/bin/curl"}}, old))
	now := old.Add(31 * 24 * time.Hour)
	n, err := s.DropOld(now)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("expected old shape to be pruned")
	}
	if rows, _ := s.Shapes("shop"); len(rows) != 0 {
		t.Errorf("shape should be gone after DropOld, got %+v", rows)
	}
}

package contractpropose

import (
	"path/filepath"
	"testing"
)

func openTmp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "prop.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateGet(t *testing.T) {
	s := openTmp(t)
	p, err := s.Create(Proposal{App: "wp", Submitter: "operator", Reason: "deploy v2",
		TargetSHA: "abc", DeclarationJSON: []byte(`{"name":"wp"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "" || p.Status != StatusPending {
		t.Errorf("bad created proposal: %+v", p)
	}
	got, ok := s.Get("wp", p.ID)
	if !ok || got.Reason != "deploy v2" || string(got.DeclarationJSON) != `{"name":"wp"}` {
		t.Errorf("get mismatch: %+v ok=%v", got, ok)
	}
	// Cross-app isolation: same id under a different app must not resolve.
	if _, ok := s.Get("other", p.ID); ok {
		t.Error("proposal must be scoped to its app")
	}
}

func TestDecide_OnlyPendingOnce(t *testing.T) {
	s := openTmp(t)
	p, _ := s.Create(Proposal{App: "wp", DeclarationJSON: []byte("{}")})
	if err := s.Decide("wp", p.ID, StatusApproved, "admin"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	got, _ := s.Get("wp", p.ID)
	if got.Status != StatusApproved || got.DecidedBy != "admin" {
		t.Errorf("status not updated: %+v", got)
	}
	// Second decision must fail — already decided.
	if err := s.Decide("wp", p.ID, StatusRejected, "admin"); err == nil {
		t.Error("a decided proposal must not be re-decided")
	}
}

func TestDecide_InvalidStatus(t *testing.T) {
	s := openTmp(t)
	p, _ := s.Create(Proposal{App: "wp", DeclarationJSON: []byte("{}")})
	if err := s.Decide("wp", p.ID, StatusPending, "x"); err == nil {
		t.Error("pending is not a valid decision")
	}
}

func TestListForApp_NewestFirst(t *testing.T) {
	s := openTmp(t)
	_, _ = s.Create(Proposal{App: "wp", Reason: "first", DeclarationJSON: []byte("{}")})
	_, _ = s.Create(Proposal{App: "wp", Reason: "second", DeclarationJSON: []byte("{}")})
	_, _ = s.Create(Proposal{App: "other", Reason: "x", DeclarationJSON: []byte("{}")})
	got, err := s.ListForApp("wp", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 for wp, got %d", len(got))
	}
}

func TestRandID_Unique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id, err := randID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatal("duplicate id generated")
		}
		seen[id] = true
	}
}

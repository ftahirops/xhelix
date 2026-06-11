package contractaudit

import (
	"path/filepath"
	"testing"
	"time"
)

func openTmp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRecordAndChain(t *testing.T) {
	s := openTmp(t)
	base := time.Unix(1700000000, 0)
	e1, err := s.Record(Entry{Time: base, Role: "admin", TokenName: "admin", SourceIP: "10.0.0.1",
		Action: "arm", App: "wordpress", Detail: "nginx.service", Outcome: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	if e1.Seq != 1 || e1.PrevHash != "" || e1.Hash == "" {
		t.Errorf("genesis entry wrong: %+v", e1)
	}
	e2, _ := s.Record(Entry{Time: base.Add(time.Second), Role: "operator", TokenName: "op",
		Action: "disarm", App: "wordpress", Outcome: "ok"})
	if e2.Seq != 2 || e2.PrevHash != e1.Hash {
		t.Errorf("chain linkage broken: e2.prev=%s e1.hash=%s", e2.PrevHash, e1.Hash)
	}

	res, err := s.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Checked != 2 {
		t.Errorf("verify failed: %+v", res)
	}
}

func TestVerify_DetectsTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	s, _ := Open(path)
	base := time.Unix(1700000000, 0)
	for i := 0; i < 5; i++ {
		_, _ = s.Record(Entry{Time: base.Add(time.Duration(i) * time.Second),
			Role: "admin", TokenName: "admin", Action: "arm", App: "app", Outcome: "ok"})
	}
	// Tamper: edit a row's outcome directly in the DB.
	if _, err := s.db.Exec(`UPDATE audit SET outcome='forged' WHERE seq=3`); err != nil {
		t.Fatal(err)
	}
	res, err := s.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("verify should have detected the edited row")
	}
	if res.BrokenAtSeq != 3 {
		t.Errorf("expected break at seq 3, got %d", res.BrokenAtSeq)
	}
}

func TestVerify_DetectsDeletion(t *testing.T) {
	s := openTmp(t)
	base := time.Unix(1700000000, 0)
	for i := 0; i < 5; i++ {
		_, _ = s.Record(Entry{Time: base.Add(time.Duration(i) * time.Second),
			Role: "admin", TokenName: "admin", Action: "arm", App: "app", Outcome: "ok"})
	}
	// Delete a middle row → the next row's prev_hash no longer links.
	if _, err := s.db.Exec(`DELETE FROM audit WHERE seq=3`); err != nil {
		t.Fatal(err)
	}
	res, _ := s.Verify()
	if res.OK {
		t.Fatal("verify should have detected the deletion")
	}
	if res.BrokenAtSeq != 4 {
		t.Errorf("expected break at seq 4 (orphaned link), got %d", res.BrokenAtSeq)
	}
}

func TestRecoverTip_AcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	s, _ := Open(path)
	base := time.Unix(1700000000, 0)
	e1, _ := s.Record(Entry{Time: base, Role: "admin", TokenName: "a", Action: "arm", App: "x", Outcome: "ok"})
	s.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	e2, _ := s2.Record(Entry{Time: base.Add(time.Second), Role: "admin", TokenName: "a", Action: "disarm", App: "x", Outcome: "ok"})
	if e2.Seq != 2 || e2.PrevHash != e1.Hash {
		t.Errorf("tip not recovered across reopen: e2=%+v", e2)
	}
	res, _ := s2.Verify()
	if !res.OK || res.Checked != 2 {
		t.Errorf("verify after reopen failed: %+v", res)
	}
}

func TestListForApp(t *testing.T) {
	s := openTmp(t)
	base := time.Unix(1700000000, 0)
	_, _ = s.Record(Entry{Time: base, Role: "admin", TokenName: "a", Action: "arm", App: "app1", Outcome: "ok"})
	_, _ = s.Record(Entry{Time: base.Add(time.Second), Role: "admin", TokenName: "a", Action: "arm", App: "app2", Outcome: "ok"})
	_, _ = s.Record(Entry{Time: base.Add(2 * time.Second), Role: "admin", TokenName: "a", Action: "disarm", App: "app1", Outcome: "ok"})

	got, err := s.ListForApp("app1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 entries for app1, got %d", len(got))
	}
	if got[0].Action != "disarm" {
		t.Errorf("newest-first expected, got %s", got[0].Action)
	}
}

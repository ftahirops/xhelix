package enforce

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSoakPersistenceRoundTrip pins the "operator's view of N-days-clean
// must survive a daemon restart" guarantee (soak.go doc). This is the
// recurring ERRORS.md silent-failure class — a knob/state that looks
// persisted but isn't.
func TestSoakPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "soak.json")

	now := time.Now().UTC().Truncate(time.Second)
	s := NewSoak(30)
	s.Track("rule_a", now, 1)
	s.Track("rule_a", now.Add(time.Hour), 0) // class 0 must not clobber existing class
	s.MarkFP("rule_b", now)
	s.Track("rule_b", now.Add(2*time.Hour), 2)

	if err := s.SaveTo(path); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	// A fresh tracker that loads the file must see the same records.
	s2 := NewSoak(30)
	if err := s2.LoadFrom(path); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	got := map[string]Record{}
	for _, r := range s2.Snapshot() {
		got[r.RuleID] = r
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 records after reload, got %d", len(got))
	}
	if ra := got["rule_a"]; ra.Class != 1 || ra.FireCount != 2 {
		t.Errorf("rule_a survived as %+v; want Class=1 FireCount=2", ra)
	}
	if rb := got["rule_b"]; rb.Class != 2 || rb.FPCount != 1 {
		t.Errorf("rule_b survived as %+v; want Class=2 FPCount=1", rb)
	}
	// LastFP is the field that drives the clean-day clock; it must
	// round-trip through JSON intact or "30 days clean" lies after restart.
	if rb := got["rule_b"]; !rb.LastFP.Equal(now) {
		t.Errorf("rule_b.LastFP = %v after reload; want %v", rb.LastFP, now)
	}
}

func TestSoakLoadFromMissingFileIsNotError(t *testing.T) {
	s := NewSoak(30)
	if err := s.LoadFrom(filepath.Join(t.TempDir(), "does-not-exist.json")); err != nil {
		t.Errorf("missing file should not error, got %v", err)
	}
	if len(s.Snapshot()) != 0 {
		t.Error("tracker should be empty after loading a missing file")
	}
}

func TestNewSoakZeroDefaultsTo30(t *testing.T) {
	if s := NewSoak(0); s.MinCleanDays != 30 {
		t.Errorf("NewSoak(0).MinCleanDays = %d; want 30", s.MinCleanDays)
	}
	if s := NewSoak(7); s.MinCleanDays != 7 {
		t.Errorf("NewSoak(7).MinCleanDays = %d; want 7", s.MinCleanDays)
	}
}

// TestSoakClassBreakdown verifies the per-class FP-rate aggregation that
// the low-FP architecture doc requires operators to measure against
// targets (0.1% / 0.5% / 5%).
func TestSoakClassBreakdown(t *testing.T) {
	now := time.Now()
	s := NewSoak(30)
	// Class 1 rule: 1000 fires, 1 FP -> 0.1% == target boundary (within).
	s.Track("c1", now, 1)
	r1 := s.records["c1"]
	r1.FireCount = 1000
	r1.FPCount = 1
	// Class 2 rule: 100 fires, 10 FPs -> 10% >> 0.5% target (over).
	s.Track("c2", now, 2)
	r2 := s.records["c2"]
	r2.FireCount = 100
	r2.FPCount = 10

	byClass := map[int]ClassStats{}
	for _, cs := range s.ClassBreakdown() {
		byClass[cs.Class] = cs
	}

	c1 := byClass[1]
	if c1.FPRate != 0.001 || !c1.WithinTarget {
		t.Errorf("class1 = %+v; want FPRate=0.001 WithinTarget=true", c1)
	}
	c2 := byClass[2]
	if c2.FPRate != 0.1 || c2.WithinTarget {
		t.Errorf("class2 = %+v; want FPRate=0.1 WithinTarget=false", c2)
	}
	// Class 3 has no rules; FPRate must be 0 (no divide-by-zero) and
	// vacuously within target.
	c3 := byClass[3]
	if c3.TotalFires != 0 || c3.FPRate != 0 {
		t.Errorf("empty class3 = %+v; want zero fires and zero rate", c3)
	}
}

func TestSoakReclassify(t *testing.T) {
	now := time.Now()
	s := NewSoak(30)
	s.Track("rule_x", now, 0) // loaded before class_map -> class 0

	s.Reclassify(func(id string) int {
		if id == "rule_x" {
			return 2
		}
		return 0
	})
	if got := s.records["rule_x"].Class; got != 2 {
		t.Errorf("after Reclassify, class = %d; want 2", got)
	}

	// classOf returning 0 ("unknown") must leave the class unchanged.
	s.Reclassify(func(string) int { return 0 })
	if got := s.records["rule_x"].Class; got != 2 {
		t.Errorf("class clobbered by zero classOf: %d; want 2", got)
	}

	// Nil receiver / nil func must not panic.
	var nilSoak *Soak
	nilSoak.Reclassify(func(string) int { return 1 })
	s.Reclassify(nil)
}

// --- Quarantine error paths (the lifecycle happy-path is covered by
// TestQuarantineLifecycle in enforce_test.go) ---

func TestQuarantineRefusesPidZero(t *testing.T) {
	q := NewQuarantine(nil)
	if _, err := q.Stop(0, "x", "", "rule"); err != errInvalidPID {
		t.Errorf("Stop(0) err = %v; want errInvalidPID", err)
	}
}

func TestQuarantineResumeKillUnknownPid(t *testing.T) {
	q := NewQuarantine(nil)
	if err := q.Resume(4242); err != errNotQuarantined {
		t.Errorf("Resume(unknown) err = %v; want errNotQuarantined", err)
	}
	if err := q.Kill(4242); err != errNotQuarantined {
		t.Errorf("Kill(unknown) err = %v; want errNotQuarantined", err)
	}
}

// TestQuarantineStopSignalFailureLeavesNoRecord ensures a failed SIGSTOP
// does not leave a phantom "stopped" record — otherwise the TUI would
// show a process as contained when it is still running.
func TestQuarantineStopSignalFailureLeavesNoRecord(t *testing.T) {
	sendErr := errors.New("kill: no such process")
	q := NewQuarantine(func(int, os.Signal) error { return sendErr })

	_, err := q.Stop(9999, "ghost", "/bin/ghost", "rule")
	if err != sendErr {
		t.Fatalf("Stop err = %v; want %v", err, sendErr)
	}
	if len(q.Snapshot()) != 0 {
		t.Errorf("failed Stop left a record: %+v", q.Snapshot())
	}
}

func TestQuarantineNilSendIsNoop(t *testing.T) {
	q := NewQuarantine(nil)
	r, err := q.Stop(1234, "svc", "/usr/bin/svc", "rule")
	if err != nil {
		t.Fatalf("Stop with nil send: %v", err)
	}
	if r.State != "stopped" {
		t.Errorf("state = %q; want stopped", r.State)
	}
	if err := q.Resume(1234); err != nil {
		t.Errorf("Resume with nil send: %v", err)
	}
	if got := q.Snapshot(); len(got) != 1 || got[0].State != "resumed" {
		t.Errorf("snapshot = %+v; want one resumed record", got)
	}
}

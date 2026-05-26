package incidentgraph

import (
	"testing"
	"time"
)

func TestStore_UpsertAndLoad(t *testing.T) {
	s, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	inc := Incident{
		ID: "abcd1234", StartedAt: time.Now(), UpdatedAt: time.Now(),
		Severity: SeverityHigh, Confidence: 0.8, Intent: IntentC2,
		Summary: "test", SourceIDs: []uint64{42},
	}
	if err := s.Upsert(inc); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Get("abcd1234")
	if err != nil || !ok {
		t.Fatalf("Get failed: %v ok=%v", err, ok)
	}
	if got.Intent != IntentC2 || got.Severity != SeverityHigh {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
}

func TestStore_CloseMarksClosed(t *testing.T) {
	s, _ := OpenStore(":memory:")
	defer s.Close()
	inc := Incident{ID: "x", StartedAt: time.Now(), UpdatedAt: time.Now(), Severity: SeverityInfo}
	_ = s.Upsert(inc)
	ok, err := s.MarkClosed("x", "operator", time.Now())
	if err != nil || !ok {
		t.Fatalf("Close: ok=%v err=%v", ok, err)
	}
	open, _ := s.LoadOpen()
	if len(open) != 0 {
		t.Errorf("LoadOpen returned %d closed incidents", len(open))
	}
	all, _ := s.LoadAll(10)
	if len(all) != 1 {
		t.Errorf("LoadAll returned %d want 1", len(all))
	}
}

func TestPersistingEngine_WritesThrough(t *testing.T) {
	s, _ := OpenStore(":memory:")
	defer s.Close()
	pe, err := NewPersistingEngine(NewEngine(0), s)
	if err != nil {
		t.Fatal(err)
	}
	// Alert seeds; event enriches.
	pe.ObserveAlert(Alert{ID: "a", At: time.Now(), SourceID: 99, RuleID: "x", Severity: SeverityMedium})
	pe.Observe(Event{ID: "e1", At: time.Now(), SourceID: 99, Summary: "first"})
	all, _ := s.LoadAll(10)
	if len(all) != 1 {
		t.Errorf("expected 1 persisted incident, got %d", len(all))
	}
}

func TestPersistingEngine_RehydrateOnRestart(t *testing.T) {
	s, _ := OpenStore(":memory:")
	defer s.Close()
	// Pre-seed the store
	inc := Incident{
		ID: "preexisting", StartedAt: time.Now().Add(-time.Hour),
		UpdatedAt: time.Now().Add(-30 * time.Minute),
		Severity:  SeverityMedium, Intent: IntentPersistence,
		Summary:   "older", SourceIDs: []uint64{77},
	}
	_ = s.Upsert(inc)

	// New engine should pick it up
	pe, err := NewPersistingEngine(NewEngine(2*time.Hour), s)
	if err != nil {
		t.Fatal(err)
	}
	if pe.Size() != 1 {
		t.Errorf("rehydrated engine Size=%d want 1", pe.Size())
	}
}

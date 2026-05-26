package incidentgraph

import (
	"testing"
	"time"
)

func TestEngine_EventAloneDoesNotCreate(t *testing.T) {
	// Enrich-only semantics: events without a prior alert on the
	// same route must NOT create an incident.
	e := NewEngine(0)
	e.Observe(Event{ID: "e1", At: time.Now(), SourceID: 100, Summary: "lone event"})
	if got := e.Size(); got != 0 {
		t.Fatalf("event-alone created incident; Size=%d want 0", got)
	}
}

func TestEngine_AlertSeedsThenEventEnriches(t *testing.T) {
	e := NewEngine(0)
	now := time.Now()
	e.ObserveAlert(Alert{
		ID: "a1", At: now, SourceID: 42, RuleID: "beacon.detected",
		Severity: SeverityHigh, Class: 2,
	})
	if e.Size() != 1 {
		t.Fatalf("alert did not create incident; Size=%d", e.Size())
	}
	e.Observe(Event{ID: "e1", At: now.Add(time.Second), SourceID: 42, Summary: "follow-up"})
	snap := e.Snapshot()
	if len(snap[0].Evidence) != 2 {
		t.Errorf("Evidence len=%d want 2 (alert + enrich event)", len(snap[0].Evidence))
	}
}

func TestEngine_MergeBySourceID(t *testing.T) {
	e := NewEngine(0)
	now := time.Now()
	// Seed with an alert first; then two events enrich it.
	e.ObserveAlert(Alert{ID: "a", At: now, SourceID: 42, RuleID: "x", Severity: SeverityMedium})
	e.Observe(Event{ID: "e1", At: now.Add(time.Second), SourceID: 42, Summary: "first"})
	e.Observe(Event{ID: "e2", At: now.Add(2 * time.Second), SourceID: 42, Summary: "second"})
	if e.Size() != 1 {
		t.Fatalf("expected merge into one incident, got Size=%d", e.Size())
	}
	snap := e.Snapshot()
	if len(snap[0].Evidence) != 3 {
		t.Errorf("Evidence len=%d want 3 (1 alert + 2 events)", len(snap[0].Evidence))
	}
}

func TestEngine_AlertSeverityAndMitre(t *testing.T) {
	e := NewEngine(0)
	now := time.Now()
	e.ObserveAlert(Alert{
		ID: "a1", At: now, SourceID: 42, RuleID: "beacon.detected",
		Severity: SeverityHigh, Reason: "periodic beacon", Class: 2,
	})
	inc, ok := e.Snapshot()[0], true
	if !ok {
		t.Fatal("snapshot empty")
	}
	if inc.Severity != SeverityHigh {
		t.Errorf("Severity=%s want high", inc.Severity)
	}
	if len(inc.MitreIDs) == 0 || inc.MitreIDs[0] != "T1071" {
		t.Errorf("MitreIDs=%v want [T1071]", inc.MitreIDs)
	}
	if len(inc.TTPTags) == 0 || inc.TTPTags[0] != "c2_beacon" {
		t.Errorf("TTPTags=%v want [c2_beacon]", inc.TTPTags)
	}
	if inc.Intent != IntentC2 {
		t.Errorf("Intent=%s want c2", inc.Intent)
	}
	if inc.Confidence < 0.7 {
		t.Errorf("Confidence=%.2f want >=0.7 for Class 2", inc.Confidence)
	}
}

func TestEngine_IntentTheftRequiresExfilSignal(t *testing.T) {
	e := NewEngine(0)
	now := time.Now()
	// Metadata access alone is not theft — needs an egress signal too.
	e.ObserveAlert(Alert{
		ID: "a1", At: now, SourceID: 1, RuleID: "metadata.access_by_unexpected",
		Severity: SeverityMedium, Class: 2,
	})
	if got := e.Snapshot()[0].Intent; got == IntentTheft {
		t.Errorf("intent=%s; theft should NOT fire from metadata alone", got)
	}
	// Now add an egress deny — theft should classify.
	e.ObserveAlert(Alert{
		ID: "a2", At: now.Add(time.Second), SourceID: 1,
		RuleID: "egressguard.deny", Severity: SeverityHigh, Class: 2,
	})
	if got := e.Snapshot()[0].Intent; got != IntentTheft {
		t.Errorf("intent=%s want theft after metadata+egress", got)
	}
}

func TestEngine_SweepRemovesInactive(t *testing.T) {
	e := NewEngine(50 * time.Millisecond).(*memEngine)
	now := time.Now()
	e.ObserveAlert(Alert{ID: "a", At: now, SourceID: 1, RuleID: "x", Severity: SeverityMedium})
	swept := e.Sweep(now.Add(time.Second))
	if len(swept) != 1 {
		t.Errorf("Sweep returned %d want 1", len(swept))
	}
	if e.Size() != 0 {
		t.Errorf("Size after sweep=%d want 0", e.Size())
	}
}

func TestEngine_EvidenceBound(t *testing.T) {
	e := NewEngine(0)
	now := time.Now()
	e.ObserveAlert(Alert{ID: "a", At: now, SourceID: 99, RuleID: "x", Severity: SeverityMedium})
	for i := 0; i < maxEvidencePerIncident+10; i++ {
		e.Observe(Event{
			ID: "e", At: now.Add(time.Duration(i) * time.Millisecond),
			SourceID: 99, Summary: "x",
		})
	}
	snap := e.Snapshot()
	if len(snap[0].Evidence) != maxEvidencePerIncident {
		t.Errorf("Evidence len=%d want capped at %d",
			len(snap[0].Evidence), maxEvidencePerIncident)
	}
}

func TestEngine_CloseRemoves(t *testing.T) {
	e := NewEngine(0)
	e.ObserveAlert(Alert{ID: "a", At: time.Now(), SourceID: 7, RuleID: "x", Severity: SeverityMedium})
	id := e.Snapshot()[0].ID
	if !e.Close(id, "operator-test") {
		t.Fatal("Close returned false")
	}
	if e.Size() != 0 {
		t.Errorf("Size after close=%d want 0", e.Size())
	}
	if _, ok := e.Get(id); ok {
		t.Errorf("Get returned ok for closed incident")
	}
}

func TestEngine_StableIDAcrossSameMinute(t *testing.T) {
	at := time.Unix(1716700020, 0) // fixed, aligned to minute boundary
	id1 := generateIncidentID(42, 100, at)
	id2 := generateIncidentID(42, 100, at.Add(30*time.Second))
	if id1 != id2 {
		t.Errorf("ID instability within a minute: %s vs %s", id1, id2)
	}
	id3 := generateIncidentID(42, 100, at.Add(2*time.Minute))
	if id1 == id3 {
		t.Errorf("ID collision across minutes")
	}
}

func TestEngine_VerifierResultLiftsConfidence(t *testing.T) {
	e := NewEngine(0)
	now := time.Now()
	// Seed first — verifier results are also enrich-only.
	e.ObserveAlert(Alert{ID: "a", At: now, SourceID: 5, RuleID: "x", Severity: SeverityMedium})
	e.ObserveVerifierResult(
		Event{ID: "e1", At: now.Add(time.Second), SourceID: 5},
		VerifierResult{Outcome: "promote", Score: 4.5, Reason: "high"},
	)
	inc := e.Snapshot()[0]
	if inc.Confidence < 0.85 {
		t.Errorf("Confidence=%.2f want >=0.85 for promote", inc.Confidence)
	}
}

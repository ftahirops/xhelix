package actionlog

import (
	"sync"
	"testing"
	"time"
)

func TestState_DefaultObserved(t *testing.T) {
	l := New()
	if got := l.State(42); got != StateObserved {
		t.Fatalf("unknown lineage should be observed, got %q", got)
	}
}

func TestRecord_HappyPath(t *testing.T) {
	l := New()
	err := l.Record(Transition{
		LineageID: 1, To: StateTriaged,
		Reason: "score=55", PlanID: "p1",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := l.State(1); got != StateTriaged {
		t.Fatalf("after record, state=%q want %q", got, StateTriaged)
	}
	if h := l.History(1); len(h) != 1 || h[0].From != StateObserved || h[0].To != StateTriaged {
		t.Fatalf("history wrong: %+v", h)
	}
}

func TestRecord_RejectsIllegalTransition(t *testing.T) {
	l := New()
	// Cannot go from observed → released without an intermediate state.
	err := l.Record(Transition{
		LineageID: 1, To: StateReleased,
		Reason: "test", PlanID: "p1",
	})
	if err == nil {
		t.Fatal("observed → released should be illegal")
	}
}

func TestRecord_RejectsFromTerminated(t *testing.T) {
	l := New()
	// Set up terminated state first via legal path.
	_ = l.Record(Transition{LineageID: 1, To: StateSuspended, Reason: "x", PlanID: "p1"})
	_ = l.Record(Transition{LineageID: 1, To: StateTerminated, Reason: "kill", PlanID: "p2"})

	// Now anything outbound should fail.
	err := l.Record(Transition{LineageID: 1, To: StateReleased, Reason: "x", PlanID: "p3"})
	if err == nil {
		t.Fatal("terminated → released should fail (terminated is absorbing)")
	}
}

func TestRecord_RequiresReason(t *testing.T) {
	l := New()
	err := l.Record(Transition{LineageID: 1, To: StateTriaged, PlanID: "p1"})
	if err == nil {
		t.Fatal("missing reason should fail")
	}
}

func TestRecord_RequiresPlanOrOperator(t *testing.T) {
	l := New()
	err := l.Record(Transition{LineageID: 1, To: StateTriaged, Reason: "x"})
	if err == nil {
		t.Fatal("missing plan_id+operator_id should fail")
	}
}

func TestRecord_FromMismatchDetected(t *testing.T) {
	l := New()
	_ = l.Record(Transition{LineageID: 1, To: StateTriaged, Reason: "x", PlanID: "p1"})
	// Now try to record with stale From.
	err := l.Record(Transition{
		LineageID: 1, From: StateObserved, To: StateSuspended,
		Reason: "x", PlanID: "p2",
	})
	if err == nil {
		t.Fatal("From mismatch should fail (stale read)")
	}
}

func TestRecord_SelfTransitionAllowed(t *testing.T) {
	l := New()
	_ = l.Record(Transition{LineageID: 1, To: StateTriaged, Reason: "x", PlanID: "p1"})
	// Refresh: triaged → triaged.
	err := l.Record(Transition{LineageID: 1, To: StateTriaged, Reason: "refresh", PlanID: "p2"})
	if err != nil {
		t.Fatalf("self-transition (refresh) should be allowed: %v", err)
	}
	if h := l.History(1); len(h) != 2 {
		t.Fatalf("history len=%d want 2", len(h))
	}
}

func TestCanTransition_Table(t *testing.T) {
	// Spot-check the table.
	for _, c := range []struct {
		from, to ContainmentState
		want     bool
	}{
		{StateObserved, StateTriaged, true},
		{StateObserved, StateContained, true},     // skip-level for L1 crown jewel
		{StateObserved, StateRemediated, false},    // can't remediate without containment first
		{StateSuspended, StateIsolated, true},
		{StateSuspended, StateRemediated, true},
		{StateContained, StateObserved, false},
		{StateReleased, StateObserved, true},       // only outbound for released
		{StateReleased, StateSuspended, false},
		{StateTerminated, StateObserved, false},
		{StateTerminated, StateTerminated, true},   // self
	} {
		if got := CanTransition(c.from, c.to); got != c.want {
			t.Errorf("CanTransition(%q,%q) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestSnapshot_AndCountByState(t *testing.T) {
	l := New()
	_ = l.Record(Transition{LineageID: 1, To: StateTriaged, Reason: "x", PlanID: "p"})
	_ = l.Record(Transition{LineageID: 2, To: StateTriaged, Reason: "x", PlanID: "p"})
	_ = l.Record(Transition{LineageID: 3, To: StateSuspended, Reason: "x", PlanID: "p"})

	snap := l.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot len=%d want 3", len(snap))
	}
	// Sorted ascending.
	if snap[0].LineageID != 1 || snap[1].LineageID != 2 || snap[2].LineageID != 3 {
		t.Fatalf("snapshot not sorted: %+v", snap)
	}
	counts := l.CountByState()
	if counts[StateTriaged] != 2 || counts[StateSuspended] != 1 {
		t.Fatalf("counts wrong: %+v", counts)
	}

	in := l.LineagesInState(StateTriaged)
	if len(in) != 2 || in[0] != 1 || in[1] != 2 {
		t.Fatalf("LineagesInState(triaged)=%v", in)
	}
}

func TestRecord_Concurrent(t *testing.T) {
	l := New()
	var wg sync.WaitGroup
	for i := uint64(1); i <= 50; i++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			_ = l.Record(Transition{LineageID: id, To: StateTriaged, Reason: "x", PlanID: "p"})
		}(i)
	}
	wg.Wait()
	if got := len(l.Snapshot()); got != 50 {
		t.Fatalf("concurrent records: got %d lineages, want 50", got)
	}
}

func TestRecord_StampsAt(t *testing.T) {
	l := New()
	before := time.Now().UTC()
	_ = l.Record(Transition{LineageID: 1, To: StateTriaged, Reason: "x", PlanID: "p"})
	h := l.History(1)
	if h[0].At.Before(before) {
		t.Fatal("At should be stamped at record time")
	}
}

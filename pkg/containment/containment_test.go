package containment

import (
	"testing"
	"time"
)

func TestSelectStep_Bands(t *testing.T) {
	p := Policy{
		MinAlert: 1, MinThrottle: 60, MinBlockNet: 70, MinKillProc: 80,
		MinQuarantineFile: 80, MinQuarantineDir: 90, MinHostIsolate: 95,
		MinPanicSwitch: 100, MaxStep: StepPanicSwitch,
	}
	cases := []struct {
		score int
		want  Step
	}{
		{0, StepObserve}, {1, StepAlert}, {59, StepAlert},
		{60, StepThrottle}, {69, StepThrottle},
		{70, StepBlockNet}, {79, StepBlockNet},
		{80, StepQuarantineFile}, // tie with KillProc — Quarantine wins per switch order
		{90, StepQuarantineDir}, {95, StepHostIsolate}, {100, StepPanicSwitch},
	}
	for _, c := range cases {
		if got := p.SelectStep(c.score); got != c.want {
			t.Errorf("score %d → %s want %s", c.score, got, c.want)
		}
	}
}

func TestSelectStep_DefaultIsObserveOnly(t *testing.T) {
	p := DefaultPolicy()
	if p.SelectStep(100) != StepAlert {
		t.Errorf("default ceiling should clamp to Alert, got %s", p.SelectStep(100))
	}
	if p.SelectStep(0) != StepObserve {
		t.Errorf("zero score → %s want observe", p.SelectStep(0))
	}
}

func TestHandle_ObserveNoAction(t *testing.T) {
	calls := 0
	l := New(DefaultPolicy(), Actions{
		Alert: func(Verdict) error { calls++; return nil },
	}, nil)
	step, err := l.Handle(Verdict{Score: 0, SourceID: "src"})
	if err != nil || step != StepObserve {
		t.Errorf("step=%s err=%v want observe,nil", step, err)
	}
	if calls != 0 {
		t.Errorf("observe should not invoke any action, calls=%d", calls)
	}
}

func TestHandle_AlertFires(t *testing.T) {
	calls := 0
	l := New(DefaultPolicy(), Actions{
		Alert: func(Verdict) error { calls++; return nil },
	}, nil)
	step, _ := l.Handle(Verdict{Score: 50, SourceID: "src"})
	if step != StepAlert || calls != 1 {
		t.Errorf("step=%s calls=%d want alert,1", step, calls)
	}
}

func TestHandle_SuppressionOnRepeat(t *testing.T) {
	calls := 0
	l := New(DefaultPolicy(), Actions{
		Alert: func(Verdict) error { calls++; return nil },
	}, nil)
	now := time.Now()
	_, _ = l.Handle(Verdict{Score: 50, SourceID: "src", At: now})
	_, _ = l.Handle(Verdict{Score: 50, SourceID: "src", At: now.Add(time.Minute)})
	if calls != 1 {
		t.Errorf("repeat within cooldown should suppress; calls=%d want 1", calls)
	}
	// After cooldown, should fire again.
	_, _ = l.Handle(Verdict{Score: 50, SourceID: "src", At: now.Add(6 * time.Minute)})
	if calls != 2 {
		t.Errorf("post-cooldown should re-fire; calls=%d want 2", calls)
	}
}

func TestHandle_EscalationBypassesSuppression(t *testing.T) {
	policy := DefaultPolicy()
	policy.MaxStep = StepKillProc
	killCalls := 0
	alertCalls := 0
	l := New(policy, Actions{
		Alert:    func(Verdict) error { alertCalls++; return nil },
		KillProc: func(Verdict) error { killCalls++; return nil },
	}, nil)
	now := time.Now()
	_, _ = l.Handle(Verdict{Score: 50, SourceID: "src", At: now})
	// Escalate to KillProc within cooldown — must still fire.
	_, _ = l.Handle(Verdict{Score: 85, SourceID: "src", PID: 1234, At: now.Add(30 * time.Second)})
	if killCalls != 1 {
		t.Errorf("escalation must bypass suppression; killCalls=%d want 1", killCalls)
	}
	if alertCalls != 1 {
		t.Errorf("initial alert should still have fired once; got %d", alertCalls)
	}
}

func TestHandle_MissingExecutorIsSafe(t *testing.T) {
	policy := DefaultPolicy()
	policy.MaxStep = StepKillProc
	l := New(policy, Actions{}, nil) // no executors at all
	step, err := l.Handle(Verdict{Score: 90, SourceID: "src", PID: 1234})
	if err != nil {
		t.Errorf("missing executor must not error; got %v", err)
	}
	if step != StepKillProc {
		t.Errorf("step=%s want kill_proc (decision should still report)", step)
	}
}

func TestParseStep_RoundTrip(t *testing.T) {
	for s := StepObserve; s <= StepPanicSwitch; s++ {
		got, ok := ParseStep(s.String())
		if !ok || got != s {
			t.Errorf("ParseStep(%q)=%s,%v want %s,true", s.String(), got, ok, s)
		}
	}
	if _, ok := ParseStep("notreal"); ok {
		t.Errorf("unknown step should return false")
	}
}

func TestNilLadder(t *testing.T) {
	var l *Ladder
	step, err := l.Handle(Verdict{Score: 100})
	if step != StepObserve || err != nil {
		t.Errorf("nil ladder Handle=%s,%v want observe,nil", step, err)
	}
	l.SetPolicy(DefaultPolicy())                  // must not panic
	if got := l.Policy(); got.MaxStep != 0 {
		t.Errorf("nil ladder Policy=%+v want zero", got)
	}
}

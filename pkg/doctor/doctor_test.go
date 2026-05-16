package doctor

import (
	"context"
	"errors"
	"testing"
)

func mkCheck(id string, sev Severity, status Status) Check {
	return Check{
		ID:       id,
		Title:    id,
		Category: "test",
		Severity: sev,
		Run:      func(_ context.Context) Result { return Result{Status: status} },
	}
}

func TestScoreAllPass(t *testing.T) {
	r := NewRunner([]Check{
		mkCheck("a", SeverityCritical, Pass),
		mkCheck("b", SeverityHigh, Pass),
	})
	rep := r.Run(context.Background())
	if rep.Score.Composite != 100 {
		t.Errorf("score = %d, want 100", rep.Score.Composite)
	}
	if rep.Score.Failed != 0 || rep.Score.Passed != 2 {
		t.Errorf("counts wrong: %+v", rep.Score)
	}
}

func TestScoreCriticalFailDominates(t *testing.T) {
	r := NewRunner([]Check{
		mkCheck("a", SeverityCritical, Fail),
		mkCheck("b", SeverityLow, Pass),
	})
	rep := r.Run(context.Background())
	// crit fail (weight 16) + low pass (weight 2) → earned 2 of 18.
	want := 2 * 100 / 18
	if rep.Score.Composite != want {
		t.Errorf("score = %d, want %d", rep.Score.Composite, want)
	}
}

func TestScoreSkipDoesNotPenalise(t *testing.T) {
	r := NewRunner([]Check{
		mkCheck("a", SeverityCritical, Pass),
		mkCheck("b", SeverityCritical, Skip),
	})
	rep := r.Run(context.Background())
	if rep.Score.Composite != 100 {
		t.Errorf("skip should not penalise; got %d", rep.Score.Composite)
	}
}

func TestPanicCaughtAsError(t *testing.T) {
	r := NewRunner([]Check{{
		ID:       "boom",
		Severity: SeverityCritical,
		Run:      func(_ context.Context) Result { panic("nope") },
	}})
	rep := r.Run(context.Background())
	if rep.Findings[0].Result.Status != Errored {
		t.Errorf("status = %v", rep.Findings[0].Result.Status)
	}
}

func TestFilter(t *testing.T) {
	r := NewRunner([]Check{
		{ID: "kernel.a", Category: "kernel", Severity: SeverityHigh, Run: func(_ context.Context) Result { return Pass.r() }},
		{ID: "ssh.b", Category: "ssh", Severity: SeverityHigh, Run: func(_ context.Context) Result { return Pass.r() }},
	})
	if got := len(r.Filter("kernel", "").Checks); got != 1 {
		t.Errorf("category filter: got %d", got)
	}
	if got := len(r.Filter("", "ssh").Checks); got != 1 {
		t.Errorf("id filter: got %d", got)
	}
}

func TestErrorResult(t *testing.T) {
	res := ErrorResult(errors.New("boom"))
	if res.Status != Errored {
		t.Error("status")
	}
}

// helper for the filter test
func (s Status) r() Result { return Result{Status: s} }

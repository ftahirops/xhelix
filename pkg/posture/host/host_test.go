package host

import "testing"

func TestInspectProducesChecks(t *testing.T) {
	r := Inspect()
	if len(r.Checks) == 0 {
		t.Fatal("Inspect returned no checks")
	}
	// Every check has a Name.
	for _, c := range r.Checks {
		if c.Name == "" {
			t.Errorf("check with empty name: %+v", c)
		}
	}
}

func TestScoreBounds(t *testing.T) {
	r := Inspect()
	s := r.Score()
	if s < 0 || s > 100 {
		t.Errorf("score out of bounds: %d", s)
	}
}

func TestFormatTextNonEmpty(t *testing.T) {
	r := Inspect()
	out := r.FormatText()
	if len(out) == 0 {
		t.Error("FormatText empty")
	}
}

func TestCountsSum(t *testing.T) {
	r := Inspect()
	p, w, f, u := r.Counts()
	if p+w+f+u != len(r.Checks) {
		t.Errorf("counts %d+%d+%d+%d != %d", p, w, f, u, len(r.Checks))
	}
}

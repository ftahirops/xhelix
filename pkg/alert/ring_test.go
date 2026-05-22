package alert

import (
	"context"
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestRingSinkEviction(t *testing.T) {
	r := NewRingSink(3)
	for i := 0; i < 5; i++ {
		_ = r.Send(context.Background(), model.Alert{RuleID: string(rune('a' + i))})
	}
	snap := r.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("want 3 (cap), got %d", len(snap))
	}
	// Oldest two should have been evicted; expect c,d,e.
	if snap[0].RuleID != "c" || snap[1].RuleID != "d" || snap[2].RuleID != "e" {
		t.Errorf("oldest-evict wrong: %+v", snap)
	}
}

func TestRingSinkCountAndCopy(t *testing.T) {
	r := NewRingSink(0) // default
	_ = r.Send(context.Background(), model.Alert{RuleID: "x"})
	if r.Count() != 1 {
		t.Errorf("count=%d want 1", r.Count())
	}
	s1 := r.Snapshot()
	s1[0].RuleID = "MUTATED"
	if r.Snapshot()[0].RuleID != "x" {
		t.Errorf("Snapshot returned shared reference")
	}
}

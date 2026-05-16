package rules

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestEngineSimpleMatch(t *testing.T) {
	var fires atomic.Uint64
	var captured atomic.Pointer[model.Alert]

	eng, err := NewEngine(func(a model.Alert) {
		fires.Add(1)
		c := a
		captured.Store(&c)
	})
	if err != nil {
		t.Fatal(err)
	}

	rules := []model.Rule{
		{
			ID:          "test_match",
			Desc:        "match anything from heartbeat sensor",
			SeverityRaw: "warn",
			Match:       `event.sensor == "heartbeat"`,
		},
		{
			ID:          "test_nomatch",
			SeverityRaw: "info",
			Match:       `event.sensor == "ebpf.proc"`,
		},
	}
	for i := range rules {
		if err := rules[i].Normalize(); err != nil {
			t.Fatalf("normalize: %v", err)
		}
	}
	if err := eng.Load(rules); err != nil {
		t.Fatalf("load: %v", err)
	}
	if eng.Count() != 2 {
		t.Errorf("loaded %d, want 2", eng.Count())
	}

	ev := model.NewEvent("heartbeat", model.SeverityInfo)
	ev.Comm = "xhelix"
	eng.Eval(context.Background(), ev)

	if got := fires.Load(); got != 1 {
		t.Errorf("fired %d, want 1", got)
	}
	if a := captured.Load(); a == nil || a.RuleID != "test_match" {
		t.Errorf("rule id = %v, want test_match", a)
	}
}

func TestEngineRateLimit(t *testing.T) {
	var fires atomic.Uint64
	eng, err := NewEngine(func(a model.Alert) { fires.Add(1) })
	if err != nil {
		t.Fatal(err)
	}

	r := model.Rule{
		ID:          "rl",
		SeverityRaw: "warn",
		Match:       `event.sensor == "test"`,
		RateLimit: &model.RuleRateLimit{
			PerMinute: 2,
			PerKey:    "rule",
		},
	}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := eng.Load([]model.Rule{r}); err != nil {
		t.Fatal(err)
	}

	ev := model.NewEvent("test", model.SeverityInfo)
	for i := 0; i < 5; i++ {
		eng.Eval(context.Background(), ev)
	}
	if got := fires.Load(); got != 2 {
		t.Errorf("fires = %d, want 2 (rate-limited)", got)
	}
}

func TestEngineLoadInvalidRule(t *testing.T) {
	eng, _ := NewEngine(func(model.Alert) {})

	r := model.Rule{
		ID:          "bad",
		SeverityRaw: "warn",
		Match:       "this isn't valid CEL syntax @@@",
	}
	_ = r.Normalize()
	err := eng.Load([]model.Rule{r})
	if err == nil {
		t.Fatal("expected compile error on invalid CEL")
	}
}

func TestLimiterStopIsIdempotent(t *testing.T) {
	l := NewLimiter()
	l.Stop()
	l.Stop() // must not panic
}

func TestEngineTagsAndTreeAccessible(t *testing.T) {
	var fires atomic.Uint64
	eng, _ := NewEngine(func(model.Alert) { fires.Add(1) })

	r := model.Rule{
		ID:          "tags_tree",
		SeverityRaw: "high",
		Match: `event.tags["foo"] == "bar" &&` +
			` size(tree) > 0 && tree[0].comm == "shell"`,
	}
	_ = r.Normalize()
	if err := eng.Load([]model.Rule{r}); err != nil {
		t.Fatal(err)
	}

	ev := model.NewEvent("ebpf.proc", model.SeverityHigh)
	ev.Tags["foo"] = "bar"
	ev.ProcTree = []model.ProcNode{{PID: 1234, Comm: "shell"}}
	eng.Eval(context.Background(), ev)
	time.Sleep(10 * time.Millisecond)

	if got := fires.Load(); got != 1 {
		t.Errorf("fires = %d, want 1", got)
	}
}

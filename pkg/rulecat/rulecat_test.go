package rulecat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestResolver_DefaultsToWeakSignal(t *testing.T) {
	r := NewResolver()
	if got := r.Category("never.seen"); got != model.CategoryWeakSignal {
		t.Fatalf("unknown rule must default to weak_signal, got %v", got)
	}
}

func TestResolver_AddRules(t *testing.T) {
	rules := []model.Rule{
		{ID: "hard1", CategoryRaw: "hard_deny", Category: model.CategoryHardDeny},
		{ID: "fact1", CategoryRaw: "fact", Category: model.CategoryFact},
		{ID: "unclassified", CategoryRaw: ""}, // skipped → defaults
	}
	r := NewResolver()
	r.AddRules(rules)
	if r.Category("hard1") != model.CategoryHardDeny {
		t.Fatal("hard1")
	}
	if r.Category("fact1") != model.CategoryFact {
		t.Fatal("fact1")
	}
	if r.Category("unclassified") != model.CategoryWeakSignal {
		t.Fatal("unclassified must default to weak_signal")
	}
}

func TestResolver_AddRuntimeFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rt.yaml")
	body := "categories:\n  brp.hard_deny: hard_deny\n  cap.gained: fact\n  lolbin.suspicious: weak_signal\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewResolver()
	if err := r.AddRuntimeFile(p); err != nil {
		t.Fatalf("load: %v", err)
	}
	if r.Category("brp.hard_deny") != model.CategoryHardDeny {
		t.Fatal("brp.hard_deny must be hard_deny")
	}
	if r.Category("cap.gained") != model.CategoryFact {
		t.Fatal("cap.gained must be fact")
	}
}

func TestResolver_AddRuntimeFile_MissingIsOK(t *testing.T) {
	r := NewResolver()
	if err := r.AddRuntimeFile("/nonexistent/path.yaml"); err != nil {
		t.Fatalf("missing file must not error, got %v", err)
	}
}

func TestResolver_AddRuntimeFile_RejectsBadCategory(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rt.yaml")
	if err := os.WriteFile(p, []byte("categories:\n  x: bogus\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewResolver()
	if err := r.AddRuntimeFile(p); err == nil {
		t.Fatal("invalid category must error")
	}
}

func TestShouldEmit(t *testing.T) {
	cases := []struct {
		cat  model.Category
		mode string
		want bool
	}{
		{model.CategoryFact, "visibility", false},
		{model.CategoryWeakSignal, "visibility", false},
		{model.CategoryIncident, "visibility", true},
		{model.CategoryHardDeny, "visibility", true},
		{model.CategoryFact, "detection", true},
		{model.CategoryWeakSignal, "detection", true},
		{model.CategoryIncident, "detection", true},
		{model.CategoryHardDeny, "detection", true},
		{model.CategoryFact, "", false}, // unknown mode fails safe to visibility
	}
	for _, c := range cases {
		if got := ShouldEmit(c.cat, c.mode); got != c.want {
			t.Errorf("ShouldEmit(%v,%q)=%v want %v", c.cat, c.mode, got, c.want)
		}
	}
}

func TestResolver_Gate(t *testing.T) {
	r := NewResolver()
	r.AddRules([]model.Rule{{ID: "f", CategoryRaw: "fact", Category: model.CategoryFact}})
	gate := r.Gate("visibility")
	if gate(model.Alert{RuleID: "f"}) {
		t.Fatal("fact must be suppressed in visibility")
	}
	if gate(model.Alert{RuleID: "unknown.but.treated.as.weak"}) {
		t.Fatal("unknown rule_id is weak_signal → suppressed in visibility")
	}
	// In detection mode everything passes.
	g2 := r.Gate("detection")
	if !g2(model.Alert{RuleID: "f"}) {
		t.Fatal("detection mode must emit fact")
	}
}

func TestResolver_Known(t *testing.T) {
	r := NewResolver()
	r.AddRules([]model.Rule{{ID: "f", CategoryRaw: "fact", Category: model.CategoryFact}})
	if !r.Known("f") {
		t.Fatal("explicitly classified rule must be Known")
	}
	if r.Known("never.added") {
		t.Fatal("unclassified rule must not be Known (it falls back to weak_signal default)")
	}
}

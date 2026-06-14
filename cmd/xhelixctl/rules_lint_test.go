package main

import (
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestLintRequiresCategory(t *testing.T) {
	r := model.Rule{ID: "test_rule", Match: "true"}
	if err := r.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	errs := lintCategoryViolations([]model.Rule{r})
	if len(errs) != 1 {
		t.Fatalf("want 1 violation for unclassified rule, got %d", len(errs))
	}
	if !strings.Contains(errs[0], "test_rule") || !strings.Contains(errs[0], "category") {
		t.Fatalf("violation message should name the rule and field: %q", errs[0])
	}
}

func TestLintAcceptsAllCategories(t *testing.T) {
	for _, c := range []string{"fact", "weak_signal", "incident", "hard_deny"} {
		r := model.Rule{ID: "test_" + c, Match: "true", CategoryRaw: c}
		if err := r.Normalize(); err != nil {
			t.Fatalf("normalize %s: %v", c, err)
		}
		errs := lintCategoryViolations([]model.Rule{r})
		if len(errs) != 0 {
			t.Fatalf("category %s should pass lint, got: %v", c, errs)
		}
	}
}

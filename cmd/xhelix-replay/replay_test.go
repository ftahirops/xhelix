package main

import (
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/rulecat"
)

func testResolver() *rulecat.Resolver {
	r := rulecat.NewResolver()
	r.AddRules([]model.Rule{
		{ID: "cap.gained", CategoryRaw: "fact", Category: model.CategoryFact},
		{ID: "tls_no_sni", CategoryRaw: "fact", Category: model.CategoryFact},
		{ID: "memfd_run_pattern", CategoryRaw: "weak_signal", Category: model.CategoryWeakSignal},
		{ID: "shell_with_socket_fd", CategoryRaw: "incident", Category: model.CategoryIncident},
		{ID: "brp.hard_deny", CategoryRaw: "hard_deny", Category: model.CategoryHardDeny},
		{ID: "rc_local_modified", CategoryRaw: "hard_deny", Category: model.CategoryHardDeny},
		{ID: "messaging_platform_egress", CategoryRaw: "weak_signal", Category: model.CategoryWeakSignal},
		{ID: "fim.drift", CategoryRaw: "weak_signal", Category: model.CategoryWeakSignal},
	})
	return r
}

func TestReplay_Visibility_SuppressesFactsAndWeak(t *testing.T) {
	res, err := ReplayFile("testdata/sample_alerts.jsonl", ReplayOpts{
		AlertMode: "visibility", Resolver: testResolver(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalLines != 10 {
		t.Fatalf("lines: got %d want 10", res.TotalLines)
	}
	// fact: cap.gained x2 + tls_no_sni x2 = 4
	// weak: memfd x1 + messaging x1 + fim.drift x1 = 3
	// incident: shell_with_socket_fd x1 = 1 (emit)
	// hard_deny: brp.hard_deny x1 + rc_local_modified x1 = 2 (emit)
	if res.Emitted != 3 {
		t.Fatalf("emitted: got %d want 3", res.Emitted)
	}
	if res.Suppressed != 7 {
		t.Fatalf("suppressed: got %d want 7", res.Suppressed)
	}
	if res.SuppressedByCategory["fact"] != 4 {
		t.Fatalf("fact suppressed: got %d want 4", res.SuppressedByCategory["fact"])
	}
	if res.SuppressedByCategory["weak_signal"] != 3 {
		t.Fatalf("weak suppressed: got %d want 3", res.SuppressedByCategory["weak_signal"])
	}
}

func TestReplay_Detection_EmitsAll(t *testing.T) {
	res, err := ReplayFile("testdata/sample_alerts.jsonl", ReplayOpts{
		AlertMode: "detection", Resolver: testResolver(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Emitted != 10 {
		t.Fatalf("detection emits all: got %d want 10", res.Emitted)
	}
}

func TestReplay_UnknownRuleDefaultsWeakAndCounted(t *testing.T) {
	// Empty resolver: every rule unknown → weak_signal → suppressed in visibility.
	res, err := ReplayFile("testdata/sample_alerts.jsonl", ReplayOpts{
		AlertMode: "visibility", Resolver: rulecat.NewResolver(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Emitted != 0 {
		t.Fatalf("all unknown → all suppressed: got %d emitted want 0", res.Emitted)
	}
	if res.Unclassified["cap.gained"] != 2 {
		t.Fatalf("unclassified cap.gained: got %d want 2", res.Unclassified["cap.gained"])
	}
}

func TestReplay_TPRegressionDetected(t *testing.T) {
	// brp.hard_deny mis-classified as fact → suppressed → must flag.
	r := rulecat.NewResolver()
	r.AddRules([]model.Rule{{ID: "brp.hard_deny", CategoryRaw: "fact", Category: model.CategoryFact}})
	res, err := ReplayFile("testdata/sample_alerts.jsonl", ReplayOpts{
		AlertMode: "visibility", Resolver: r,
		TruePositiveIDs: map[string]bool{"brp.hard_deny": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TPRegressions) == 0 || !strings.Contains(strings.Join(res.TPRegressions, ""), "brp.hard_deny") {
		t.Fatalf("expected TP regression for brp.hard_deny, got %v", res.TPRegressions)
	}
}

package forensic

import (
	"testing"
	"time"
)

func TestCoEngine_DownloadAndExecute_Fires(t *testing.T) {
	e := NewCoEngine(DefaultCoRules())
	t0 := time.Unix(1700000000, 0).UTC()

	if hits := e.Observe(Observation{
		Kind: KindURL, Value: "http://attacker.io/payload",
		At: t0, Source: "sess1",
	}); len(hits) != 0 {
		t.Fatalf("single URL should not fire: %+v", hits)
	}

	hits := e.Observe(Observation{
		Kind: KindCommand, Value: "curl",
		At: t0.Add(2 * time.Second), Source: "sess1",
	})
	if len(hits) == 0 {
		t.Fatal("URL + Command should fire download_and_execute")
	}
	found := false
	for _, h := range hits {
		if h.RuleID == "cooccur.download_and_execute" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected cooccur.download_and_execute fire, got %+v", hits)
	}
}

func TestCoEngine_ReverseShell(t *testing.T) {
	// P-RF.9g H1: rule rewritten to require KindBeaconHost
	// (sinkhole-captured, not text-extracted). Just an IP in
	// honey-sh output no longer fires it.
	e := NewCoEngine(DefaultCoRules())
	t0 := time.Unix(1700000000, 0).UTC()
	e.Observe(Observation{Kind: KindBeaconHost, Value: "evil.c2.example.com", At: t0, Source: "s1"})
	hits := e.Observe(Observation{Kind: KindCommand, Value: "/bin/sh", At: t0, Source: "s1"})

	found := false
	for _, h := range hits {
		if h.RuleID == "cooccur.reverse_shell" {
			found = true
			if len(h.Contributors) != 2 {
				t.Errorf("expected 2 contributors, got %d", len(h.Contributors))
			}
		}
	}
	if !found {
		t.Fatalf("reverse_shell didn't fire: %+v", hits)
	}
}

func TestCoEngine_ReverseShell_DoesNotFireOnRandomIP(t *testing.T) {
	// Verify the P-RF.9g H1 fix: text-extracted KindIPv4 +
	// KindCommand should NOT trigger reverse_shell anymore.
	e := NewCoEngine(DefaultCoRules())
	t0 := time.Unix(1700000000, 0).UTC()
	e.Observe(Observation{Kind: KindIPv4, Value: "8.8.4.4", At: t0, Source: "s1"})
	hits := e.Observe(Observation{Kind: KindCommand, Value: "ping", At: t0, Source: "s1"})
	for _, h := range hits {
		if h.RuleID == "cooccur.reverse_shell" {
			t.Fatalf("reverse_shell should NOT fire on text-extracted IP + command")
		}
	}
}

func TestCoEngine_WindowExpiry(t *testing.T) {
	e := NewCoEngine(DefaultCoRules())
	t0 := time.Unix(1700000000, 0).UTC()

	e.Observe(Observation{Kind: KindURL, Value: "http://x/y", At: t0, Source: "s1"})
	// Now far past download_and_execute's 5 min window.
	hits := e.Observe(Observation{
		Kind: KindCommand, Value: "curl",
		At: t0.Add(10 * time.Minute), Source: "s1",
	})
	for _, h := range hits {
		if h.RuleID == "cooccur.download_and_execute" {
			t.Fatal("rule should NOT fire — observations too far apart")
		}
	}
}

func TestCoEngine_DifferentSourcesDoNotMerge(t *testing.T) {
	e := NewCoEngine(DefaultCoRules())
	t0 := time.Unix(1700000000, 0).UTC()
	e.Observe(Observation{Kind: KindURL, Value: "http://x/y", At: t0, Source: "A"})
	hits := e.Observe(Observation{
		Kind: KindCommand, Value: "curl",
		At: t0, Source: "B", // different source!
	})
	for _, h := range hits {
		if h.RuleID == "cooccur.download_and_execute" {
			t.Fatal("rule must NOT fire across distinct sources")
		}
	}
}

func TestCoEngine_AllDefaultRulesReachable(t *testing.T) {
	rules := DefaultCoRules()
	if len(rules) < 5 {
		t.Fatalf("expected ≥5 default rules, got %d", len(rules))
	}
	// Smoke test: every rule fires when its Need set is satisfied.
	for _, r := range rules {
		e := NewCoEngine([]CoRule{r})
		t0 := time.Unix(1700000000, 0).UTC()
		for _, k := range r.Need {
			e.Observe(Observation{
				Kind: k, Value: "x-" + string(k),
				At: t0, Source: "test",
			})
		}
		// Last Observe should have triggered the rule.
		// (We re-feed the last one to capture the return value.)
		last := r.Need[len(r.Need)-1]
		hits := e.Observe(Observation{
			Kind: last, Value: "x-" + string(last),
			At: t0, Source: "test",
		})
		found := false
		for _, h := range hits {
			if h.RuleID == r.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("rule %q never fired despite satisfied Need: %v", r.ID, r.Need)
		}
	}
}

func TestCoEngine_Forget(t *testing.T) {
	e := NewCoEngine(DefaultCoRules())
	t0 := time.Unix(1700000000, 0).UTC()
	e.Observe(Observation{Kind: KindURL, Value: "u", At: t0, Source: "s1"})
	e.Forget("s1")
	hits := e.Observe(Observation{Kind: KindCommand, Value: "c", At: t0, Source: "s1"})
	for _, h := range hits {
		if h.RuleID == "cooccur.download_and_execute" {
			t.Fatal("after Forget, prior URL should not contribute")
		}
	}
}

func TestCoEngine_SourcesListed(t *testing.T) {
	e := NewCoEngine(DefaultCoRules())
	e.Observe(Observation{Kind: KindURL, Value: "u", Source: "s1"})
	e.Observe(Observation{Kind: KindURL, Value: "u", Source: "s2"})
	e.Observe(Observation{Kind: KindURL, Value: "u", Source: "s0"})
	got := e.Sources()
	if len(got) != 3 || got[0] != "s0" || got[1] != "s1" || got[2] != "s2" {
		t.Fatalf("Sources not sorted/all-present: %v", got)
	}
}

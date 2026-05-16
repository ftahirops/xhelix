package explain

import (
	"strings"
	"testing"
)

func TestRegisterAndRender(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Rule{
		ID: "test.basic", Title: "Basic Title",
		Body: "Process {{.Comm}} hit {{.DstIP}}", Severity: SeverityWarn,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := r.Render("test.basic", Context{Comm: "curl", DstIP: "1.2.3.4"})
	if got.Body != "Process curl hit 1.2.3.4" {
		t.Fatalf("body = %q", got.Body)
	}
	if got.Severity != SeverityWarn {
		t.Errorf("severity = %s", got.Severity)
	}
}

func TestUnknownRuleFallback(t *testing.T) {
	r := NewRegistry()
	got := r.Render("nonexistent.rule", Context{})
	if got.Title == "" {
		t.Fatal("fallback should produce a title")
	}
	if !strings.Contains(got.Body, "No explanation") {
		t.Errorf("fallback body = %q", got.Body)
	}
}

func TestRegisterEmptyIDFails(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(Rule{ID: "", Body: "x"}); err == nil {
		t.Fatal("empty ID should error")
	}
}

func TestRegisterBadTemplateFails(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Rule{ID: "broken", Body: "{{.Unclosed"})
	if err == nil {
		t.Fatal("malformed template should error")
	}
}

func TestRenderHandlesMissingFieldsGracefully(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(Rule{
		ID: "miss", Body: "comm={{.Comm}} country={{.Country}}",
	})
	got := r.Render("miss", Context{Comm: "x"})
	if got.Body != "comm=x country=" {
		t.Fatalf("got %q", got.Body)
	}
}

func TestIDsSortedAndLen(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(Rule{ID: "b", Body: "x"})
	_ = r.Register(Rule{ID: "a", Body: "x"})
	_ = r.Register(Rule{ID: "c", Body: "x"})
	ids := r.IDs()
	if len(ids) != 3 || ids[0] != "a" || ids[2] != "c" {
		t.Fatalf("ids = %v", ids)
	}
	if r.Len() != 3 {
		t.Fatalf("len = %d", r.Len())
	}
}

func TestMustRegisterPanicsOnBad(t *testing.T) {
	r := NewRegistry()
	defer func() {
		if recover() == nil {
			t.Fatal("MustRegister with bad template should panic")
		}
	}()
	r.MustRegister(Rule{ID: "x", Body: "{{.Unclosed"})
}

func TestDefaultRegistryPopulated(t *testing.T) {
	r := DefaultRegistry()
	if r.Len() < 10 {
		t.Fatalf("default registry too small: %d", r.Len())
	}
	// Spot-check a couple of well-known rule IDs
	for _, id := range []string{"beacon.periodic_callback", "intel.bad_ip", "revshell.detected"} {
		got := r.Render(id, Context{Comm: "test", DstIP: "1.2.3.4"})
		if got.Title == "" || got.Body == "" {
			t.Errorf("default rule %s renders empty: %+v", id, got)
		}
	}
}

func TestDefaultRulesAttackPhaseSet(t *testing.T) {
	r := DefaultRegistry()
	missing := 0
	for _, id := range r.IDs() {
		got := r.Render(id, Context{})
		if got.AttackPhase == "" {
			missing++
		}
	}
	if missing > 0 {
		t.Errorf("%d bundled rules missing AttackPhase", missing)
	}
}

func TestDefaultRulesMitigationSet(t *testing.T) {
	r := DefaultRegistry()
	missing := 0
	for _, id := range r.IDs() {
		got := r.Render(id, Context{})
		if got.Mitigation == "" {
			missing++
		}
	}
	if missing > 0 {
		t.Errorf("%d bundled rules missing Mitigation", missing)
	}
}

func TestSeverityString(t *testing.T) {
	cases := []struct {
		s    Severity
		want string
	}{
		{SeverityInfo, "info"}, {SeverityNotice, "notice"},
		{SeverityWarn, "warn"}, {SeverityHigh, "high"},
		{SeverityCritical, "critical"}, {Severity(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("Severity(%d) = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestRenderUsesContextFields(t *testing.T) {
	r := DefaultRegistry()
	got := r.Render("phishing.brand_lookalike", Context{
		QName: "paypa1.com", Reason: "edit-distance 1 from paypal",
	})
	if !strings.Contains(got.Body, "paypa1.com") {
		t.Fatalf("body missing qname: %q", got.Body)
	}
	if !strings.Contains(got.Body, "edit-distance 1 from paypal") {
		t.Fatalf("body missing reason: %q", got.Body)
	}
}

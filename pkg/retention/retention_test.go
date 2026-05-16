package retention

import (
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/store/history"
)

func TestDefaultPolicyMatchesHistoryDefaults(t *testing.T) {
	c := New(Policy{})
	r := c.AsHistoryRetention()
	d := history.DefaultRetention()
	if r != d {
		t.Fatalf("zero policy should fill defaults: got %+v want %+v", r, d)
	}
}

func TestPartialPolicyFillsRest(t *testing.T) {
	c := New(Policy{Flows: time.Hour})
	r := c.AsHistoryRetention()
	if r.Flows != time.Hour {
		t.Errorf("Flows = %v", r.Flows)
	}
	d := history.DefaultRetention()
	if r.DNS != d.DNS || r.Activities != d.Activities {
		t.Errorf("unspecified fields not defaulted: %+v", r)
	}
}

func TestSetReplaces(t *testing.T) {
	c := New(Policy{})
	c.Set(Policy{Anon: AnonRedact})
	if c.Get().Anon != AnonRedact {
		t.Fatal("Set did not stick")
	}
}

func TestAnonOffPassThrough(t *testing.T) {
	c := New(Policy{Anon: AnonOff})
	if c.SanitiseQName("example.com") != "example.com" {
		t.Fatal("AnonOff should pass through")
	}
}

func TestAnonRedactReturnsEmpty(t *testing.T) {
	c := New(Policy{Anon: AnonRedact})
	if c.SanitiseQName("example.com") != "" {
		t.Fatal("AnonRedact must return empty")
	}
}

func TestAnonHashDeterministic(t *testing.T) {
	c := New(Policy{Anon: AnonHash, AnonSalt: "test"})
	a := c.SanitiseQName("example.com")
	b := c.SanitiseQName("example.com")
	if a != b {
		t.Fatal("AnonHash must be deterministic")
	}
	if len(a) != 32 {
		t.Fatalf("hash length = %d, want 32", len(a))
	}
}

func TestAnonHashDifferentDomainsDifferentHashes(t *testing.T) {
	c := New(Policy{Anon: AnonHash})
	a := c.SanitiseQName("example.com")
	b := c.SanitiseQName("other.example")
	if a == b {
		t.Fatal("different inputs should hash differently")
	}
}

func TestAnonHashCaseAndTrailingDotNormalised(t *testing.T) {
	c := New(Policy{Anon: AnonHash})
	a := c.SanitiseQName("Example.COM.")
	b := c.SanitiseQName("example.com")
	if a != b {
		t.Fatal("case/trailing-dot variants should hash the same")
	}
}

func TestAnonHashEmptyInputEmptyOutput(t *testing.T) {
	c := New(Policy{Anon: AnonHash})
	if c.SanitiseQName("") != "" {
		t.Fatal("empty input → empty output")
	}
}

func TestSanitiseAnswersPreservesIPs(t *testing.T) {
	c := New(Policy{Anon: AnonRedact})
	got := c.SanitiseAnswers([]string{"1.2.3.4", "example.com", "fe80::1"})
	if got[0] != "1.2.3.4" || got[1] != "" || got[2] != "fe80::1" {
		t.Fatalf("answers = %v", got)
	}
}

func TestSanitiseAnswersOffMode(t *testing.T) {
	c := New(Policy{})
	in := []string{"1.2.3.4", "example.com"}
	got := c.SanitiseAnswers(in)
	if got[0] != in[0] || got[1] != in[1] {
		t.Fatalf("AnonOff should pass through")
	}
}

func TestIsAnonymous(t *testing.T) {
	if New(Policy{}).IsAnonymous() {
		t.Fatal("default not anonymous")
	}
	if !New(Policy{Anon: AnonHash}).IsAnonymous() {
		t.Fatal("hash is anonymous")
	}
	if !New(Policy{Anon: AnonRedact}).IsAnonymous() {
		t.Fatal("redact is anonymous")
	}
}

func TestLooksLikeIP(t *testing.T) {
	cases := map[string]bool{
		"1.2.3.4":      true,
		"127.0.0.1":    true,
		"fe80::1":      true,
		"::1":          true,
		"example.com":  false,
		"abc.def.ghi":  false,
		"":             false,
		"1.2.3.4.5":    true, // dotted-quad over-length is best-effort
	}
	for in, want := range cases {
		if got := looksLikeIP(in); got != want {
			t.Errorf("looksLikeIP(%q) = %v, want %v", in, got, want)
		}
	}
}

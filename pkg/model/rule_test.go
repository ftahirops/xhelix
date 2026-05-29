package model

import "testing"

func TestRule_NormalizeCategory_FromYAML(t *testing.T) {
	cases := []struct {
		raw  string
		want Category
		ok   bool
	}{
		{"", CategoryWeakSignal, true}, // default — force explicit until reclassified
		{"fact", CategoryFact, true},
		{"weak_signal", CategoryWeakSignal, true},
		{"incident", CategoryIncident, true},
		{"hard_deny", CategoryHardDeny, true},
		{"FACT", CategoryFact, true},        // case-insensitive
		{"junk", CategoryWeakSignal, false}, // invalid → default + error
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			r := Rule{CategoryRaw: c.raw}
			err := r.NormalizeCategory()
			if (err == nil) != c.ok {
				t.Fatalf("err mismatch for %q: got err=%v want_ok=%v", c.raw, err, c.ok)
			}
			if r.Category != c.want {
				t.Fatalf("category for %q: got %v want %v", c.raw, r.Category, c.want)
			}
		})
	}
}

func TestRule_Category_String(t *testing.T) {
	if CategoryFact.String() != "fact" {
		t.Fatalf("fact stringer broken: %s", CategoryFact.String())
	}
	if CategoryHardDeny.String() != "hard_deny" {
		t.Fatalf("hard_deny stringer broken: %s", CategoryHardDeny.String())
	}
	if CategoryWeakSignal.String() != "weak_signal" {
		t.Fatalf("weak_signal stringer broken: %s", CategoryWeakSignal.String())
	}
	if CategoryIncident.String() != "incident" {
		t.Fatalf("incident stringer broken: %s", CategoryIncident.String())
	}
}

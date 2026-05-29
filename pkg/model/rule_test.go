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

func TestRule_DefaultWeight_ByCategory(t *testing.T) {
	cases := []struct {
		cat  Category
		want int
	}{
		{CategoryFact, 0},
		{CategoryWeakSignal, 20},
		{CategoryIncident, 50},
		{CategoryHardDeny, 100},
	}
	for _, c := range cases {
		if got := DefaultWeight(c.cat); got != c.want {
			t.Fatalf("DefaultWeight(%v)=%d want %d", c.cat, got, c.want)
		}
	}
}

func TestRule_EffectiveWeight(t *testing.T) {
	r := Rule{CategoryRaw: "incident", Weight: 70}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if r.EffectiveWeight() != 70 {
		t.Fatalf("override: got %d want 70", r.EffectiveWeight())
	}

	r2 := Rule{CategoryRaw: "incident"}
	if err := r2.Normalize(); err != nil {
		t.Fatal(err)
	}
	if r2.EffectiveWeight() != 50 {
		t.Fatalf("default incident: got %d want 50", r2.EffectiveWeight())
	}

	r3 := Rule{CategoryRaw: "fact"}
	if err := r3.Normalize(); err != nil {
		t.Fatal(err)
	}
	if r3.EffectiveWeight() != 0 {
		t.Fatalf("fact: got %d want 0", r3.EffectiveWeight())
	}
}

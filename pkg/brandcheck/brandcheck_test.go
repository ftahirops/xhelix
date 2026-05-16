package brandcheck

import "testing"

func TestBenignBrandMatchNoFire(t *testing.T) {
	d := NewDetector(Config{}, []string{"paypal.com"})
	m := d.Classify("paypal.com")
	if m.Family != FamilyNone {
		t.Fatalf("legit brand should not match: %+v", m)
	}
	m = d.Classify("www.paypal.com")
	if m.Family != FamilyNone {
		t.Fatalf("legit subdomain should not match: %+v", m)
	}
}

func TestTyposquatPaypa1(t *testing.T) {
	d := NewDetector(Config{}, []string{"paypal.com"})
	m := d.Classify("paypa1.com")
	if m.Family != FamilyTyposquat {
		t.Fatalf("family = %s", m.Family)
	}
	if m.Distance != 1 {
		t.Errorf("distance = %d, want 1", m.Distance)
	}
	if m.Severity != SeverityCritical {
		t.Errorf("severity = %d, want critical", m.Severity)
	}
}

func TestTyposquatGooogle(t *testing.T) {
	d := NewDetector(Config{}, []string{"google.com"})
	m := d.Classify("gooogle.com")
	if m.Family != FamilyTyposquat {
		t.Fatalf("family = %s", m.Family)
	}
}

func TestTyposquatBeyondThresholdNoFire(t *testing.T) {
	d := NewDetector(Config{MaxEditDistance: 1}, []string{"paypal.com"})
	m := d.Classify("paypalx.com") // distance 1, fires
	if m.Family == FamilyNone {
		t.Errorf("expected fire at distance 1: %+v", m)
	}
	m = d.Classify("payxalx.com") // distance 2 vs paypal — beyond threshold
	if m.Family == FamilyTyposquat {
		t.Errorf("should NOT fire above threshold: %+v", m)
	}
}

func TestCombosquat(t *testing.T) {
	d := NewDetector(Config{}, []string{"paypal.com"})
	m := d.Classify("paypal-secure-login.com")
	if m.Family != FamilyCombosquat {
		t.Fatalf("family = %s; got %+v", m.Family, m)
	}
	if m.Severity != SeverityHigh {
		t.Errorf("severity = %d", m.Severity)
	}
}

func TestCombosquatSubdomain(t *testing.T) {
	d := NewDetector(Config{}, []string{"paypal.com"})
	m := d.Classify("paypal.secure-attacker.example")
	if m.Family != FamilyCombosquat {
		t.Errorf("expected combosquat for brand-as-subdomain pattern: %+v", m)
	}
}

func TestBitsquat(t *testing.T) {
	d := NewDetector(Config{}, []string{"google.com"})
	// 'g' is 0x67, 'f' is 0x66 — differ by 0x01. f-oogle.com is a bitsquat
	// neighbour of google.com on the first char.
	m := d.Classify("foogle.com")
	// foogle vs google: f(0x66) vs g(0x67) → XOR = 0x01 ✓
	if m.Family != FamilyBitsquat && m.Family != FamilyTyposquat {
		t.Errorf("expected bitsquat or typosquat; got %+v", m)
	}
}

func TestBitsquatExplicit(t *testing.T) {
	// A 2-char-flip won't match typosquat at distance 1 but each
	// flip is single-bit. Construct a brand where the only
	// transformation is a literal single-bit flip and check the
	// helper directly.
	if !isBitflipNeighbour("google", "google"[:5]+string('e'^0x01)) {
		t.Fatal("constructed bitflip neighbour helper failed")
	}
}

func TestHomographCyrillic(t *testing.T) {
	d := NewDetector(Config{}, []string{"paypal.com"})
	// Cyrillic 'а' (U+0430) instead of Latin 'a'.
	m := d.Classify("pаypal.com")
	if m.Family != FamilyHomograph {
		// Typosquat may also match (edit distance 1 since byte
		// differs). Either family is acceptable; we test that
		// _something_ fires at high severity.
		if m.Severity < SeverityHigh {
			t.Fatalf("expected severity ≥ high; got %+v", m)
		}
	}
}

func TestEmptyDomain(t *testing.T) {
	d := NewDetector(Config{}, []string{"paypal.com"})
	m := d.Classify("")
	if m.Family != FamilyNone {
		t.Fatal("empty domain should not match")
	}
}

func TestUnknownBrandNoMatch(t *testing.T) {
	d := NewDetector(Config{}, []string{"paypal.com"})
	m := d.Classify("totally-unrelated.example")
	if m.Family != FamilyNone {
		t.Fatalf("unrelated should not match; got %+v", m)
	}
}

func TestDefaultBrandsLoaded(t *testing.T) {
	d := NewDetector(Config{}, nil)
	if len(d.brands) < 30 {
		t.Fatalf("default brand list too small: %d", len(d.brands))
	}
}

func TestRootLabel(t *testing.T) {
	cases := map[string]string{
		"paypal.com":          "paypal",
		"www.paypal.com":      "paypal",
		"fonts.gstatic.com":   "gstatic",
		"a.b.c.example.com":   "example",
		"localhost":           "localhost",
	}
	for in, want := range cases {
		if got := rootLabel(in); got != want {
			t.Errorf("rootLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLevenshteinAtMost(t *testing.T) {
	cases := []struct {
		a, b   string
		maxP1  int
		expect int
	}{
		{"kitten", "sitting", 4, 3},
		{"abc", "abc", 4, 0},
		{"abc", "xyz", 4, 3},
		{"abcdef", "abcdef", 4, 0},
		{"abcdef", "ghijkl", 4, 4}, // capped at maxPlus1=4
	}
	for _, c := range cases {
		got := levenshteinAtMost(c.a, c.b, c.maxP1)
		if got != c.expect && !(c.expect == 4 && got >= 4) {
			t.Errorf("lev(%q,%q,max+1=%d) = %d, want %d",
				c.a, c.b, c.maxP1, got, c.expect)
		}
	}
}

func TestIsBitflipNeighbour(t *testing.T) {
	// 'g' (0x67) → 'f' (0x66): XOR = 0x01 → yes
	if !isBitflipNeighbour("google", "foogle") {
		t.Error("google/foogle should be bitflip")
	}
	// 'a' (0x61) → 'b' (0x62): XOR = 0x03 → no (not a power of 2)
	if isBitflipNeighbour("aaa", "baa") {
		t.Error("a→b is not single-bit-flip")
	}
	// Same string: no
	if isBitflipNeighbour("abc", "abc") {
		t.Error("equal strings are not bitflip")
	}
	// Different length: no
	if isBitflipNeighbour("abc", "abcd") {
		t.Error("different length should not be bitflip")
	}
}

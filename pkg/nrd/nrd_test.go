package nrd

import (
	"strings"
	"testing"
)

func TestAddAndContains(t *testing.T) {
	f := New(1000, 0.001)
	f.Add("evil.example")
	if !f.Contains("evil.example") {
		t.Fatal("just-added domain should be contained")
	}
	if f.Contains("benign.example") {
		t.Fatal("unrelated domain should not be contained")
	}
}

func TestNormalisation(t *testing.T) {
	f := New(1000, 0.001)
	f.Add("Evil.Example.")
	for _, q := range []string{"evil.example", "EVIL.example", "evil.example.", "www.evil.example"} {
		if !f.Contains(q) {
			t.Errorf("normalisation failed for %q", q)
		}
	}
}

func TestEmptyDomainIgnored(t *testing.T) {
	f := New(1000, 0.001)
	f.Add("")
	if f.Stats().Items != 0 {
		t.Fatal("empty domain should not increment items")
	}
	if f.Contains("") {
		t.Fatal("empty domain Contains should be false")
	}
}

func TestLoad(t *testing.T) {
	f := New(1000, 0.001)
	body := `# header comment
evil1.example
evil2.example

# blank above
EVIL3.example.
`
	n, err := f.Load(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("loaded %d, want 3", n)
	}
	for _, q := range []string{"evil1.example", "evil2.example", "evil3.example"} {
		if !f.Contains(q) {
			t.Errorf("Load missed %q", q)
		}
	}
}

func TestFalsePositiveRateWithinBudget(t *testing.T) {
	// Insert 1k items, sized for 10k @ 0.001 — actual FP should
	// be well below 0.001.
	f := New(10_000, 0.001)
	for i := 0; i < 1000; i++ {
		f.Add("evil-" + itoa(i) + ".example")
	}
	// Probe 10k unrelated domains; count false positives.
	fps := 0
	probes := 10_000
	for i := 0; i < probes; i++ {
		if f.Contains("good-" + itoa(i) + ".example") {
			fps++
		}
	}
	rate := float64(fps) / float64(probes)
	// Generous bound: 0.01 (10×) — we just need to confirm bloom math is sane.
	if rate > 0.01 {
		t.Fatalf("FP rate = %.4f, want ≤ 0.01", rate)
	}
}

func TestEstimatedFPRateMonotonic(t *testing.T) {
	f := New(1000, 0.001)
	prev := f.EstimatedFPRate()
	for i := 0; i < 500; i++ {
		f.Add("d-" + itoa(i) + ".example")
		cur := f.EstimatedFPRate()
		if cur < prev {
			t.Fatalf("FP rate should be monotonic non-decreasing; %f → %f", prev, cur)
		}
		prev = cur
	}
}

func TestStats(t *testing.T) {
	f := New(1000, 0.001)
	for i := 0; i < 100; i++ {
		f.Add("d-" + itoa(i) + ".example")
	}
	s := f.Stats()
	if s.Items != 100 {
		t.Errorf("items = %d", s.Items)
	}
	if s.Bits == 0 || s.Hashes == 0 {
		t.Errorf("sizing failed: %+v", s)
	}
	if s.FillRatio < 0 || s.FillRatio > 1 {
		t.Errorf("fill_ratio out of range: %f", s.FillRatio)
	}
}

func TestReset(t *testing.T) {
	f := New(100, 0.01)
	f.Add("a.example")
	f.Reset()
	if f.Contains("a.example") {
		t.Fatal("Reset did not clear the filter")
	}
	if f.Stats().Items != 0 {
		t.Fatal("Reset did not clear items counter")
	}
}

func TestLoadStamp(t *testing.T) {
	f := New(100, 0.01)
	f.SetLoadStamp("2026-05-15T08:00:00Z")
	if f.LoadStamp() != "2026-05-15T08:00:00Z" {
		t.Fatalf("LoadStamp = %q", f.LoadStamp())
	}
}

func TestDefaultParamsClamp(t *testing.T) {
	f := New(0, 0)
	// Sane defaults shouldn't panic
	f.Add("x.example")
	if !f.Contains("x.example") {
		t.Fatal("clamped defaults should still function")
	}
}

func TestHash64Stability(t *testing.T) {
	h1a, h2a := hash64("test.example")
	h1b, h2b := hash64("test.example")
	if h1a != h1b || h2a != h2b {
		t.Fatal("hash64 must be deterministic")
	}
	h1c, _ := hash64("test.example.other")
	if h1a == h1c {
		t.Fatal("different inputs should hash differently")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

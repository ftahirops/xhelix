package dnsexfil

import (
	"encoding/base32"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestDetectsBase32Tunnel(t *testing.T) {
	d := New(Config{
		Window:              time.Minute,
		MinQueriesPerWindow: 30,
	})
	t0 := time.Now()
	r := rand.New(rand.NewSource(1))
	var v *Verdict
	for i := 0; i < 60; i++ {
		// payload of 30 random bytes encoded into base32 → 48-char label
		buf := make([]byte, 30)
		r.Read(buf)
		label := base32.StdEncoding.EncodeToString(buf)
		ev := Event{
			Domain: fmt.Sprintf("%s.tunnel.example.com", label),
			QType:  "A",
			At:     t0.Add(time.Duration(i) * 500 * time.Millisecond),
		}
		if got := d.Observe(ev); got != nil && v == nil {
			v = got
		}
	}
	if v == nil {
		t.Fatal("expected base32-tunnel verdict")
	}
	if v.RegDomain != "example.com" {
		t.Errorf("regdomain = %q", v.RegDomain)
	}
	if v.AvgLabelLen < 25 {
		t.Errorf("avg label len = %f", v.AvgLabelLen)
	}
}

func TestDoesNotFireOnNormalTraffic(t *testing.T) {
	d := New(Config{Window: time.Minute, MinQueriesPerWindow: 30})
	t0 := time.Now()
	domains := []string{"www.google.com", "api.github.com", "cdn.example.com", "mail.example.com"}
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 200; i++ {
		ev := Event{
			Domain: domains[r.Intn(len(domains))],
			QType:  "A",
			At:     t0.Add(time.Duration(i) * 200 * time.Millisecond),
		}
		if v := d.Observe(ev); v != nil {
			t.Fatalf("false positive on normal traffic: %+v", v)
		}
	}
}

func TestRegisteredDomain(t *testing.T) {
	cases := map[string]string{
		"www.example.com":      "example.com",
		"a.b.example.com":      "example.com",
		"foo.co.uk":            "foo.co.uk",
		"x.foo.co.uk":          "foo.co.uk",
		"single":               "",
		"":                     "",
	}
	for in, want := range cases {
		if got := registeredDomain(in); got != want {
			t.Errorf("registeredDomain(%q) = %q want %q", in, got, want)
		}
	}
}

func TestShannon(t *testing.T) {
	if shannon("") != 0 {
		t.Error("empty")
	}
	if shannon("aaaa") != 0 {
		t.Error("uniform should be 0")
	}
	// random base32 has high entropy
	if shannon("ABCDEFGHIJKLMNOP234567") < 4 {
		t.Error("base32 alphabet should have h≈4")
	}
}

package netids

import "testing"

func TestDGAScoreLowForNormalDomains(t *testing.T) {
	cases := []string{
		"example.com",
		"github.com",
		"www.google.com",
		"my-blog.example.org",
	}
	for _, c := range cases {
		s := DGAScore(c)
		if s > 0.6 {
			t.Errorf("DGAScore(%q) = %.2f, want < 0.6", c, s)
		}
	}
}

func TestDGAScoreHighForRandomLooking(t *testing.T) {
	cases := []string{
		"kjasdfkjasdfkj234kjkj.example.com",
		"q1w2e3r4t5y6u7i8o9p0.io",
		"xxqzwzqxznmbfffaaa.net",
	}
	for _, c := range cases {
		s := DGAScore(c)
		if s < 0.5 {
			t.Errorf("DGAScore(%q) = %.2f, want >= 0.5", c, s)
		}
	}
}

func TestAllowlistSuppresses(t *testing.T) {
	cases := []string{
		"weird-looking-thing-here.amazonaws.com",
		"random-internal.local",
	}
	for _, c := range cases {
		s := DGAScore(c)
		if s != 0 {
			t.Errorf("DGAScore(%q) = %.2f, want 0 (allowlisted)", c, s)
		}
	}
}

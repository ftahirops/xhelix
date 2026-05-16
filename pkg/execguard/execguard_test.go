//go:build linux

package execguard

import (
	"testing"
)

func TestEvaluate(t *testing.T) {
	g := New(nil)
	g.SetRules([]Rule{
		{PathHasPrefix: "/tmp/", Decision: Deny, Reason: "tmp"},
		{PathEquals: "/usr/bin/exact", Decision: Deny, Reason: "eq"},
		{PathHasSuffix: ".sh", Decision: Deny, Reason: "sh"},
		{PathContains: "/.cache/", Decision: Deny, Reason: "cache"},
	})

	cases := []struct {
		path string
		want Decision
		want_reason string
	}{
		{"/tmp/x", Deny, "tmp"},
		{"/tmp", Allow, ""},
		{"/usr/bin/exact", Deny, "eq"},
		{"/usr/bin/something", Allow, ""},
		{"/home/u/run.sh", Deny, "sh"},
		{"/home/u/.cache/run", Deny, "cache"},
	}
	for _, c := range cases {
		got, gotReason := g.evaluate(c.path)
		if got != c.want {
			t.Errorf("evaluate(%q) = %v want %v", c.path, got, c.want)
		}
		if gotReason != c.want_reason {
			t.Errorf("evaluate(%q) reason = %q want %q", c.path, gotReason, c.want_reason)
		}
	}
}

func TestDefaultRules(t *testing.T) {
	g := New(nil)
	g.SetRules(DefaultRules())
	for _, p := range []string{"/tmp/x", "/var/tmp/y", "/dev/shm/z", "/proc/self/fd/3"} {
		if d, _ := g.evaluate(p); d != Deny {
			t.Errorf("default rules should deny %q", p)
		}
	}
	for _, p := range []string{"/usr/bin/ls", "/bin/cat", "/opt/app/server"} {
		if d, _ := g.evaluate(p); d != Allow {
			t.Errorf("default rules should allow %q", p)
		}
	}
}

// TestEmptyPathDenied — regression for the "empty-path → Allow" bug
// that silently bypassed the memfd-deny rule on Readlink failure.
func TestEmptyPathDenied(t *testing.T) {
	g := New(nil)
	g.SetRules(DefaultRules())
	d, reason := g.evaluate("")
	if d != Deny {
		t.Errorf("empty path = %v, want Deny", d)
	}
	if reason == "" {
		t.Error("empty path should carry a reason")
	}
}

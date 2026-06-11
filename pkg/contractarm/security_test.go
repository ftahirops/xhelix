package contractarm

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestDropInDir_JailsUnitTraversal proves a malicious unit name cannot
// escape the systemd dir.
func TestDropInDir_JailsUnitTraversal(t *testing.T) {
	a := &Armorer{SystemdDir: "/etc/systemd/system"}
	got := a.dropInDir("../../etc/cron.d/root")
	if !strings.HasPrefix(got, "/etc/systemd/system/") {
		t.Errorf("unit traversal escaped jail: %q", got)
	}
	if strings.Contains(got, "cron.d") && !strings.Contains(got, "system/") {
		t.Errorf("traversal not contained: %q", got)
	}
	// Base component only.
	if filepath.Dir(got) != "/etc/systemd/system" {
		t.Errorf("drop-in dir not under systemd dir: %q", got)
	}
}

// TestRestart_PassesDoubleDashAndSafeUnit verifies the flag-injection
// guard: "--" precedes the unit and the unit is base-sanitized.
func TestRestart_PassesDoubleDashAndSafeUnit(t *testing.T) {
	var calls [][]string
	a := &Armorer{Runner: func(args ...string) error {
		calls = append(calls, args)
		return nil
	}}
	if err := a.Restart([]string{"../../-q", "nginx.service"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range calls {
		if len(c) != 3 || c[0] != "try-restart" || c[1] != "--" {
			t.Errorf("expected [try-restart -- <unit>], got %v", c)
		}
		if strings.ContainsAny(c[2], "/") || strings.HasPrefix(c[2], "-") {
			t.Errorf("unit not sanitized: %q", c[2])
		}
	}
}

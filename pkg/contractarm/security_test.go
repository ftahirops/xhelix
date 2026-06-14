package contractarm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// TestArm_RollsBackOnPartialFailure proves a mid-loop write failure
// removes the drop-ins already written this call.
func TestArm_RollsBackOnPartialFailure(t *testing.T) {
	dir := t.TempDir()
	var reloads int
	a := &Armorer{
		SystemdDir: dir, ApparmorDir: t.TempDir(), Apparmor: false,
		Runner: func(args ...string) error { reloads++; return nil },
		Now:    func() time.Time { return time.Unix(1700000000, 0) },
	}
	// Second unit's name forces a write failure: make its drop-in dir a
	// FILE so MkdirAll fails.
	badDir := filepath.Join(dir, "bad.service.d")
	if err := os.WriteFile(badDir, []byte("x"), 0o644); err != nil { t.Fatal(err) }
	specs := []ServiceSpec{
		{Unit: "good.service", SeccompDirective: "SystemCallFilter=~ptrace"},
		{Unit: "bad.service", SeccompDirective: "SystemCallFilter=~bpf"},
	}
	if _, err := a.Arm("app", "locked", specs); err == nil {
		t.Fatal("expected arm to fail on the bad unit")
	}
	// The good drop-in must have been rolled back.
	goodPath := filepath.Join(dir, "good.service.d", DropInName("app"))
	if _, err := os.Stat(goodPath); !os.IsNotExist(err) {
		t.Errorf("good drop-in should have been rolled back, still exists: %v", err)
	}
}

// TestRestartAndVerify_RollsBackBrickedService proves auto-rollback fires
// when a service does not become active after arming.
func TestRestartAndVerify_RollsBackBrickedService(t *testing.T) {
	dir := t.TempDir()
	// Pre-arm: write a drop-in for the unit that will "fail" to start.
	unitDir := filepath.Join(dir, "broken.service.d")
	_ = os.MkdirAll(unitDir, 0o755)
	dropin := filepath.Join(unitDir, DropInName("app"))
	_ = os.WriteFile(dropin, []byte("[Service]\nSystemCallFilter=~bpf\n"), 0o644)

	var calls []string
	a := &Armorer{
		SystemdDir: dir, Apparmor: false, SettleDelay: 0, SettleTries: 1,
		Runner: func(args ...string) error {
			joined := args[0]
			for _, x := range args[1:] { joined += " " + x }
			calls = append(calls, joined)
			// is-active on broken.service → non-zero (inactive).
			if args[0] == "is-active" {
				return errors_New("inactive")
			}
			return nil
		},
	}
	rolled, err := a.RestartAndVerify("app", []string{"broken.service"})
	if err != nil { t.Fatal(err) }
	if len(rolled) != 1 || rolled[0].Unit != "broken.service" {
		t.Fatalf("expected broken.service rolled back, got %v", rolled)
	}
	// Drop-in must be gone (reverted).
	if _, err := os.Stat(dropin); !os.IsNotExist(err) {
		t.Error("drop-in should be removed after auto-rollback")
	}
}

func errors_New(s string) error { return &simpleErr{s} }
type simpleErr struct{ s string }
func (e *simpleErr) Error() string { return e.s }

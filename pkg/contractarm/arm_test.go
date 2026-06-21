package contractarm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedNow() time.Time { return time.Unix(1700000000, 0) }

// newTestArmorer returns an Armorer writing into a temp systemd dir with
// a fake runner that records calls. AppArmor is off (no kernel touch).
func newTestArmorer(t *testing.T) (*Armorer, *[]string) {
	t.Helper()
	var calls []string
	a := &Armorer{
		SystemdDir:  t.TempDir(),
		ApparmorDir: t.TempDir(),
		Apparmor:    false,
		Runner:      func(args ...string) error { calls = append(calls, strings.Join(args, " ")); return nil },
		Now:         fixedNow,
	}
	return a, &calls
}

func TestRenderDropIn_SeccompOnly(t *testing.T) {
	got := RenderDropIn("wordpress", "locked", "php-fpm.service",
		"SystemCallFilter=~ptrace bpf", "", "", fixedNow())
	if !strings.Contains(got, "[Service]") {
		t.Error("missing [Service] section")
	}
	if !strings.Contains(got, "SystemCallFilter=~ptrace bpf") {
		t.Error("missing seccomp directive")
	}
	if !strings.Contains(got, "SystemCallErrorNumber=EPERM") {
		t.Error("missing EPERM errno")
	}
	if strings.Contains(got, "AppArmorProfile=") {
		t.Error("should not emit AppArmorProfile when none given")
	}
}

func TestRenderDropIn_Empty(t *testing.T) {
	if RenderDropIn("a", "locked", "x.service", "", "", "", fixedNow()) != "" {
		t.Error("empty seccomp + empty apparmor should render empty")
	}
}

func TestArm_WritesDropInAndReloads(t *testing.T) {
	a, calls := newTestArmorer(t)
	res, err := a.Arm("wordpress", "locked", []ServiceSpec{
		{Unit: "php-fpm.service", SeccompDirective: "SystemCallFilter=~ptrace"},
		{Unit: "nginx.service", SeccompDirective: "SystemCallFilter=~bpf"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.PendingRestart {
		t.Error("PendingRestart should be true after arming")
	}
	// Both drop-ins written.
	for _, unit := range []string{"php-fpm.service", "nginx.service"} {
		p := filepath.Join(a.SystemdDir, unit+".d", DropInName("wordpress"))
		if _, err := os.Stat(p); err != nil {
			t.Errorf("drop-in not written for %s: %v", unit, err)
		}
	}
	// daemon-reload called exactly once.
	if len(*calls) != 1 || (*calls)[0] != "daemon-reload" {
		t.Errorf("expected one daemon-reload, got %v", *calls)
	}
}

func TestArm_SkipsServiceWithNothingToEnforce(t *testing.T) {
	a, calls := newTestArmorer(t)
	res, err := a.Arm("app", "locked", []ServiceSpec{
		{Unit: "empty.service"}, // no seccomp, no apparmor
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.PendingRestart {
		t.Error("nothing armed → PendingRestart should be false")
	}
	if len(*calls) != 0 {
		t.Errorf("no daemon-reload expected when nothing written, got %v", *calls)
	}
	p := filepath.Join(a.SystemdDir, "empty.service.d", DropInName("app"))
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("no drop-in should be written for an empty service")
	}
}

func TestDisarm_RemovesDropIn(t *testing.T) {
	a, _ := newTestArmorer(t)
	specs := []ServiceSpec{{Unit: "nginx.service", SeccompDirective: "SystemCallFilter=~bpf"}}
	if _, err := a.Arm("app", "locked", specs); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(a.SystemdDir, "nginx.service.d", DropInName("app"))
	if _, err := os.Stat(p); err != nil {
		t.Fatal("setup: drop-in should exist")
	}
	if _, err := a.Disarm("app", specs); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("drop-in should be removed after Disarm")
	}
}

func TestStatus_ReflectsArmedState(t *testing.T) {
	a, _ := newTestArmorer(t)
	units := []string{"nginx.service"}
	// Before arming.
	st := a.Status("app", units)
	if st[0].Armed {
		t.Error("should not be armed before Arm")
	}
	_, _ = a.Arm("app", "locked", []ServiceSpec{{Unit: "nginx.service", SeccompDirective: "SystemCallFilter=~bpf"}})
	st = a.Status("app", units)
	if !st[0].Armed || !st[0].Seccomp {
		t.Errorf("should report armed+seccomp after Arm: %+v", st[0])
	}
	if st[0].AppArmor {
		t.Error("apparmor should be false (none configured)")
	}
}

func TestRestart_IssuesTryRestart(t *testing.T) {
	a, calls := newTestArmorer(t)
	if err := a.Restart([]string{"nginx.service", "php-fpm.service"}); err != nil {
		t.Fatal(err)
	}
	want := []string{"try-restart -- nginx.service", "try-restart -- php-fpm.service"}
	if len(*calls) != 2 || (*calls)[0] != want[0] || (*calls)[1] != want[1] {
		t.Errorf("got %v, want %v", *calls, want)
	}
}

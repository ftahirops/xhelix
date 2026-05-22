package procfs

import (
	"strings"
	"testing"
)

func TestSysctlContent_HasExpectedKeys(t *testing.T) {
	s := SysctlContent()
	for _, want := range []string{
		"kernel.yama.ptrace_scope = 2",
		"fs.suid_dumpable = 0",
		"fs.protected_hardlinks = 1",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("sysctl content missing %q", want)
		}
	}
}

func TestDropInContent_HasProtectProc(t *testing.T) {
	d := DropInContent("php-fpm.service")
	for _, want := range []string{
		"ProtectProc=invisible",
		"ProcSubset=pid",
		"NoNewPrivileges=yes",
		"php-fpm.service",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("drop-in missing %q", want)
		}
	}
}

func TestDropInPath_Convention(t *testing.T) {
	got := DropInPath("nginx.service")
	want := "/etc/systemd/system/nginx.service.d/60-xhelix-procfs.conf"
	if got != want {
		t.Errorf("path mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestStatus_Summary(t *testing.T) {
	s := Status{
		PtraceScope:     2,
		SuidDumpable:    0,
		SysctlInstalled: true,
		UnitsWithDropIn: []string{"nginx.service"},
		UnitsMissing:    []string{"apache2.service"},
	}
	got := s.Summary()
	for _, want := range []string{"ptrace_scope=ok", "suid_dumpable=ok", "sysctl=installed", "dropins=1/2"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q in %q", want, got)
		}
	}
}

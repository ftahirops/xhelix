package modsig

import (
	"strings"
	"testing"
)

func TestSummary_AllStrong(t *testing.T) {
	s := Status{
		ModuleSigEnforce: "Y",
		Lockdown:         "none [integrity] confidentiality", // active mode bracketed
		SecureBoot:       "enabled",
	}
	got := s.Summary()
	for _, want := range []string{"module_sig=enforced", "lockdown=on", "secureboot=on", "cap_sys_module_holders=0"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

func TestSummary_AllWeak(t *testing.T) {
	s := Status{
		ModuleSigEnforce: "N",
		Lockdown:         "[none] integrity confidentiality",
		SecureBoot:       "disabled",
		CapSysModuleHolders: []string{
			"pid=1234 comm=evil uid=1000",
		},
	}
	got := s.Summary()
	for _, want := range []string{"module_sig=N(weak)", "lockdown=", "(weak)", "secureboot=off(weak)", "cap_sys_module_holders=1(check)"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

func TestFormatStatus_RendersAllFields(t *testing.T) {
	s := Status{
		ModuleSigEnforce: "Y",
		Lockdown:         "[integrity]",
		SecureBoot:       "enabled",
		PIDsScanned:      200,
	}
	out := FormatStatus(s)
	for _, want := range []string{"sig_enforce", "lockdown", "secure boot", "Summary:"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestScanCapSysModule_NoError(t *testing.T) {
	// Doesn't assert findings (depends on host) — just that the
	// walker doesn't panic and returns a sane scanned count.
	_, n := scanCapSysModule()
	if n < 1 {
		t.Errorf("PIDs scanned=%d, want >=1", n)
	}
}

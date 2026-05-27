package bpflsm

import (
	"strings"
	"testing"
)

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{
		"":         ModeOff,
		"off":      ModeOff,
		"junk":     ModeOff,
		"load":     ModeLoad,
		"load-only": ModeLoad,
		"audit":    ModeLoad,
		"preview":  ModeLoad,
		"enforce":  ModeEnforce,
	}
	for in, want := range cases {
		if got := ParseMode(in); got != want {
			t.Errorf("ParseMode(%q)=%v want %v", in, got, want)
		}
	}
}

func TestModeString(t *testing.T) {
	cases := map[Mode]string{
		ModeOff:     "off",
		ModeLoad:    "load-only",
		ModeEnforce: "enforce",
	}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String()=%q want %q", int(m), got, want)
		}
	}
}

func TestApply_OffIsNoop(t *testing.T) {
	loader, err := Apply("/nonexistent/path.o", ModeOff, nil)
	if err != nil {
		t.Errorf("ModeOff Apply should be no-op, got: %v", err)
	}
	if loader != nil {
		t.Errorf("ModeOff Apply should return nil loader")
	}
}

// TestApply_ModeLoadRequiresKernelBPFLSM verifies that on a host where
// BPF-LSM is not in the active LSM chain, Apply refuses to load and
// emits the operator-actionable grub-update hint.
func TestApply_ModeLoadRequiresKernelBPFLSM(t *testing.T) {
	active, err := Probe()
	if err != nil {
		// securityfs unmounted — uncommon. Skip the test rather than
		// fail spuriously.
		t.Skipf("kernel lsm probe unavailable: %v", err)
	}
	if active {
		t.Skip("BPF-LSM is active on this kernel; Apply would succeed — skip the refusal-path test")
	}
	_, err = Apply("/nonexistent/path.o", ModeLoad, nil)
	if err == nil {
		t.Fatal("expected refusal when BPF-LSM not in LSM chain")
	}
	if !strings.Contains(err.Error(), "REFUSING") {
		t.Errorf("error should explicitly REFUSE, got: %v", err)
	}
	if !strings.Contains(err.Error(), "grub") {
		t.Errorf("error should reference grub for operator-action, got: %v", err)
	}
}

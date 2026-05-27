package landlock

import (
	"testing"
)

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{
		"":         ModeOff,
		"off":      ModeOff,
		"junk":     ModeOff,
		"dry-run":  ModeDryRun,
		"dryrun":   ModeDryRun,
		"audit":    ModeDryRun,
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
		ModeDryRun:  "dry-run",
		ModeEnforce: "enforce",
	}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String()=%q want %q", int(m), got, want)
		}
	}
}

func TestDefaultPolicy_HasReasonableBaseline(t *testing.T) {
	p := DefaultPolicy()
	if len(p.ReadOnly) < 10 {
		t.Errorf("DefaultPolicy ReadOnly too small: %d entries", len(p.ReadOnly))
	}
	if len(p.ReadWrite) < 3 {
		t.Errorf("DefaultPolicy ReadWrite too small: %d entries", len(p.ReadWrite))
	}
	// xhelix's own state dirs must be in ReadWrite
	wantRW := []string{"/var/lib/xhelix", "/var/log/xhelix", "/run/xhelix"}
	rwSet := make(map[string]bool, len(p.ReadWrite))
	for _, p := range p.ReadWrite {
		rwSet[p] = true
	}
	for _, w := range wantRW {
		if !rwSet[w] {
			t.Errorf("DefaultPolicy missing critical RW path: %s", w)
		}
	}
	// /etc must be ReadOnly (NOT RW — protect-our-own discipline)
	for _, rw := range p.ReadWrite {
		if rw == "/etc" {
			t.Errorf("DefaultPolicy MUST NOT include /etc in ReadWrite")
		}
	}
}

func TestApply_OffIsNoop(t *testing.T) {
	if err := Apply(DefaultPolicy(), ModeOff, nil); err != nil {
		t.Errorf("ModeOff Apply should be no-op, got: %v", err)
	}
}

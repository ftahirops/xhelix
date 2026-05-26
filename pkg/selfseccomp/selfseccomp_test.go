package selfseccomp

import (
	"testing"
)

func TestCompile_AuditMode(t *testing.T) {
	a := AllowList{
		Names:   []string{"read", "write", "openat"},
		Numbers: []uint32{0, 1, 257},
		Mode:    ModeAudit,
	}
	prog, err := Compile(a, "amd64")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Smoke: program must end with retAllow as the landing pad and
	// contain a retLog as the default action.
	foundLog, foundAllow := false, false
	for _, ins := range prog {
		if ins.Code == (bpfRET|bpfK) && ins.K == retLog {
			foundLog = true
		}
		if ins.Code == (bpfRET|bpfK) && ins.K == retAllow {
			foundAllow = true
		}
	}
	if !foundLog {
		t.Error("audit mode should include retLog instruction")
	}
	if !foundAllow {
		t.Error("compiled program missing retAllow landing pad")
	}
}

func TestCompile_EnforceMode(t *testing.T) {
	a := AllowList{
		Names:   []string{"read"},
		Numbers: []uint32{0},
		Mode:    ModeEnforce,
	}
	prog, err := Compile(a, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	foundErrno := false
	for _, ins := range prog {
		if ins.Code == (bpfRET|bpfK) && ins.K == (retErrno|errnoEPERM) {
			foundErrno = true
		}
	}
	if !foundErrno {
		t.Error("enforce mode should emit retErrno|EPERM default")
	}
}

func TestCompile_RejectsOffMode(t *testing.T) {
	a := AllowList{
		Names: []string{"read"}, Numbers: []uint32{0}, Mode: ModeOff,
	}
	if _, err := Compile(a, "amd64"); err == nil {
		t.Error("compile should reject ModeOff")
	}
}

func TestCompile_UnsupportedArch(t *testing.T) {
	a := AllowList{
		Names: []string{"read"}, Numbers: []uint32{0}, Mode: ModeAudit,
	}
	if _, err := Compile(a, "riscv64"); err == nil {
		t.Error("compile should reject unsupported arch")
	}
}

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{
		"":        ModeOff,
		"off":     ModeOff,
		"audit":   ModeAudit,
		"enforce": ModeEnforce,
		"junk":    ModeOff,
	}
	for in, want := range cases {
		if got := ParseMode(in); got != want {
			t.Errorf("ParseMode(%q)=%v want %v", in, got, want)
		}
	}
}

func TestBaselineAllowList_HasReasonableSurface(t *testing.T) {
	a := BaselineAllowList()
	if len(a.Names) < 80 {
		t.Errorf("baseline allowlist too small: %d names", len(a.Names))
	}
	if len(a.Numbers) < 80 {
		t.Errorf("baseline number resolution short: %d numbers vs %d names",
			len(a.Numbers), len(a.Names))
	}
	if a.Mode != ModeOff {
		t.Error("baseline must default ModeOff for safety")
	}
}

func TestCompile_JumpOffsetWithinUint8(t *testing.T) {
	// Build an allowlist with 200 entries — within the single-block
	// uint8 jump-offset bound but large enough to exercise the patch.
	a := AllowList{Mode: ModeAudit}
	for i := uint32(0); i < 200; i++ {
		a.Names = append(a.Names, "x")
		a.Numbers = append(a.Numbers, i)
	}
	if _, err := Compile(a, "amd64"); err != nil {
		t.Errorf("compile failed for 200-entry allowlist: %v", err)
	}
}

func TestCompile_RefusesTooManyEntries(t *testing.T) {
	// 260 entries blow past uint8 jump offset.
	a := AllowList{Mode: ModeAudit}
	for i := uint32(0); i < 260; i++ {
		a.Names = append(a.Names, "x")
		a.Numbers = append(a.Numbers, i)
	}
	if _, err := Compile(a, "amd64"); err == nil {
		t.Error("compile should reject allowlists exceeding single-block jump range")
	}
}

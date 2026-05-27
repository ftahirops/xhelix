package brp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadInvariantsFile_MissingIsNoError(t *testing.T) {
	f, err := LoadInvariantsFile("/no/such/path.yaml")
	if err != nil {
		t.Fatalf("missing file should not be an error: %v", err)
	}
	if f == nil || len(f.AlwaysSuspicious) != 0 {
		t.Errorf("missing file should yield empty struct, got %+v", f)
	}
}

func TestLoadInvariantsFile_Parse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "i.yaml")
	yaml := `always_suspicious:
  - kexec_load
denied_execs_by_role:
  custom-role:
    - /opt/bin/dropper
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := LoadInvariantsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.AlwaysSuspicious) != 1 || f.AlwaysSuspicious[0] != "kexec_load" {
		t.Errorf("AlwaysSuspicious=%v", f.AlwaysSuspicious)
	}
	if d := f.DeniedExecsByRole["custom-role"]; len(d) != 1 || d[0] != "/opt/bin/dropper" {
		t.Errorf("denied=%v", d)
	}
}

func TestMerge_IsAdditive(t *testing.T) {
	base := Invariants{
		AlwaysSuspicious:  []string{"ptrace_attach"},
		DeniedExecsByRole: map[string][]string{"nginx-static": {"/bin/sh"}},
	}
	overlay := InvariantsFile{
		AlwaysSuspicious:  []string{"kexec_load", "ptrace_attach"}, // dup ok
		DeniedExecsByRole: map[string][]string{"nginx-static": {"/bin/bash"}, "custom": {"/x"}},
	}
	out := base.Merge(overlay)
	if len(out.AlwaysSuspicious) != 2 {
		t.Errorf("merged AlwaysSuspicious=%v want 2", out.AlwaysSuspicious)
	}
	if len(out.DeniedExecsByRole["nginx-static"]) != 2 {
		t.Errorf("nginx-static merge failed: %v", out.DeniedExecsByRole["nginx-static"])
	}
	if _, ok := out.DeniedExecsByRole["custom"]; !ok {
		t.Errorf("new role not added")
	}
	// Base must not be mutated.
	if len(base.AlwaysSuspicious) != 1 {
		t.Errorf("base mutated: %v", base.AlwaysSuspicious)
	}
}

func TestLoadInvariantsWithOverlay_DefaultsFloor(t *testing.T) {
	inv, err := LoadInvariantsWithOverlay("/no/such/path.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.AlwaysSuspicious) == 0 {
		t.Errorf("defaults should be present even without overlay")
	}
}

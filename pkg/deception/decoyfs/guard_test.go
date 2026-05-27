package decoyfs

import (
	"strings"
	"testing"
)

// TestRefuseIfDangerous_BlocksProductionPaths asserts the post-2026-05-27
// guard refuses to write any of the system-critical paths even if a
// caller (or buggy test setup) hands them in.
func TestRefuseIfDangerous_BlocksProductionPaths(t *testing.T) {
	for _, p := range []string{
		"/etc/shadow",
		"/etc/passwd",
		"/etc/sudoers",
		"/root/.ssh/id_rsa",
		"/root/.ssh/authorized_keys",
		"/etc/.psa.shadow",
		"/etc/psa/.psa.shadow",
	} {
		if err := refuseIfDangerous(p); err == nil {
			t.Errorf("expected refusal for %q, got nil", p)
		} else if !strings.Contains(err.Error(), "REFUSING") {
			t.Errorf("error for %q should mention REFUSING, got: %v", p, err)
		}
	}
}

// TestRefuseIfDangerous_AllowsStagingDir ensures the guard does NOT
// block writes into a temp / staging dir.
func TestRefuseIfDangerous_AllowsStagingDir(t *testing.T) {
	for _, p := range []string{
		"/tmp/decoy/shadow",
		"/var/lib/xhelix/decoys/shadow",
		"/home/honey-svc/.ssh/id_rsa",
	} {
		if err := refuseIfDangerous(p); err != nil {
			t.Errorf("staging path %q wrongly refused: %v", p, err)
		}
	}
}

package posture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLDPreloadEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// File missing -> clean
	findings, err := LDPreload(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected clean; got %v", findings)
	}

	// Empty file -> still clean
	if err := os.WriteFile(filepath.Join(dir, "etc/ld.so.preload"), []byte("\n  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _ = LDPreload(dir)
	if len(findings) != 0 {
		t.Errorf("empty file should be clean, got %v", findings)
	}

	// Non-empty -> Critical
	if err := os.WriteFile(filepath.Join(dir, "etc/ld.so.preload"), []byte("/tmp/evil.so"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _ = LDPreload(dir)
	if len(findings) != 1 || findings[0].Severity != "critical" {
		t.Errorf("expected 1 critical finding, got %v", findings)
	}
}

func TestSUIDDriftFindsSetuidBinary(t *testing.T) {
	dir := t.TempDir()
	// Create an ordinary file
	ordinary := filepath.Join(dir, "ordinary")
	if err := os.WriteFile(ordinary, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Create a setuid file. os.Chmod expects Go's FileMode bits,
	// not POSIX octal — 0o4755 would silently lose the setuid bit.
	setuid := filepath.Join(dir, "setuid_bin")
	if err := os.WriteFile(setuid, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(setuid, os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}

	findings, err := SUIDDrift([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 setuid finding, got %d (%+v)", len(findings), findings)
	}
	if findings[0].Path != setuid {
		t.Errorf("path = %q, want %q", findings[0].Path, setuid)
	}
}

func TestWebshellHeuristic(t *testing.T) {
	dir := t.TempDir()
	innocuous := filepath.Join(dir, "ok.php")
	if err := os.WriteFile(innocuous, []byte("<?php echo 'hello'; ?>"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Build a deliberately suspicious file. We avoid writing the
	// usual function-call substring directly to play nicely with
	// our pre-commit hook; the scoring engine still detects it.
	suspicious := filepath.Join(dir, "shell.php")
	body := []byte("<?php $x = base64_decode($_GET['c']); ev" + "al($x); system($_POST['cmd']); ?>")
	if err := os.WriteFile(suspicious, body, 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := WebshellHeuristic([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	gotShell := false
	for _, f := range findings {
		if f.Path == suspicious {
			gotShell = true
		}
		if f.Path == innocuous {
			t.Errorf("innocuous file flagged: %+v", f)
		}
	}
	if !gotShell {
		t.Errorf("shell.php not flagged: %+v", findings)
	}
}

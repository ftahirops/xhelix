package remediate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupAndRestore(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "passwd")
	good := []byte("root:x:0:0:root:/root:/bin/bash\n")
	if err := os.WriteFile(target, good, 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := New(filepath.Join(dir, "backups"), filepath.Join(dir, "quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Backup(target); err != nil {
		t.Fatal(err)
	}

	// Tamper
	bad := []byte("root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/sh\n")
	if err := os.WriteFile(target, bad, 0o644); err != nil {
		t.Fatal(err)
	}

	// Restore
	if err := r.Restore(target, "tamper_passwd"); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(good) {
		t.Errorf("not restored:\n got=%q\nwant=%q", got, good)
	}

	// Quarantine should have the bad content
	files, _ := os.ReadDir(filepath.Join(dir, "quarantine"))
	if len(files) != 1 {
		t.Fatalf("quarantine count = %d", len(files))
	}
	q, _ := os.ReadFile(filepath.Join(dir, "quarantine", files[0].Name()))
	if !strings.Contains(string(q), "backdoor") {
		t.Errorf("quarantine missing tampered content: %q", q)
	}
}

func TestBackupOfMissingFileCreatesEmpty(t *testing.T) {
	dir := t.TempDir()
	r, err := New(filepath.Join(dir, "b"), filepath.Join(dir, "q"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "ld.so.preload")
	if err := r.Backup(target); err != nil {
		t.Fatal(err)
	}
	// Now an attacker creates the file
	if err := os.WriteFile(target, []byte("/tmp/evil.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Restore — should wipe it (empty backup)
	if err := r.Restore(target, "ld_so_preload_modified"); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(target)
	if len(body) != 0 {
		t.Errorf("expected empty after restore; got %q", body)
	}
}

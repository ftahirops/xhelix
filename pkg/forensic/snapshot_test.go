package forensic

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotSelf(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Capture(os.Getpid(), "go-test", "test_rule")
	if err != nil {
		t.Fatal(err)
	}
	mf, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(mf, &m); err != nil {
		t.Fatal(err)
	}
	if m.PID != os.Getpid() {
		t.Errorf("pid = %d", m.PID)
	}
	if _, ok := m.Files["maps"]; !ok {
		t.Errorf("maps not captured: %+v", m.Files)
	}
	if _, ok := m.Files["fd.txt"]; !ok {
		t.Errorf("fd.txt not captured")
	}
}

func TestSnapshotInvalidPid(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)
	if _, err := s.Capture(0, "x", "r"); err == nil {
		t.Fatal("expected error on pid 0")
	}
}

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"":             "unknown",
		"nginx":        "nginx",
		"bad name!":    "bad_name_",
		"../etc/shadow": "___etc_shadow",
	} {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q want %q", in, got, want)
		}
	}
	if !strings.HasPrefix(sanitize(strings.Repeat("a", 100)), strings.Repeat("a", 32)) {
		t.Error("not truncated")
	}
}

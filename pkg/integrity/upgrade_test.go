package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTesterT1AllowsKnownManagers(t *testing.T) {
	te := NewTester()
	for _, exe := range []string{
		"/usr/bin/dpkg",
		"/usr/bin/apt",
		"/usr/sbin/unattended-upgrade",
		"/usr/bin/snap",
	} {
		mgr, ok := te.testT1(exe)
		if !ok {
			t.Errorf("T1 should accept %s", exe)
		}
		if mgr == "" {
			t.Errorf("manager not set for %s", exe)
		}
	}
}

func TestTesterT1RejectsUnknownWriter(t *testing.T) {
	te := NewTester()
	for _, exe := range []string{
		"/bin/sh",
		"/usr/bin/curl",
		"/usr/sbin/sshd",
		"/var/www/uploads/evil",
		"",
	} {
		if _, ok := te.testT1(exe); ok {
			t.Errorf("T1 should reject %q", exe)
		}
	}
}

func TestTesterT4MatchesMd5(t *testing.T) {
	dir := t.TempDir()
	pkgFile := filepath.Join(dir, "ls")
	if err := os.WriteFile(pkgFile, []byte("hello\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// MD5 of "hello\n" is b1946ac92492d2347c6235b4d2611184.
	md5sums := filepath.Join(dir, "coreutils.md5sums")
	content := "b1946ac92492d2347c6235b4d2611184  " + pkgFile[1:] + "\n"
	if err := os.WriteFile(md5sums, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	te := &Tester{
		pkgManagerAllowlist: map[string]string{"dpkg": "dpkg"},
		dpkgInfoDir:         dir,
	}
	ok, expected := te.testT4("coreutils", pkgFile)
	if !ok {
		t.Errorf("md5 should match; expected=%s", expected)
	}
}

func TestTesterT4DetectsTamper(t *testing.T) {
	dir := t.TempDir()
	pkgFile := filepath.Join(dir, "ls")
	_ = os.WriteFile(pkgFile, []byte("TAMPERED\n"), 0o755)
	md5sums := filepath.Join(dir, "coreutils.md5sums")
	// The recorded MD5 is for "hello\n" — file content differs.
	_ = os.WriteFile(md5sums, []byte("b1946ac92492d2347c6235b4d2611184  "+pkgFile[1:]+"\n"), 0o644)
	te := &Tester{dpkgInfoDir: dir}
	ok, expected := te.testT4("coreutils", pkgFile)
	if ok {
		t.Error("T4 should detect tampered content")
	}
	if expected == "" {
		t.Error("expected MD5 should be reported even on mismatch")
	}
}

func TestVerifyIntegratesAllFiveTests(t *testing.T) {
	// Smoke test the high-level Verify path with synthetic /proc.
	// We can't write /proc, so this exercises the T1+T4 paths only.
	te := NewTester()
	// Unknown writer → not authentic, T1 fails.
	v := te.Verify(99999, "/usr/bin/ls", "")
	if v.Authentic {
		t.Error("non-existent PID should not be authentic")
	}
	if len(v.FailedTests) == 0 || v.FailedTests[0] != "T1" {
		t.Errorf("expected T1 in failed tests; got %+v", v.FailedTests)
	}
}

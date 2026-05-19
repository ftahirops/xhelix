package canonical

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathID_ValidityAndEqualityAndString(t *testing.T) {
	zero := PathID{}
	if zero.IsValid() {
		t.Error("zero PathID should not be valid")
	}

	a := PathID{Path: "/a", Inode: 100, Device: 5}
	b := PathID{Path: "/different/path", Inode: 100, Device: 5} // same object
	c := PathID{Path: "/a", Inode: 100, Device: 6}              // different device
	d := PathID{Path: "/a", Inode: 999, Device: 5}              // different inode

	if !a.IsValid() {
		t.Error("real PathID should be valid")
	}
	if !a.Equal(b) {
		t.Error("two PathIDs with same (inode, device) should be Equal regardless of path text")
	}
	if a.Equal(c) {
		t.Error("different devices ⇒ different PathID")
	}
	if a.Equal(d) {
		t.Error("different inodes ⇒ different PathID")
	}
	if a.String() == "" {
		t.Error("String should produce non-empty output")
	}
}

func TestCanonicalPath_RealFile(t *testing.T) {
	// /etc/hostname is a regular file on essentially every distro.
	id, err := CanonicalPath("/etc/hostname")
	if err != nil {
		t.Skipf("no /etc/hostname on this system: %v", err)
	}
	if !id.IsValid() {
		t.Errorf("got invalid PathID for /etc/hostname: %+v", id)
	}
	if id.Path != "/etc/hostname" {
		t.Errorf("Path = %q, want /etc/hostname", id.Path)
	}
}

func TestCanonicalPath_ThroughSymlink(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "real.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	a, err := CanonicalPath(target)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalPath(link)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Errorf("symlink and target should resolve to same PathID: a=%v b=%v", a, b)
	}
	if a.Path != target {
		t.Errorf("Path through real file = %q, want %q", a.Path, target)
	}
	if b.Path != target {
		t.Errorf("Path through symlink should resolve to target: got %q, want %q", b.Path, target)
	}
}

func TestCanonicalPath_NotFound(t *testing.T) {
	_, err := CanonicalPath("/no/such/path/exists/under/the/sun")
	if err == nil {
		t.Fatal("expected error for missing path")
	}
	if _, ok := err.(PathNotFound); !ok {
		t.Errorf("expected PathNotFound, got %T: %v", err, err)
	}
}

func TestCanonicalPath_EmptyInput(t *testing.T) {
	if _, err := CanonicalPath(""); err == nil {
		t.Error("empty path should error")
	}
}

func TestProcExePath_Self(t *testing.T) {
	id, err := ProcExePath(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("ProcExePath(self): %v", err)
	}
	if !id.IsValid() {
		t.Errorf("self exe PathID invalid: %+v", id)
	}
	if !filepath.IsAbs(id.Path) {
		t.Errorf("exe path should be absolute, got %q", id.Path)
	}
}

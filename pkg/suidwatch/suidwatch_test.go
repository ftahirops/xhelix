package suidwatch

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompareEmpty(t *testing.T) {
	d := Compare(Snapshot{}, Snapshot{})
	if !d.IsEmpty() {
		t.Fatalf("expected empty diff; got %+v", d)
	}
}

func TestCompareAdditions(t *testing.T) {
	base := Snapshot{}
	cur := Snapshot{Entries: []Entry{
		{Path: "/usr/bin/passwd", HasSUID: true},
		{Path: "/usr/bin/wall", HasSGID: true},
	}}
	d := Compare(base, cur)
	if len(d.Added) != 2 {
		t.Fatalf("added = %d, want 2", len(d.Added))
	}
	if d.Added[0].Path != "/usr/bin/passwd" || d.Added[1].Path != "/usr/bin/wall" {
		t.Fatalf("not sorted: %+v", d.Added)
	}
}

func TestCompareRemovals(t *testing.T) {
	base := Snapshot{Entries: []Entry{{Path: "/old", HasSUID: true}}}
	cur := Snapshot{}
	d := Compare(base, cur)
	if len(d.Removed) != 1 {
		t.Fatalf("removed = %d, want 1", len(d.Removed))
	}
}

func TestCompareModifications(t *testing.T) {
	base := Snapshot{Entries: []Entry{
		{Path: "/usr/bin/sudo", SHA256: "old", Size: 100, HasSUID: true},
	}}
	cur := Snapshot{Entries: []Entry{
		{Path: "/usr/bin/sudo", SHA256: "new", Size: 110, HasSUID: true},
	}}
	d := Compare(base, cur)
	if len(d.Modified) != 1 {
		t.Fatalf("modified = %d, want 1", len(d.Modified))
	}
	if d.Modified[0].Old.SHA256 != "old" || d.Modified[0].New.SHA256 != "new" {
		t.Fatalf("modified entry: %+v", d.Modified[0])
	}
}

func TestCompareFallsBackToSizeMode(t *testing.T) {
	base := Snapshot{Entries: []Entry{
		{Path: "/x", Mode: 0o4755, Size: 100, HasSUID: true},
	}}
	cur := Snapshot{Entries: []Entry{
		{Path: "/x", Mode: 0o4755, Size: 200, HasSUID: true},
	}}
	d := Compare(base, cur)
	if len(d.Modified) != 1 {
		t.Fatalf("expected size-based modification")
	}
}

func TestWalkFindsSUIDFile(t *testing.T) {
	root := t.TempDir()
	suidBin := filepath.Join(root, "fakesudo")
	if err := os.WriteFile(suidBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(suidBin, 0o4755); err != nil {
		t.Skipf("cannot set setuid in test env: %v", err)
	}
	// Some tmpfs / nosuid mounts silently drop the setuid bit.
	if info, err := os.Stat(suidBin); err == nil && info.Mode()&os.ModeSetuid == 0 {
		t.Skip("test filesystem does not preserve setuid bit (likely nosuid mount)")
	}
	snap, err := Walk(WalkConfig{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Entries) == 0 {
		t.Fatalf("walker missed SUID file under %s", root)
	}
	if !snap.Entries[0].HasSUID {
		t.Errorf("HasSUID = false on a setuid file")
	}
	if snap.Entries[0].SHA256 == "" {
		t.Errorf("SHA256 missing on small regular file")
	}
}

func TestWalkSkipsNonSUID(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "plain"), []byte("ok"), 0o755)
	snap, _ := Walk(WalkConfig{Roots: []string{root}})
	if len(snap.Entries) != 0 {
		t.Fatalf("plain file should be ignored; got %+v", snap.Entries)
	}
}

func TestWalkDefaultRoots(t *testing.T) {
	// Just confirm it doesn't error on real roots (best-effort
	// — outputs depend on host).
	_, err := Walk(WalkConfig{})
	if err != nil {
		t.Fatalf("walking default roots failed: %v", err)
	}
}

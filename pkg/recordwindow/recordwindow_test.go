package recordwindow

import (
	"path/filepath"
	"testing"
)

func TestFlagToggleAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record_window")

	f := New(path)
	if f.Open() {
		t.Fatal("fresh flag (no file) should be closed")
	}

	if err := f.SetOpen(true); err != nil {
		t.Fatal(err)
	}
	if !f.Open() {
		t.Error("after SetOpen(true), Open should be true")
	}

	// A second Flag on the same path (simulating a restart) must observe the
	// open state from the file.
	f2 := New(path)
	if !f2.Open() {
		t.Error("state should persist across construction via the control file")
	}

	if err := f.SetOpen(false); err != nil {
		t.Fatal(err)
	}
	if f.Open() {
		t.Error("after SetOpen(false), Open should be false")
	}
	// f2 still caches the old value until it refreshes.
	if !f2.Open() {
		t.Error("f2 cache should be stale-open until Refresh")
	}
	if f2.Refresh() {
		t.Error("after Refresh, f2 should observe the closed state")
	}
}

func TestSetOpenFalseWhenAlreadyClosedIsNoError(t *testing.T) {
	f := New(filepath.Join(t.TempDir(), "record_window"))
	if err := f.SetOpen(false); err != nil {
		t.Errorf("closing an already-closed window should not error: %v", err)
	}
}

func TestNilFlagSafe(t *testing.T) {
	var f *Flag
	if f.Open() {
		t.Error("nil flag must read closed")
	}
	if f.Refresh() {
		t.Error("nil flag Refresh must be false")
	}
	if err := f.SetOpen(true); err != nil {
		t.Errorf("nil flag SetOpen must be a no-op: %v", err)
	}
}

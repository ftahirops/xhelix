package integrity

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestBaseline(t *testing.T) *Baseline {
	t.Helper()
	b, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestUpsertAndLookup(t *testing.T) {
	b := newTestBaseline(t)
	r := Row{
		Path: "/usr/bin/ls", SHA256: "abc123",
		Size: 100, MtimeUnix: 1000, Source: SourceTOFU,
	}
	if err := b.Upsert(r); err != nil {
		t.Fatal(err)
	}
	got, ok, err := b.Lookup("/usr/bin/ls")
	if err != nil || !ok {
		t.Fatalf("lookup: err=%v ok=%v", err, ok)
	}
	if got.SHA256 != "abc123" || got.Source != SourceTOFU {
		t.Errorf("row wrong: %+v", got)
	}
	if got.AddedAt.IsZero() {
		t.Error("AddedAt should be set")
	}
}

func TestUpsertPreservesHigherTrustSource(t *testing.T) {
	b := newTestBaseline(t)
	// First: pkg-mgr verified.
	_ = b.Upsert(Row{Path: "/usr/bin/ls", SHA256: "v1", Size: 100, MtimeUnix: 1, Source: SourcePkgMgr})
	// Then: TOFU attempts to "downgrade" — must NOT overwrite source.
	_ = b.Upsert(Row{Path: "/usr/bin/ls", SHA256: "v2", Size: 200, MtimeUnix: 2, Source: SourceTOFU})
	got, _, _ := b.Lookup("/usr/bin/ls")
	if got.Source != SourcePkgMgr {
		t.Errorf("source should stay pkg-mgr (higher trust), got %s", got.Source)
	}
	if got.SHA256 != "v2" {
		t.Errorf("SHA should update (new hash post-upgrade), got %s", got.SHA256)
	}
}

func TestUpsertAcceptsHigherTrustUpgrade(t *testing.T) {
	b := newTestBaseline(t)
	_ = b.Upsert(Row{Path: "/usr/bin/ls", SHA256: "v1", Size: 100, MtimeUnix: 1, Source: SourceTOFU})
	_ = b.Upsert(Row{Path: "/usr/bin/ls", SHA256: "v2", Size: 200, MtimeUnix: 2, Source: SourcePkgMgr})
	got, _, _ := b.Lookup("/usr/bin/ls")
	if got.Source != SourcePkgMgr {
		t.Errorf("source should upgrade tofu→pkg-mgr, got %s", got.Source)
	}
}

func TestLookupMissingPath(t *testing.T) {
	b := newTestBaseline(t)
	_, ok, err := b.Lookup("/does/not/exist")
	if err != nil {
		t.Errorf("missing path should not error: %v", err)
	}
	if ok {
		t.Error("missing path should not be found")
	}
}

func TestPerSource(t *testing.T) {
	b := newTestBaseline(t)
	_ = b.Upsert(Row{Path: "/a", SHA256: "x", Source: SourcePkgMgr})
	_ = b.Upsert(Row{Path: "/b", SHA256: "x", Source: SourcePkgMgr})
	_ = b.Upsert(Row{Path: "/c", SHA256: "x", Source: SourceTOFU})
	counts, err := b.PerSource()
	if err != nil {
		t.Fatal(err)
	}
	if counts[SourcePkgMgr] != 2 || counts[SourceTOFU] != 1 {
		t.Errorf("counts wrong: %+v", counts)
	}
}

func TestForgetRemovesRow(t *testing.T) {
	b := newTestBaseline(t)
	_ = b.Upsert(Row{Path: "/foo", SHA256: "x", Source: SourceTOFU})
	if err := b.Forget("/foo"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := b.Lookup("/foo"); ok {
		t.Error("row still present after Forget")
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash, size, mt, err := HashFile(p, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if hash != "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03" {
		t.Errorf("hash of 'hello\\n' wrong: %s", hash)
	}
	if size != 6 {
		t.Errorf("size wrong: %d", size)
	}
	if mt.After(time.Now()) {
		t.Errorf("mtime in future: %v", mt)
	}
}

func TestHashFileRejectsTooLarge(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big")
	_ = os.WriteFile(p, []byte("aaaaaaaa"), 0o644)
	_, _, _, err := HashFile(p, 4)
	if err == nil {
		t.Error("HashFile should reject file larger than cap")
	}
}

func TestHashFileRejectsNonRegular(t *testing.T) {
	dir := t.TempDir()
	// Symlinks are not regular files (HashFile follows then checks
	// the resolved target via os.Stat which dereferences); test the
	// case of a directory.
	_, _, _, err := HashFile(dir, 1<<30)
	if err == nil {
		t.Error("HashFile should reject directories")
	}
}

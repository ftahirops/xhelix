package integrity

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildPopulatesBaseline(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"ls", "cat", "echo"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\necho "+name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	b := newTestBaseline(t)
	pr, err := Build(context.Background(), b, WalkOptions{Paths: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	if pr.FilesHashed != 3 {
		t.Errorf("FilesHashed = %d want 3", pr.FilesHashed)
	}
	for _, name := range []string{"ls", "cat", "echo"} {
		_, ok, _ := b.Lookup(filepath.Join(dir, name))
		if !ok {
			t.Errorf("%s not in baseline", name)
		}
	}
	n, _ := b.Count()
	if n != 3 {
		t.Errorf("Count=%d want 3", n)
	}
}

func TestBuildIdempotent(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "ls"), []byte("x"), 0o755)
	b := newTestBaseline(t)
	_, _ = Build(context.Background(), b, WalkOptions{Paths: []string{dir}})
	_, _ = Build(context.Background(), b, WalkOptions{Paths: []string{dir}})
	n, _ := b.Count()
	if n != 1 {
		t.Errorf("second build should not duplicate; Count=%d", n)
	}
}

func TestBuildPreservesPkgMgrSource(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ls")
	_ = os.WriteFile(p, []byte("x"), 0o755)
	b := newTestBaseline(t)
	// Operator pre-seeded with pkg-mgr source.
	_ = b.Upsert(Row{Path: p, SHA256: "stale", Source: SourcePkgMgr})
	_, _ = Build(context.Background(), b, WalkOptions{Paths: []string{dir}})
	row, _, _ := b.Lookup(p)
	if row.Source != SourcePkgMgr {
		t.Errorf("walker should not downgrade pkg-mgr to TOFU; got %s", row.Source)
	}
	// SHA should be refreshed though.
	if row.SHA256 == "stale" {
		t.Error("walker should refresh SHA even when keeping source")
	}
}

func TestBuildSkipsNonRegular(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "real"), []byte("x"), 0o755)
	_ = os.Symlink("/nowhere", filepath.Join(dir, "link"))
	b := newTestBaseline(t)
	pr, _ := Build(context.Background(), b, WalkOptions{Paths: []string{dir}})
	if pr.FilesHashed != 1 {
		t.Errorf("FilesHashed = %d, want 1 (symlink skipped)", pr.FilesHashed)
	}
}

func TestBuildSkipsBoringExtensions(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "ls"), []byte("x"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "image.png"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "notes.md"), []byte("x"), 0o644)
	b := newTestBaseline(t)
	pr, _ := Build(context.Background(), b, WalkOptions{Paths: []string{dir}})
	if pr.FilesHashed != 1 {
		t.Errorf("FilesHashed = %d, want 1", pr.FilesHashed)
	}
}

func TestBuildHonorsContextCancellation(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 50; i++ {
		_ = os.WriteFile(filepath.Join(dir, "f"+string(rune('a'+i%26))+string(rune('a'+i/26))), []byte("xxx"), 0o644)
	}
	b := newTestBaseline(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled
	_, _ = Build(ctx, b, WalkOptions{Paths: []string{dir}, Workers: 1})
	// Some files may have been processed before cancel propagated; we
	// just verify we didn't process all 50.
	n, _ := b.Count()
	if n >= 50 {
		t.Errorf("expected partial run; got Count=%d", n)
	}
}

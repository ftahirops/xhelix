package diskwarden

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDirSize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b"), []byte("world!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := dirSize(dir); n != 12 {
		t.Errorf("dirSize=%d want 12", n)
	}
}

func TestGzipYesterdayCompressesAndRemovesUncompressed(t *testing.T) {
	state := t.TempDir()
	rollupDir := filepath.Join(state, "egress-analytics")
	_ = os.MkdirAll(rollupDir, 0o755)
	// Yesterday's file (NOT today)
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02") + ".jsonl"
	_ = os.WriteFile(filepath.Join(rollupDir, yesterday),
		[]byte(`{"a":1}`+"\n"+`{"b":2}`+"\n"), 0o644)
	// Today's file MUST NOT be touched
	today := time.Now().UTC().Format("2006-01-02") + ".jsonl"
	_ = os.WriteFile(filepath.Join(rollupDir, today), []byte(`{"c":3}`+"\n"), 0o644)

	w := New(Config{StateDir: state, LogDir: t.TempDir(), Log: slog.Default()})
	reclaimed := w.gzipYesterdayRollup()
	if reclaimed <= 0 {
		// gzip of 14 bytes can result in larger output due to header;
		// we just check that we didn't crash + yesterday now has .gz
	}
	if _, err := os.Stat(filepath.Join(rollupDir, yesterday)); !os.IsNotExist(err) {
		t.Errorf("uncompressed yesterday file should be removed")
	}
	if _, err := os.Stat(filepath.Join(rollupDir, yesterday+".gz")); err != nil {
		t.Errorf("gz file should exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rollupDir, today)); err != nil {
		t.Errorf("today's file must NOT be removed")
	}
}

func TestDeleteOldRollupsRespectsRetention(t *testing.T) {
	state := t.TempDir()
	rollupDir := filepath.Join(state, "egress-analytics")
	_ = os.MkdirAll(rollupDir, 0o755)
	old := filepath.Join(rollupDir, "2020-01-01.jsonl.gz")
	recent := filepath.Join(rollupDir, "2099-01-01.jsonl.gz")
	_ = os.WriteFile(old, []byte("x"), 0o644)
	_ = os.WriteFile(recent, []byte("x"), 0o644)
	// Backdate the old file.
	oldT := time.Now().AddDate(0, 0, -90)
	_ = os.Chtimes(old, oldT, oldT)
	w := New(Config{StateDir: state, RetentionDays: 30, Log: slog.Default()})
	reclaimed := w.deleteOldRollups()
	if reclaimed != 1 {
		t.Errorf("want 1 byte reclaimed (the old file); got %d", reclaimed)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old file should be deleted")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Errorf("recent file should survive: %v", err)
	}
}

func TestTickRunsWithoutErrorOnEmptyState(t *testing.T) {
	w := New(Config{StateDir: t.TempDir(), LogDir: t.TempDir(), Log: slog.Default()})
	w.Tick(context.Background())
	s := w.Stats()
	if s.Runs != 1 {
		t.Errorf("Runs=%d want 1", s.Runs)
	}
}

func TestFreePercentReturnsSensible(t *testing.T) {
	p := freePercentFor("/")
	if p < 0 || p > 100 {
		t.Errorf("free percent should be 0-100, got %d", p)
	}
}

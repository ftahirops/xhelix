package egressmon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/destclass"
)

func TestRollupWritesAndReads(t *testing.T) {
	dir := t.TempDir()
	c := destclass.New()
	obs := New(c, time.Minute)
	obs.Observe(LineageID(1), net.ParseIP("8.8.8.8"), "github.com", 443)
	obs.ObserveBytes(LineageID(1), net.ParseIP("8.8.8.8"), "github.com", 443, 1234)

	r := NewRollup(obs, dir, 100*time.Millisecond, "test-host")
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// Let the immediate write happen.
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	today := time.Now().UTC().Format("2006-01-02")
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(files) != 1 || filepath.Base(files[0]) != today+".jsonl" {
		t.Fatalf("expected exactly one daily file %s.jsonl; got %v", today, files)
	}
	recs, err := LoadDay(dir, today)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("LoadDay returned no records")
	}
	found := false
	for _, rec := range recs {
		if rec.Host != "test-host" {
			t.Errorf("host stamping wrong: %s", rec.Host)
		}
		if rec.Stats.LineageID == LineageID(1) && rec.Stats.TotalBytesOut == 1234 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected record for lineage 1 with bytes 1234; got %d records", len(recs))
	}
}

func TestLoadDayMissingFileIsNotError(t *testing.T) {
	dir := t.TempDir()
	recs, err := LoadDay(dir, "1999-01-01")
	if err != nil {
		t.Errorf("missing day file should not error; got %v", err)
	}
	if recs != nil {
		t.Errorf("missing day should yield nil records; got %d", len(recs))
	}
}

func TestRollupCreatesDir(t *testing.T) {
	tmp := t.TempDir()
	subdir := filepath.Join(tmp, "deep/path/here")
	c := destclass.New()
	obs := New(c, time.Minute)
	r := NewRollup(obs, subdir, time.Second, "")
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start should mkdir: %v", err)
	}
	cancel()
	if _, err := os.Stat(subdir); err != nil {
		t.Errorf("dir not created: %v", err)
	}
}

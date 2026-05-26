package chain

import (
	"crypto/ed25519"
	"os"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// TestRotation_CapsBatchCount verifies the MaxBatches rotation logic
// added 2026-05-24 to close the unbounded-growth bug that produced
// 5571 batches / 20GB in 28h on the dev host. After this test, callers
// MUST set MaxBatches in production configurations.
func TestRotation_CapsBatchCount(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(nil)
	c, err := New(dir, priv)
	if err != nil {
		t.Fatal(err)
	}
	c.MaxBatches = 5
	c.BatchCap = 1 // finalise on every event

	for i := 0; i < 20; i++ {
		ev := model.NewEvent("test", model.SeverityInfo)
		ev.Time = time.Now().UTC()
		if err := c.Add(ev); err != nil {
			t.Fatal(err)
		}
	}

	entries, _ := os.ReadDir(dir)
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			count++
		}
	}
	if count > 5 {
		t.Errorf("rotation failed: %d files, MaxBatches=5", count)
	}
	if count < 4 {
		t.Errorf("over-rotated: only %d files", count)
	}
}

func TestRotation_ZeroMaxBatchesIsUnbounded(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(nil)
	c, _ := New(dir, priv)
	c.MaxBatches = 0 // unbounded
	c.BatchCap = 1

	for i := 0; i < 10; i++ {
		ev := model.NewEvent("test", model.SeverityInfo)
		ev.Time = time.Now().UTC()
		c.Add(ev)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 10 {
		t.Errorf("zero MaxBatches must keep all files; got %d", len(entries))
	}
}

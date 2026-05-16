package chain

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestChainRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	c, err := New(dir, priv)
	if err != nil {
		t.Fatal(err)
	}
	c.BatchCap = 3 // force finalisation after 3 events

	for i := 0; i < 7; i++ {
		ev := model.NewEvent("test", model.SeverityInfo)
		ev.Time = time.Now().Add(time.Duration(i) * time.Millisecond)
		ev.Tags["i"] = string(rune('0' + i))
		if err := c.Add(ev); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if err := c.Tick(); err != nil {
		t.Fatal(err)
	}

	// Should have 3 batches: 3+3+1.
	files, err := batchFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Errorf("batch files = %d, want 3", len(files))
	}

	verified, err := Verify(dir, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified != 3 {
		t.Errorf("verified = %d, want 3", verified)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, _ := New(dir, priv)
	c.BatchCap = 2

	for i := 0; i < 4; i++ {
		ev := model.NewEvent("test", model.SeverityInfo)
		ev.Time = time.Now().Add(time.Duration(i) * time.Millisecond)
		_ = c.Add(ev)
	}
	_ = c.Tick()

	files, _ := batchFiles(dir)
	if len(files) < 2 {
		t.Fatalf("not enough batches to test")
	}

	// Corrupt the first batch body by appending a byte.
	body, _ := os.ReadFile(files[0])
	body[len(body)-1] ^= 0xFF
	_ = os.WriteFile(files[0], body, 0o600)

	if _, err := Verify(dir, pub); err == nil {
		t.Error("expected verification failure after tampering")
	}
}

func TestChainResumes(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// First run: write 2 batches.
	c, _ := New(dir, priv)
	c.BatchCap = 2
	for i := 0; i < 4; i++ {
		ev := model.NewEvent("test", model.SeverityInfo)
		_ = c.Add(ev)
	}
	_ = c.Close()

	// Second run: open the same dir; nextBatchID should pick up.
	c2, err := New(dir, priv)
	if err != nil {
		t.Fatal(err)
	}
	if c2.nextBatchID != 2 {
		t.Errorf("nextBatchID = %d, want 2", c2.nextBatchID)
	}

	// Add another batch and verify the whole chain.
	c2.BatchCap = 2
	for i := 0; i < 2; i++ {
		_ = c2.Add(model.NewEvent("test", model.SeverityInfo))
	}
	_ = c2.Close()

	files, _ := batchFiles(dir)
	if len(files) != 3 {
		t.Errorf("files = %d, want 3", len(files))
	}
	verified, err := Verify(dir, pub)
	if err != nil {
		t.Fatalf("verify after resume: %v", err)
	}
	if verified != 3 {
		t.Errorf("verified = %d, want 3", verified)
	}

	// Tidy.
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		return nil
	})
}

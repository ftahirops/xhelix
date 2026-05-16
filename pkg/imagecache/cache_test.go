package imagecache

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestComputeHashesAndCaches(t *testing.T) {
	c, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	dir := t.TempDir()
	bin := filepath.Join(dir, "test-bin")
	if err := os.WriteFile(bin, []byte("hello world\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	img, err := c.Compute(ctx, bin)
	if err != nil {
		t.Fatal(err)
	}
	// "hello world\n" -> known sha256
	want := "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
	if img.SHA256 != want {
		t.Errorf("sha = %q, want %q", img.SHA256, want)
	}

	// Second compute (no mtime change) should hit the cache.
	img2, err := c.Compute(ctx, bin)
	if err != nil {
		t.Fatal(err)
	}
	if img2.SHA256 != want {
		t.Errorf("cached sha = %q", img2.SHA256)
	}

	// Lookup should also find it.
	st, _ := os.Stat(bin)
	got, ok := c.Lookup(bin, st.ModTime())
	if !ok {
		t.Fatal("Lookup miss")
	}
	if got.SHA256 != want {
		t.Errorf("lookup sha = %q", got.SHA256)
	}
}

package fim

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildAndVerify(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "etc")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"passwd":         "root:x:0:0:root:/root:/bin/bash\n",
		"shadow":         "root:!:19000:0:99999:7:::\n",
		"ld.so.preload":  "",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(target, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	bs, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()

	ctx := context.Background()
	n, err := bs.Build(ctx, []string{target})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("built %d, want 3", n)
	}

	// No drift expected immediately.
	if drifts, err := bs.Verify(ctx, nil); err != nil {
		t.Fatal(err)
	} else if len(drifts) != 0 {
		t.Errorf("unexpected drift: %+v", drifts)
	}

	// Modify passwd; verify catches it.
	if err := os.WriteFile(filepath.Join(target, "passwd"),
		[]byte("root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/sh\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	drifts, err := bs.Verify(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(drifts) != 1 {
		t.Fatalf("drift count = %d, want 1", len(drifts))
	}
	if drifts[0].Reason != "sha-mismatch" {
		t.Errorf("reason = %q, want sha-mismatch", drifts[0].Reason)
	}
}

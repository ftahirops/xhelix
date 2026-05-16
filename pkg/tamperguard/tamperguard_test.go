package tamperguard

import (
	"os"
	"sync"
	"testing"
	"time"
)

func TestBinaryMtimeChange(t *testing.T) {
	dir := t.TempDir()
	bin := dir + "/fake-xhelix"
	if err := os.WriteFile(bin, []byte("\x7fELF"), 0o755); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var fires []string
	g := New(Config{
		Interval:   10 * time.Millisecond,
		BinaryPath: bin,
		OnAnomaly: func(reason string, _ map[string]string) {
			mu.Lock()
			fires = append(fires, reason)
			mu.Unlock()
		},
	})
	if err := g.captureBaseline(); err != nil {
		t.Fatal(err)
	}

	// Touch the file so mtime advances.
	time.Sleep(10 * time.Millisecond)
	now := time.Now()
	if err := os.Chtimes(bin, now, now); err != nil {
		t.Fatal(err)
	}

	g.tick()
	mu.Lock()
	defer mu.Unlock()
	if len(fires) == 0 {
		t.Fatal("expected mtime tamper alert")
	}
}

func TestRateLimit(t *testing.T) {
	g := New(Config{})
	count := 0
	g.cfg.OnAnomaly = func(_ string, _ map[string]string) { count++ }
	for i := 0; i < 10; i++ {
		g.fire("test_id", "boom", nil)
	}
	if count != 1 {
		t.Errorf("rate-limit failed: count=%d", count)
	}
}

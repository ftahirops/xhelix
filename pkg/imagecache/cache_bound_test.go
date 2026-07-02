package imagecache

import (
	"fmt"
	"testing"
	"time"
)

func TestMemCacheBounded(t *testing.T) {
	c, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Insert well over the cap directly through the accelerator path.
	for i := 0; i < maxMemEntries+20000; i++ {
		key := fmt.Sprintf("/bin/x%d|t", i)
		c.mu.Lock()
		c.putMemLocked(key, &Image{Path: key, Mtime: time.Unix(int64(i), 0)})
		c.mu.Unlock()
	}
	c.mu.RLock()
	n := len(c.mem)
	c.mu.RUnlock()
	if n > maxMemEntries {
		t.Errorf("mem cache unbounded: %d entries > cap %d", n, maxMemEntries)
	}
}

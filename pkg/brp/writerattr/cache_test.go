package writerattr

import (
	"testing"
	"time"
)

func TestRecordAndLookupWithinTTL(t *testing.T) {
	c := NewCache(10, 5*time.Second)
	now := time.Now()
	c.Record("/etc/shadow", Writer{PID: 42, Comm: "dpkg", ExePath: "/usr/bin/dpkg", When: now})
	w, ok := c.Lookup("/etc/shadow", now.Add(time.Second))
	if !ok {
		t.Fatal("lookup within TTL should succeed")
	}
	if w.PID != 42 || w.Comm != "dpkg" {
		t.Errorf("wrong writer recovered: %+v", w)
	}
}

func TestLookupAfterTTLDropsEntry(t *testing.T) {
	c := NewCache(10, 1*time.Second)
	now := time.Now()
	c.Record("/etc/shadow", Writer{PID: 1, When: now})
	if _, ok := c.Lookup("/etc/shadow", now.Add(2*time.Second)); ok {
		t.Error("lookup after TTL should miss")
	}
	if c.Size() != 0 {
		t.Errorf("stale entry not evicted: size=%d", c.Size())
	}
}

func TestRecordOverwritesLatestWriter(t *testing.T) {
	c := NewCache(10, 5*time.Second)
	now := time.Now()
	c.Record("/etc/foo", Writer{PID: 1, Comm: "first", When: now})
	c.Record("/etc/foo", Writer{PID: 2, Comm: "second", When: now.Add(100 * time.Millisecond)})
	w, _ := c.Lookup("/etc/foo", now.Add(200*time.Millisecond))
	if w.Comm != "second" {
		t.Errorf("expected last-writer-wins, got %q", w.Comm)
	}
}

func TestLRUEviction(t *testing.T) {
	c := NewCache(3, time.Minute)
	now := time.Now()
	for i, p := range []string{"/a", "/b", "/c", "/d"} {
		c.Record(p, Writer{PID: uint32(i + 1), When: now})
	}
	if c.Size() != 3 {
		t.Errorf("size=%d, want 3 (max)", c.Size())
	}
	if _, ok := c.Lookup("/a", now); ok {
		t.Error("oldest entry /a should be evicted")
	}
	if _, ok := c.Lookup("/d", now); !ok {
		t.Error("newest entry /d should be present")
	}
}

func TestEmptyPathRejected(t *testing.T) {
	c := NewCache(10, time.Second)
	c.Record("", Writer{PID: 1})
	if c.Size() != 0 {
		t.Error("empty path should not be recorded")
	}
	if _, ok := c.Lookup("", time.Now()); ok {
		t.Error("empty path lookup should miss")
	}
}

func TestSweep(t *testing.T) {
	c := NewCache(10, 1*time.Second)
	now := time.Now()
	c.Record("/old1", Writer{When: now.Add(-10 * time.Second)})
	c.Record("/old2", Writer{When: now.Add(-10 * time.Second)})
	c.Record("/new", Writer{When: now})
	reclaimed := c.Sweep(now)
	if reclaimed != 2 {
		t.Errorf("reclaimed=%d, want 2", reclaimed)
	}
	if c.Size() != 1 {
		t.Errorf("after sweep size=%d, want 1", c.Size())
	}
}

func TestConcurrent(t *testing.T) {
	c := NewCache(1000, time.Minute)
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 200; j++ {
				c.Record("/p", Writer{PID: uint32(id*1000 + j), When: time.Now()})
				c.Lookup("/p", time.Now())
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

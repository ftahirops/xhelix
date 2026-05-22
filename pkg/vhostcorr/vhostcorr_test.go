package vhostcorr

import (
	"testing"
	"time"
)

func TestNoteAndLookup(t *testing.T) {
	c := New(2 * time.Second)
	c.Note(100, "site-a.com")
	host, ok := c.Lookup(100)
	if !ok || host != "site-a.com" {
		t.Errorf("lookup wrong: host=%q ok=%v", host, ok)
	}
}

func TestLookupMissingPid(t *testing.T) {
	c := New(time.Second)
	if _, ok := c.Lookup(999); ok {
		t.Error("Lookup on unknown pid should miss")
	}
}

func TestTTLExpires(t *testing.T) {
	c := New(100 * time.Millisecond)
	t0 := time.Now()
	c.WithClock(func() time.Time { return t0 })
	c.Note(200, "site-b.com")
	c.WithClock(func() time.Time { return t0.Add(300 * time.Millisecond) })
	if _, ok := c.Lookup(200); ok {
		t.Error("expired entry should miss")
	}
}

func TestReplaceNewerEntry(t *testing.T) {
	c := New(time.Second)
	c.Note(300, "site-a.com")
	c.Note(300, "site-b.com")
	h, _ := c.Lookup(300)
	if h != "site-b.com" {
		t.Errorf("newest should win, got %q", h)
	}
}

func TestForgetEvicts(t *testing.T) {
	c := New(time.Second)
	c.Note(400, "site-a.com")
	c.Forget(400)
	if _, ok := c.Lookup(400); ok {
		t.Error("Forget didn't evict")
	}
}

func TestSweepRemovesStale(t *testing.T) {
	c := New(50 * time.Millisecond)
	t0 := time.Now()
	c.WithClock(func() time.Time { return t0 })
	c.Note(500, "stale.com")
	c.Note(501, "stale2.com")
	c.WithClock(func() time.Time { return t0.Add(200 * time.Millisecond) })
	c.Sweep()
	if _, ok := c.Lookup(500); ok {
		t.Error("sweep should remove stale 500")
	}
	if _, ok := c.Lookup(501); ok {
		t.Error("sweep should remove stale 501")
	}
}

func TestZeroPidIgnored(t *testing.T) {
	c := New(time.Second)
	c.Note(0, "x.com")
	if _, ok := c.Lookup(0); ok {
		t.Error("pid 0 should never match")
	}
}

func TestConcurrentNoteLookup(t *testing.T) {
	c := New(time.Second)
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func(pid uint32) {
			for j := 0; j < 500; j++ {
				c.Note(pid, "site.com")
				_, _ = c.Lookup(pid)
			}
			done <- struct{}{}
		}(uint32(i + 1))
	}
	for i := 0; i < 4; i++ {
		<-done
	}
}

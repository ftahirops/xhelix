package flowstats

import (
	"testing"
	"time"
)

func TestAddAndSum(t *testing.T) {
	c := New(time.Minute, 5*time.Second)
	now := time.Now()
	c.Add("/usr/bin/curl", DirOut, 1000, now)
	c.Add("/usr/bin/curl", DirOut, 500, now.Add(time.Second))
	got := c.Sum("/usr/bin/curl", DirOut, now.Add(2*time.Second))
	if got != 1500 {
		t.Errorf("sum=%d want 1500", got)
	}
}

func TestWindowExpiry(t *testing.T) {
	c := New(time.Minute, 5*time.Second)
	now := time.Now()
	c.Add("/bin/x", DirOut, 1000, now)
	// 2 minutes later — window has rolled fully.
	if got := c.Sum("/bin/x", DirOut, now.Add(2*time.Minute)); got != 0 {
		t.Errorf("expired sum=%d want 0", got)
	}
}

func TestSweepRemovesIdle(t *testing.T) {
	c := New(time.Minute, 5*time.Second)
	now := time.Now()
	c.Add("/bin/idle", DirOut, 100, now)
	c.Add("/bin/active", DirOut, 100, now.Add(5*time.Minute))
	d := c.Sweep(now.Add(6 * time.Minute))
	if d != 1 {
		t.Errorf("dropped=%d want 1", d)
	}
}

func TestTopOut(t *testing.T) {
	c := New(time.Minute, 5*time.Second)
	now := time.Now()
	c.Add("/bin/a", DirOut, 100, now)
	c.Add("/bin/b", DirOut, 1000, now)
	c.Add("/bin/c", DirOut, 50, now)
	top := c.TopOut(2, now.Add(time.Second))
	if len(top) != 2 || top[0].Image != "/bin/b" || top[1].Image != "/bin/a" {
		t.Errorf("top=%v want b,a", top)
	}
}

func TestNilCounters(t *testing.T) {
	var c *Counters
	c.Add("x", DirOut, 1, time.Now()) // must not panic
	if got := c.Sum("x", DirOut, time.Now()); got != 0 {
		t.Errorf("nil sum=%d want 0", got)
	}
}

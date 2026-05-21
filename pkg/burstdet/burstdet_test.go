package burstdet

import (
	"testing"
	"time"
)

func TestObserveCrossesThreshold(t *testing.T) {
	c := NewCounter(Threshold{Window: 1 * time.Second, Count: 5, CoolDown: 1 * time.Second})
	start := time.Unix(0, 0)
	for i := 0; i < 4; i++ {
		if cross, _ := c.Observe(99, start.Add(time.Duration(i)*100*time.Millisecond)); cross {
			t.Fatalf("crossed too early at i=%d", i)
		}
	}
	cross, count := c.Observe(99, start.Add(4*100*time.Millisecond))
	if !cross {
		t.Errorf("did not cross at count=5: got count=%d", count)
	}
	if count != 5 {
		t.Errorf("count want 5, got %d", count)
	}
}

func TestCoolDownSuppressesRepeat(t *testing.T) {
	c := NewCounter(Threshold{Window: 10 * time.Second, Count: 3, CoolDown: 30 * time.Second})
	start := time.Unix(0, 0)
	c.Observe(1, start)
	c.Observe(1, start.Add(1*time.Second))
	if cross, _ := c.Observe(1, start.Add(2*time.Second)); !cross {
		t.Fatal("first cross missed")
	}
	// Same PID, same window, more events — must NOT re-cross.
	for i := 0; i < 5; i++ {
		if cross, _ := c.Observe(1, start.Add(time.Duration(3+i)*time.Second)); cross {
			t.Errorf("cooldown violated at i=%d", i)
		}
	}
}

func TestWindowExpiry(t *testing.T) {
	c := NewCounter(Threshold{Window: 2 * time.Second, Count: 3, CoolDown: 30 * time.Second})
	start := time.Unix(0, 0)
	c.Observe(1, start)
	c.Observe(1, start.Add(500*time.Millisecond))
	// After window expires, old entries should drop. 1 entry only.
	_, count := c.Observe(1, start.Add(10*time.Second))
	if count != 1 {
		t.Errorf("window expiry failed: count=%d want 1", count)
	}
}

func TestForgetDropsPID(t *testing.T) {
	c := NewCounter(Threshold{Window: 10 * time.Second, Count: 10, CoolDown: 30 * time.Second})
	c.Observe(7, time.Now())
	if c.Size() != 1 {
		t.Fatal("Observe didn't track")
	}
	c.Forget(7)
	if c.Size() != 0 {
		t.Errorf("Forget didn't drop: size=%d", c.Size())
	}
}

func TestSweepDropsStale(t *testing.T) {
	c := NewCounter(Threshold{Window: 10 * time.Second, Count: 10, CoolDown: 30 * time.Second})
	t0 := time.Unix(0, 0)
	c.Observe(1, t0)
	c.Observe(2, t0.Add(15*time.Second))
	// PID 1 last=0s, PID 2 last=15s. Sweep at t=20s with
	// ageOut=10s → cutoff=10s. PID 1 < 10 → drop; PID 2 > 10 → keep.
	dropped := c.Sweep(t0.Add(20*time.Second), 10*time.Second)
	if dropped != 1 {
		t.Errorf("Sweep dropped %d, want 1", dropped)
	}
	if c.Size() != 1 {
		t.Errorf("Size after sweep = %d, want 1", c.Size())
	}
}

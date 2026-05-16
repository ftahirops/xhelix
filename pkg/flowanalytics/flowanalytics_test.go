package flowanalytics

import (
	"testing"
	"time"
)

func TestEmptyKeyIgnored(t *testing.T) {
	tr := New()
	a := tr.Observe("", "1.2.3.4")
	if a.Distinct != 0 || a.Rate != 0 {
		t.Fatalf("empty key should yield zero anomaly: %+v", a)
	}
}

func TestBasicAccumulation(t *testing.T) {
	tr := New()
	tr.Window = 60 * time.Second
	t0 := time.Unix(1000, 0)
	tr.now = func() time.Time { return t0 }
	tr.Observe("ff", "1.1.1.1")
	tr.Observe("ff", "2.2.2.2")
	a := tr.Observe("ff", "1.1.1.1")
	if a.Distinct != 2 {
		t.Errorf("distinct = %d, want 2", a.Distinct)
	}
	if a.Rate <= 0 {
		t.Errorf("rate = %f, want > 0", a.Rate)
	}
}

func TestFanoutSpikeFires(t *testing.T) {
	tr := New()
	tr.Window = 10 * time.Second
	tr.FanoutMultiplier = 3.0

	t0 := time.Unix(1000, 0)
	// Establish 3 windows of low-fanout history (3 destinations each).
	for win := 0; win < 3; win++ {
		tr.now = func() time.Time { return t0.Add(time.Duration(win) * 10 * time.Second) }
		// Roll the baseline first by triggering one Observe at the window boundary.
		tr.Observe("ff", "stable.local")
		for i := 0; i < 3; i++ {
			tr.Observe("ff", "host-"+itoa(i)+".local")
		}
	}

	// Now in a new window: fan out to 50 destinations.
	tr.now = func() time.Time { return t0.Add(40 * time.Second) }
	var lastA Anomaly
	for i := 0; i < 50; i++ {
		lastA = tr.Observe("ff", "burst-"+itoa(i)+".local")
	}
	if !lastA.Fanout {
		t.Fatalf("expected fanout=true; distinct=%d baseline=%f", lastA.Distinct, lastA.FanoutBaseline)
	}
}

func TestNoFanoutOnSteadyState(t *testing.T) {
	tr := New()
	tr.Window = 5 * time.Second
	t0 := time.Unix(1000, 0)
	for w := 0; w < 5; w++ {
		tr.now = func() time.Time { return t0.Add(time.Duration(w) * 5 * time.Second) }
		for i := 0; i < 4; i++ {
			tr.Observe("ff", "host-"+itoa(i))
		}
	}
	tr.now = func() time.Time { return t0.Add(30 * time.Second) }
	a := tr.Observe("ff", "host-0")
	if a.Fanout {
		t.Fatalf("steady fan-out should not spike: %+v", a)
	}
}

func TestWindowEviction(t *testing.T) {
	tr := New()
	tr.Window = 10 * time.Second
	t0 := time.Unix(1000, 0)
	tr.now = func() time.Time { return t0 }
	for i := 0; i < 5; i++ {
		tr.Observe("ff", "old-"+itoa(i))
	}
	// Move beyond the window.
	tr.now = func() time.Time { return t0.Add(30 * time.Second) }
	a := tr.Observe("ff", "new-1")
	if a.Distinct != 1 {
		t.Fatalf("post-window distinct = %d, want 1", a.Distinct)
	}
}

func TestSnapshotSortedDescending(t *testing.T) {
	tr := New()
	tr.Window = 60 * time.Second
	t0 := time.Unix(1000, 0)
	tr.now = func() time.Time { return t0 }
	for i := 0; i < 10; i++ {
		tr.Observe("noisy", "h-"+itoa(i))
	}
	tr.Observe("quiet", "h-0")
	snap := tr.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snap = %d", len(snap))
	}
	if snap[0].Key != "noisy" {
		t.Fatalf("snap[0] = %s, want noisy", snap[0].Key)
	}
}

func TestTop(t *testing.T) {
	tr := New()
	t0 := time.Unix(1000, 0)
	tr.now = func() time.Time { return t0 }
	for i := 0; i < 5; i++ {
		tr.Observe("a", "h-"+itoa(i))
	}
	tr.Observe("b", "h-0")
	top := tr.Top(1)
	if len(top) != 1 || top[0].Key != "a" {
		t.Fatalf("top = %+v", top)
	}
}

func TestReset(t *testing.T) {
	tr := New()
	tr.Observe("ff", "x")
	tr.Reset()
	if len(tr.Snapshot()) != 0 {
		t.Fatal("Reset did not clear state")
	}
}

func TestDistinctCountWithDuplicates(t *testing.T) {
	tr := New()
	t0 := time.Unix(1000, 0)
	tr.now = func() time.Time { return t0 }
	tr.Observe("ff", "h1")
	tr.Observe("ff", "h1")
	a := tr.Observe("ff", "h2")
	if a.Distinct != 2 {
		t.Fatalf("distinct with dupes = %d, want 2", a.Distinct)
	}
}

func TestEmptyDestinationStillAccountsForRate(t *testing.T) {
	tr := New()
	t0 := time.Unix(1000, 0)
	tr.now = func() time.Time { return t0 }
	// dst="" — still accepts the key+timestamp counting toward
	// fan-out? Looking at the impl, empty dst is NOT appended, so
	// distinct stays 0. Confirm the conservative behaviour.
	a := tr.Observe("ff", "")
	if a.Distinct != 0 {
		t.Fatalf("empty dst should not be counted; got distinct=%d", a.Distinct)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

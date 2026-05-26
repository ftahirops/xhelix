package sshbrute

import (
	"testing"
	"time"
)

func TestDetector_FiresAtThreshold(t *testing.T) {
	d := NewDetector(5, time.Minute, time.Minute)
	now := time.Now()
	for i := 0; i < 4; i++ {
		if obs := d.Observe("203.0.113.5", "root", now.Add(time.Duration(i)*time.Second)); obs.Fired {
			t.Fatalf("fired at %d failures, expected at 5", i+1)
		}
	}
	obs := d.Observe("203.0.113.5", "root", now.Add(5*time.Second))
	if !obs.Fired {
		t.Fatal("did not fire at 5th failure")
	}
	if obs.Failures < 5 {
		t.Errorf("Failures=%d want >=5", obs.Failures)
	}
}

func TestDetector_CooldownSuppresses(t *testing.T) {
	d := NewDetector(3, time.Minute, time.Minute)
	now := time.Now()
	for i := 0; i < 3; i++ {
		d.Observe("198.51.100.7", "root", now.Add(time.Duration(i)*time.Second))
	}
	// First fire happens at the third event.
	fires := 0
	for i := 3; i < 20; i++ {
		if obs := d.Observe("198.51.100.7", "root", now.Add(time.Duration(i)*time.Second)); obs.Fired {
			fires++
		}
	}
	if fires != 0 {
		t.Errorf("cooldown failed: %d extra fires after first", fires)
	}
}

func TestDetector_WindowSlides(t *testing.T) {
	d := NewDetector(5, 10*time.Second, time.Minute)
	now := time.Now()
	// 4 events at t=0
	for i := 0; i < 4; i++ {
		d.Observe("192.0.2.1", "root", now)
	}
	// 5th event 30 seconds later — outside the window, should NOT fire
	obs := d.Observe("192.0.2.1", "root", now.Add(30*time.Second))
	if obs.Fired {
		t.Errorf("fired across the window: %+v", obs)
	}
}

func TestDetector_PerSourceIsolation(t *testing.T) {
	d := NewDetector(3, time.Minute, time.Minute)
	now := time.Now()
	// 2 attempts each from two sources — neither should fire yet.
	for i := 0; i < 2; i++ {
		if obs := d.Observe("198.51.100.1", "alice", now); obs.Fired {
			t.Fatalf("source 1 fired at attempt %d", i+1)
		}
		if obs := d.Observe("198.51.100.2", "bob", now); obs.Fired {
			t.Fatalf("source 2 fired at attempt %d", i+1)
		}
	}
	// Source 1 hits its 3rd failure — should fire.
	obs := d.Observe("198.51.100.1", "alice", now)
	if !obs.Fired || obs.SourceIP != "198.51.100.1" {
		t.Errorf("source 1 should fire at 3rd attempt: %+v", obs)
	}
	// Source 2 still at 2 failures — should NOT fire.
	// (we just bumped it to 3 with the next call, then it fires —
	// only test it stays quiet until then)
	if obs := d.Observe("198.51.100.2", "bob", now); !obs.Fired {
		t.Errorf("source 2 should fire at its own 3rd attempt: %+v", obs)
	}
}

func TestDetector_CapturesUsers(t *testing.T) {
	d := NewDetector(3, time.Minute, time.Minute)
	now := time.Now()
	d.Observe("203.0.113.99", "root", now)
	d.Observe("203.0.113.99", "admin", now)
	obs := d.Observe("203.0.113.99", "ubuntu", now)
	if !obs.Fired {
		t.Fatal("did not fire")
	}
	want := []string{"root", "admin", "ubuntu"}
	for _, u := range want {
		if obs.UserAttempts[u] == 0 {
			t.Errorf("user %q missing from UserAttempts: %v", u, obs.UserAttempts)
		}
	}
}

func TestDetector_SweepRemovesStale(t *testing.T) {
	d := NewDetector(5, time.Second, time.Second)
	now := time.Now()
	d.Observe("198.18.0.1", "root", now)
	if d.Size() != 1 {
		t.Fatalf("Size=%d want 1", d.Size())
	}
	d.Sweep(now.Add(time.Hour))
	if d.Size() != 0 {
		t.Errorf("Size after sweep=%d want 0", d.Size())
	}
}

func TestDetector_EmptySourceIPIgnored(t *testing.T) {
	d := NewDetector(3, time.Minute, time.Minute)
	for i := 0; i < 10; i++ {
		if obs := d.Observe("", "root", time.Now()); obs.Fired {
			t.Errorf("fired on empty source IP")
		}
	}
}

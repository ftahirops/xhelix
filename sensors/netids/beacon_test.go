package netids

import (
	"testing"
	"time"
)

func TestBeaconRegularTrafficScoresHigh(t *testing.T) {
	d := NewBeaconDetector()
	start := time.Now()
	for i := 0; i < 32; i++ {
		d.Observe("10.0.0.1", "203.0.113.5", start.Add(time.Duration(i)*time.Minute))
	}
	last := d.Observe("10.0.0.1", "203.0.113.5", start.Add(33*time.Minute))
	if last < 0.7 {
		t.Errorf("regular beacon score = %.2f, want >= 0.7", last)
	}
}

func TestBeaconIrregularTrafficScoresLow(t *testing.T) {
	d := NewBeaconDetector()
	start := time.Now()
	gaps := []time.Duration{
		2 * time.Second, 47 * time.Second, 800 * time.Millisecond,
		2 * time.Minute, 5 * time.Second, 3 * time.Minute,
		400 * time.Millisecond, 1 * time.Minute, 20 * time.Second,
		90 * time.Second, 5 * time.Second, 11 * time.Minute,
		400 * time.Millisecond, 8 * time.Minute, 3 * time.Second,
		900 * time.Millisecond, 17 * time.Minute, 4 * time.Second,
	}
	cur := start
	var last float64
	for _, g := range gaps {
		cur = cur.Add(g)
		last = d.Observe("10.0.0.1", "192.0.2.5", cur)
	}
	if last > 0.4 {
		t.Errorf("irregular score = %.2f, want <= 0.4", last)
	}
}

func TestNXDOMAINBurst(t *testing.T) {
	d := NewNXDOMAINBurst(10)
	now := time.Now()
	for i := 0; i < 9; i++ {
		if d.Observe("client-a", now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("burst tripped at i=%d", i)
		}
	}
	if !d.Observe("client-a", now.Add(9*time.Second)) {
		t.Fatal("threshold of 10 not tripped")
	}
}

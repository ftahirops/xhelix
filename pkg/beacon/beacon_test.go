package beacon

import (
	"math/rand"
	"testing"
	"time"
)

func TestPeriodicBeaconDetected(t *testing.T) {
	d := New(Config{
		MinSamples:  8,
		MaxJitterCV: 0.35,
		MinSpan:     time.Minute,
	})
	t0 := time.Now()
	r := rand.New(rand.NewSource(1))
	var v *Verdict
	for i := 0; i < 20; i++ {
		// 30s sleep + ±5s jitter: CV ≈ 5/30 ≈ 0.17, well under 0.35
		jitter := time.Duration(r.Intn(10)-5) * time.Second
		ev := Event{
			PID:     1234,
			Comm:    "implant",
			DstIP:   "203.0.113.10",
			DstPort: 443,
			At:      t0.Add(time.Duration(i)*30*time.Second + jitter),
		}
		if got := d.Observe(ev); got != nil && v == nil {
			v = got
		}
	}
	if v == nil {
		t.Fatal("expected a verdict for periodic beacon")
	}
	if v.Comm != "implant" {
		t.Errorf("comm = %q", v.Comm)
	}
	if v.JitterCV > 0.35 {
		t.Errorf("CV = %f, want <0.35", v.JitterCV)
	}
}

func TestBurstyTrafficNotABeacon(t *testing.T) {
	d := New(Config{MinSamples: 8, MaxJitterCV: 0.35, MinSpan: time.Minute})
	t0 := time.Now()
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 30; i++ {
		// random gaps from 0..120s — high CV
		gap := time.Duration(r.Intn(120)) * time.Second
		t0 = t0.Add(gap)
		ev := Event{PID: 1, Comm: "browser", DstIP: "1.1.1.1", DstPort: 443, At: t0}
		if v := d.Observe(ev); v != nil {
			t.Fatalf("false positive on bursty traffic: %+v", v)
		}
	}
}

func TestAllowList(t *testing.T) {
	d := New(Config{
		MinSamples: 4, MaxJitterCV: 0.5, MinSpan: time.Second,
		AllowList: map[string]bool{"169.254.169.254": true},
	})
	t0 := time.Now()
	for i := 0; i < 20; i++ {
		ev := Event{PID: 1, DstIP: "169.254.169.254", DstPort: 80,
			At: t0.Add(time.Duration(i) * time.Second)}
		if v := d.Observe(ev); v != nil {
			t.Fatal("allow-listed dst fired")
		}
	}
}

func TestDedup(t *testing.T) {
	d := New(Config{MinSamples: 4, MaxJitterCV: 0.5, MinSpan: time.Second, IdleTTL: time.Hour})
	t0 := time.Now()
	verdicts := 0
	for i := 0; i < 50; i++ {
		ev := Event{PID: 9, Comm: "x", DstIP: "8.8.8.8", DstPort: 53,
			At: t0.Add(time.Duration(i) * time.Second)}
		if d.Observe(ev) != nil {
			verdicts++
		}
	}
	if verdicts != 1 {
		t.Errorf("expected 1 verdict (de-duped), got %d", verdicts)
	}
}

func TestSweepPurges(t *testing.T) {
	d := New(Config{IdleTTL: time.Minute})
	d.tracks[Key{PID: 1, DstIP: "x"}] = &track{last: time.Now().Add(-2 * time.Hour)}
	d.Sweep(time.Now())
	if len(d.tracks) != 0 {
		t.Error("sweep didn't purge")
	}
}

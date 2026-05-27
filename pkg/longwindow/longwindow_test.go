package longwindow

import (
	"testing"
	"time"
)

func mustOpen(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(":memory:")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return s
}

func TestRecordAndCount(t *testing.T) {
	s := mustOpen(t)
	defer s.Close()
	now := time.Now()
	for i := 0; i < 5; i++ {
		if err := s.Record(now.Add(time.Duration(i)*time.Minute), "g1", "egress", ""); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.Count("egress", "g1", time.Hour, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("count=%d want 5", n)
	}
}

func TestDistinctCount(t *testing.T) {
	s := mustOpen(t)
	defer s.Close()
	now := time.Now()
	ips := []string{"1.1.1.1", "1.1.1.1", "2.2.2.2", "3.3.3.3", "3.3.3.3"}
	for i, ip := range ips {
		_ = s.Record(now.Add(time.Duration(i)*time.Second), "proc:42", "egress_ip", ip)
	}
	n, err := s.DistinctCount("egress_ip", "proc:42", time.Hour, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("distinct=%d want 3", n)
	}
}

func TestSweep(t *testing.T) {
	s := mustOpen(t)
	defer s.Close()
	now := time.Now()
	_ = s.Record(now.Add(-48*time.Hour), "g1", "x", "")
	_ = s.Record(now.Add(-1*time.Hour), "g1", "x", "")
	n, err := s.Sweep(24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("sweep removed=%d want 1", n)
	}
	size, _ := s.Size()
	if size != 1 {
		t.Errorf("post-sweep size=%d want 1", size)
	}
}

func TestPollerFiresOnThreshold(t *testing.T) {
	s := mustOpen(t)
	defer s.Close()
	now := time.Now()
	for i := 0; i < 6; i++ {
		_ = s.Record(now.Add(time.Duration(i)*time.Minute), "proc:9", "egress_ip",
			[]string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6"}[i])
	}
	var hits []Hit
	p := &Poller{
		Store: s,
		Rules: []Rule{{
			ID: "slow_c2_distinct_ips_24h", Tag: "egress_ip", Mode: ModeDistinctValue,
			Window: 24 * time.Hour, Threshold: 5, Severity: "high",
		}},
		Emit: func(h Hit) { hits = append(hits, h) },
	}
	p.evaluate(now.Add(10 * time.Minute))
	if len(hits) != 1 {
		t.Fatalf("hits=%d want 1", len(hits))
	}
	if hits[0].Count != 6 {
		t.Errorf("count=%d want 6", hits[0].Count)
	}

	// Second evaluate within cooldown → suppressed.
	p.evaluate(now.Add(11 * time.Minute))
	if len(hits) != 1 {
		t.Errorf("cooldown failed: hits=%d want 1", len(hits))
	}
}

func TestPollerDoesNotFireBelowThreshold(t *testing.T) {
	s := mustOpen(t)
	defer s.Close()
	now := time.Now()
	_ = s.Record(now, "g1", "x", "v1")
	var hits []Hit
	p := &Poller{
		Store: s,
		Rules: []Rule{{ID: "r1", Tag: "x", Mode: ModeCount, Window: time.Hour, Threshold: 5}},
		Emit:  func(h Hit) { hits = append(hits, h) },
	}
	p.evaluate(now.Add(time.Second))
	if len(hits) != 0 {
		t.Errorf("hits=%d want 0", len(hits))
	}
}

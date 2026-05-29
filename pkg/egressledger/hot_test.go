package egressledger

import (
	"net"
	"sync"
	"testing"
	"time"
)

func mkEvent(ts time.Time, binary, ip string) Event {
	return Event{
		Time:     ts,
		Binary:   binary,
		DestIP:   net.ParseIP(ip),
		DestPort: 443,
		Protocol: "tcp",
		Connect:  true,
		BytesOut: 100,
	}
}

func TestHotRingObserveMerges(t *testing.T) {
	// Exact-IP bucketing: two identical IPs merge; different IPs do not.
	h := newHotRing(time.Minute, 60*time.Minute)
	now := time.Now()
	ev1 := mkEvent(now, "nginx", "203.0.113.1")
	ev2 := mkEvent(now.Add(10*time.Second), "nginx", "203.0.113.1")

	k := FlowKey{Binary: "nginx", DestCIDR: cidr16(ev1.DestIP), DestPort: 443, Protocol: "tcp"}
	h.observe(ev1.Time, k, &ev1)
	h.observe(ev2.Time, k, &ev2)
	snap := h.snapshot()
	if len(snap) != 1 {
		t.Fatalf("want 1 merged row, got %d", len(snap))
	}
	if snap[0].Metrics.Connects != 2 || snap[0].Metrics.BytesOut != 200 {
		t.Fatalf("merge math wrong: %+v", snap[0].Metrics)
	}
}

func TestHotRingSlideEvicts(t *testing.T) {
	h := newHotRing(time.Minute, 5*time.Minute)
	old := time.Now().Add(-30 * time.Minute)
	ev := mkEvent(old, "nginx", "203.0.113.1")
	k := FlowKey{Binary: "nginx", DestCIDR: cidr16(ev.DestIP), DestPort: 443, Protocol: "tcp"}
	h.observe(ev.Time, k, &ev)
	if h.rowsCount() != 1 {
		t.Fatalf("expected 1 row before slide")
	}
	evicted := h.slide(time.Now())
	if len(evicted) != 1 {
		t.Fatalf("expected 1 evicted, got %d", len(evicted))
	}
	if h.rowsCount() != 0 {
		t.Fatalf("expected ring empty after slide, got %d", h.rowsCount())
	}
}

func TestHotRingConcurrentObserve(t *testing.T) {
	h := newHotRing(time.Minute, 60*time.Minute)
	now := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev := mkEvent(now, "nginx", "203.0.113.1")
			k := FlowKey{Binary: "nginx", DestCIDR: cidr16(ev.DestIP), DestPort: 443, Protocol: "tcp"}
			h.observe(ev.Time, k, &ev)
		}(i)
	}
	wg.Wait()
	snap := h.snapshot()
	if len(snap) != 1 {
		t.Fatalf("want 1 merged row, got %d", len(snap))
	}
	if snap[0].Metrics.Connects != 50 {
		t.Fatalf("want 50 connects, got %d", snap[0].Metrics.Connects)
	}
}

func TestHotRingSnapshotRangeFilters(t *testing.T) {
	h := newHotRing(time.Minute, 60*time.Minute)
	base := time.Now().Truncate(time.Hour)
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i) * time.Minute)
		ev := mkEvent(ts, "nginx", "203.0.113.1")
		k := FlowKey{Binary: "nginx", DestCIDR: cidr16(ev.DestIP), DestPort: 443, Protocol: "tcp"}
		h.observe(ts, k, &ev)
	}
	got := h.snapshotRange(base.Add(time.Minute), base.Add(3*time.Minute+30*time.Second))
	if len(got) != 3 {
		t.Fatalf("want 3 rows in 3-minute window, got %d", len(got))
	}
}

package egressledger

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func newTestLedger(t *testing.T, retentionDays int) *Ledger {
	t.Helper()
	dir := t.TempDir()
	l, err := New(Options{
		Dir:           filepath.Join(dir, "el"),
		RetentionDays: retentionDays,
		HotWindow:     time.Minute,
		HotBucket:     10 * time.Second,
		WarmRetention: 2 * time.Hour,
		WarmBucket:    time.Minute,
		ColdBucket:    time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func TestLedgerNilSafe(t *testing.T) {
	var l *Ledger
	l.Observe(Event{Time: time.Now()})
	if got := l.QueryLive(FlowFilter{}); got != nil {
		t.Fatalf("expected nil from nil ledger, got %v", got)
	}
	if got := l.Stats(); got != (Stats{}) {
		t.Fatalf("expected zero Stats from nil ledger, got %+v", got)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("nil Close err: %v", err)
	}
	if err := l.Tick(context.Background()); err != nil {
		t.Fatalf("nil Tick err: %v", err)
	}
}

func TestLedgerObserveQueryLive(t *testing.T) {
	l := newTestLedger(t, 14)
	defer l.Close()

	now := time.Now()
	for i := 0; i < 3; i++ {
		l.Observe(Event{
			Time:     now.Add(time.Duration(i) * time.Second),
			Binary:   "nginx",
			DestIP:   net.ParseIP("203.0.113.1"),
			DestPort: 443,
			Protocol: "tcp",
			Connect:  true,
			BytesOut: 100,
		})
	}
	got := l.QueryLive(FlowFilter{UID: -1, CGroupID: -1, DestPort: -1})
	if len(got) != 1 {
		t.Fatalf("want 1 row, got %d", len(got))
	}
	if got[0].Metrics.Connects != 3 || got[0].Metrics.BytesOut != 300 {
		t.Fatalf("aggregation wrong: %+v", got[0].Metrics)
	}
}

func TestLedgerFilters(t *testing.T) {
	l := newTestLedger(t, 14)
	defer l.Close()
	now := time.Now()
	for _, b := range []string{"nginx", "sshd", "cron"} {
		l.Observe(Event{
			Time:     now,
			Binary:   b,
			DestIP:   net.ParseIP("203.0.113.1"),
			DestPort: 443,
			Protocol: "tcp",
			Connect:  true,
		})
	}
	got := l.QueryLive(FlowFilter{Binary: "ssh", UID: -1, CGroupID: -1, DestPort: -1})
	if len(got) != 1 || got[0].Key.Binary != "sshd" {
		t.Fatalf("filter binary failed: %v", got)
	}
	got = l.QueryLive(FlowFilter{UID: -1, CGroupID: -1, DestPort: 80})
	if len(got) != 0 {
		t.Fatalf("filter port failed, want 0, got %d", len(got))
	}
}

func TestLedgerTickRollsHotToWarm(t *testing.T) {
	l := newTestLedger(t, 14)
	defer l.Close()
	old := time.Now().Add(-30 * time.Minute)
	l.Observe(Event{
		Time:     old,
		Binary:   "nginx",
		DestIP:   net.ParseIP("203.0.113.1"),
		DestPort: 443,
		Protocol: "tcp",
		Connect:  true,
	})
	if err := l.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	// Hot should be empty after slide (HotWindow=1m, event 30m old).
	if got := l.QueryLive(FlowFilter{UID: -1, CGroupID: -1, DestPort: -1}); len(got) != 0 {
		t.Fatalf("expected hot empty after Tick, got %d", len(got))
	}
	// Warm should now have it.
	start := old.Add(-time.Minute)
	end := old.Add(time.Minute)
	rows := l.QueryTimeline(start, end, FlowFilter{UID: -1, CGroupID: -1, DestPort: -1})
	if len(rows) != 1 {
		t.Fatalf("warm tier query returned %d, want 1", len(rows))
	}
}

func TestLedgerStats(t *testing.T) {
	l := newTestLedger(t, 14)
	defer l.Close()
	s := l.Stats()
	if s.RetentionDays != 14 {
		t.Fatalf("retention wrong: %d", s.RetentionDays)
	}
}

func TestLedgerCloseIdempotent(t *testing.T) {
	l := newTestLedger(t, 14)
	if err := l.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

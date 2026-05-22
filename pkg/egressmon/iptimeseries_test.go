package egressmon

import (
	"net"
	"testing"
	"time"
)

func newTestTS(t *testing.T) *IPTimeSeries {
	t.Helper()
	ts, err := NewIPTimeSeries(IPTimeSeriesConfig{DBPath: ":memory:", BucketSize: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ts.Close() })
	return ts
}

func TestRecordAndFlush(t *testing.T) {
	ts := newTestTS(t)
	now := time.Now()
	ts.RecordOut(net.ParseIP("1.2.3.4"), 500, now)
	ts.RecordIn(net.ParseIP("1.2.3.4"), 1500, now)
	ts.RecordOut(net.ParseIP("1.2.3.4"), 250, now)
	if err := ts.Flush(); err != nil {
		t.Fatal(err)
	}
	pts, err := ts.Series(net.ParseIP("1.2.3.4"), now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 1 {
		t.Fatalf("want 1 bucket, got %d", len(pts))
	}
	if pts[0].BytesOut != 750 {
		t.Errorf("BytesOut = %d, want 750", pts[0].BytesOut)
	}
	if pts[0].BytesIn != 1500 {
		t.Errorf("BytesIn = %d, want 1500", pts[0].BytesIn)
	}
}

func TestSeparateBuckets(t *testing.T) {
	ts := newTestTS(t)
	t0 := time.Now()
	ts.RecordOut(net.ParseIP("5.5.5.5"), 100, t0)
	ts.RecordOut(net.ParseIP("5.5.5.5"), 200, t0.Add(2*time.Minute)) // different bucket
	_ = ts.Flush()
	pts, _ := ts.Series(net.ParseIP("5.5.5.5"), t0.Add(-time.Hour), t0.Add(time.Hour))
	if len(pts) != 2 {
		t.Fatalf("want 2 buckets, got %d", len(pts))
	}
}

func TestPendingBucketVisibleBeforeFlush(t *testing.T) {
	ts := newTestTS(t)
	ts.RecordOut(net.ParseIP("9.9.9.9"), 333, time.Now())
	// Don't flush.
	pts, _ := ts.Series(net.ParseIP("9.9.9.9"), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if len(pts) != 1 || pts[0].BytesOut != 333 {
		t.Errorf("pending bucket should appear in Series; got %+v", pts)
	}
}

func TestTopIPs(t *testing.T) {
	ts := newTestTS(t)
	now := time.Now()
	ts.RecordOut(net.ParseIP("1.1.1.1"), 1000, now)
	ts.RecordOut(net.ParseIP("2.2.2.2"), 5000, now)
	ts.RecordOut(net.ParseIP("3.3.3.3"), 100, now)
	_ = ts.Flush()
	top, err := ts.TopIPs(now.Add(-time.Hour), now.Add(time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(top) != 3 {
		t.Fatalf("want 3 IPs, got %d", len(top))
	}
	if top[0].IP != "2.2.2.2" {
		t.Errorf("top should be 2.2.2.2; got %s", top[0].IP)
	}
}

func TestSweepDropsOldRows(t *testing.T) {
	ts, _ := NewIPTimeSeries(IPTimeSeriesConfig{DBPath: ":memory:", BucketSize: time.Minute, RetentionDays: 1})
	defer ts.Close()
	old := time.Now().Add(-48 * time.Hour)
	ts.RecordOut(net.ParseIP("8.8.8.8"), 100, old)
	_ = ts.Flush()
	if err := ts.Sweep(); err != nil {
		t.Fatal(err)
	}
	pts, _ := ts.Series(net.ParseIP("8.8.8.8"), old.Add(-time.Hour), old.Add(time.Hour))
	if len(pts) != 0 {
		t.Errorf("sweep should remove rows older than retention; got %d", len(pts))
	}
}

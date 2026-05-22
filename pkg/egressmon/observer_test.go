package egressmon

import (
	"net"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/destclass"
)

func newTestObserver() *Observer {
	c := destclass.New()
	return New(c, 5*time.Minute)
}

func TestObserveBasic(t *testing.T) {
	o := newTestObserver()
	d := o.Observe(LineageID(1), net.ParseIP("8.8.8.8"), "github.com", 443)
	if d.Class != destclass.ClassDevRegistry {
		t.Fatalf("github.com should be dev_registry, got %s", d.Class)
	}
	snap := o.Snapshot(LineageID(1))
	if len(snap) != 1 {
		t.Fatalf("want 1 snapshot, got %d", len(snap))
	}
	s := snap[0]
	if s.TotalConnects != 1 {
		t.Errorf("TotalConnects=%d want 1", s.TotalConnects)
	}
	if s.ByClass[destclass.ClassDevRegistry] != 1 {
		t.Errorf("ByClass[dev_registry]=%d want 1", s.ByClass[destclass.ClassDevRegistry])
	}
	if s.UniqueDests != 1 {
		t.Errorf("UniqueDests=%d want 1", s.UniqueDests)
	}
}

func TestUniqueDestsAndUnknown(t *testing.T) {
	o := newTestObserver()
	o.Observe(LineageID(2), net.ParseIP("8.8.8.8"), "github.com", 443)
	o.Observe(LineageID(2), net.ParseIP("8.8.8.8"), "github.com", 443) // dup
	o.Observe(LineageID(2), net.ParseIP("1.1.1.1"), "evil.example", 443)
	o.Observe(LineageID(2), net.ParseIP("2.2.2.2"), "another-evil.example", 443)
	s := o.Snapshot(LineageID(2))[0]
	if s.UniqueDests != 3 {
		t.Errorf("UniqueDests=%d want 3", s.UniqueDests)
	}
	if s.UniqueUnknown != 2 {
		t.Errorf("UniqueUnknown=%d want 2", s.UniqueUnknown)
	}
	if s.FirstUnknownAt.IsZero() {
		t.Errorf("FirstUnknownAt should be set after first unknown")
	}
}

func TestFirstIntelBadStamped(t *testing.T) {
	type fakeIntel struct{}
	// Use a small classifier with intel that flags 6.6.6.6
	c := destclass.New(destclass.WithIntel(fakeIntelProvider{bad: "6.6.6.6"}))
	o := New(c, time.Minute)
	o.Observe(LineageID(3), net.ParseIP("8.8.8.8"), "github.com", 443)
	if !o.Snapshot(LineageID(3))[0].FirstIntelBadAt.IsZero() {
		t.Errorf("should not be set before any intel-bad observation")
	}
	o.Observe(LineageID(3), net.ParseIP("6.6.6.6"), "", 443)
	if o.Snapshot(LineageID(3))[0].FirstIntelBadAt.IsZero() {
		t.Errorf("FirstIntelBadAt should be stamped after intel-bad observation")
	}
}

type fakeIntelProvider struct{ bad string }

func (f fakeIntelProvider) IsBad(ip net.IP) bool { return ip.String() == f.bad }

func TestCountClass(t *testing.T) {
	o := newTestObserver()
	o.Observe(LineageID(4), net.ParseIP("8.8.8.8"), "evil.example", 443)
	o.Observe(LineageID(4), net.ParseIP("9.9.9.9"), "another.example", 443)
	o.Observe(LineageID(4), net.ParseIP("8.8.8.8"), "github.com", 443)
	if got := o.CountClass(LineageID(4), destclass.ClassUnknown); got != 2 {
		t.Errorf("CountClass unknown = %d, want 2", got)
	}
	if got := o.CountClass(LineageID(4), destclass.ClassDevRegistry); got != 1 {
		t.Errorf("CountClass dev_registry = %d, want 1", got)
	}
}

func TestForgetClearsState(t *testing.T) {
	o := newTestObserver()
	o.Observe(LineageID(5), net.ParseIP("8.8.8.8"), "github.com", 443)
	if got := len(o.Snapshot(LineageID(5))); got != 1 {
		t.Fatalf("pre-forget snapshot = %d, want 1", got)
	}
	o.Forget(LineageID(5))
	if got := len(o.Snapshot(LineageID(5))); got != 0 {
		t.Errorf("post-forget snapshot = %d, want 0", got)
	}
}

func TestSnapshotAllLineages(t *testing.T) {
	o := newTestObserver()
	o.Observe(LineageID(10), net.ParseIP("8.8.8.8"), "github.com", 443)
	o.Observe(LineageID(11), net.ParseIP("1.1.1.1"), "evil.example", 443)
	all := o.Snapshot(0)
	if len(all) != 2 {
		t.Fatalf("Snapshot(0) returned %d lineages, want 2", len(all))
	}
	if all[0].LineageID > all[1].LineageID {
		t.Errorf("Snapshot(0) should be sorted by lineage id")
	}
}

func TestObserveBytes(t *testing.T) {
	o := newTestObserver()
	o.Observe(LineageID(40), net.ParseIP("8.8.8.8"), "github.com", 443)
	o.ObserveBytes(LineageID(40), net.ParseIP("8.8.8.8"), "github.com", 443, 500)
	o.ObserveBytes(LineageID(40), net.ParseIP("8.8.8.8"), "github.com", 443, 250)
	o.Observe(LineageID(40), net.ParseIP("1.1.1.1"), "evil.example", 443)
	o.ObserveBytes(LineageID(40), net.ParseIP("1.1.1.1"), "evil.example", 443, 9000)
	s := o.Snapshot(LineageID(40))[0]
	if s.TotalBytesOut != 9750 {
		t.Errorf("TotalBytesOut=%d want 9750", s.TotalBytesOut)
	}
	if s.BytesOutByClass[destclass.ClassDevRegistry] != 750 {
		t.Errorf("bytes by dev_registry = %d want 750", s.BytesOutByClass[destclass.ClassDevRegistry])
	}
	if s.BytesOutByClass[destclass.ClassUnknown] != 9000 {
		t.Errorf("bytes by unknown = %d want 9000", s.BytesOutByClass[destclass.ClassUnknown])
	}
}

func TestObserveBytesBeforeClassifyCountsAsUnknown(t *testing.T) {
	o := newTestObserver()
	// Bytes seen before any connect-event Classify call → class=Unknown.
	o.ObserveBytes(LineageID(41), net.ParseIP("8.8.8.8"), "github.com", 443, 1000)
	s := o.Snapshot(LineageID(41))[0]
	if s.BytesOutByClass[destclass.ClassUnknown] != 1000 {
		t.Errorf("orphan bytes should go to Unknown; got %v", s.BytesOutByClass)
	}
}

func TestForensicSamplePrune(t *testing.T) {
	c := destclass.New()
	o := New(c, 100*time.Millisecond)
	t0 := time.Now()
	o.WithClock(func() time.Time { return t0 })
	o.Observe(LineageID(20), net.ParseIP("1.1.1.1"), "github.com", 443)
	o.WithClock(func() time.Time { return t0.Add(200 * time.Millisecond) })
	o.Observe(LineageID(20), net.ParseIP("2.2.2.2"), "npmjs.org", 443)
	s := o.Snapshot(LineageID(20))[0]
	// The first observation should be pruned from the recent sample
	// because it's older than ttl=100ms relative to the new clock.
	if len(s.RecentSample) != 1 {
		t.Errorf("RecentSample after prune = %d, want 1", len(s.RecentSample))
	}
	// Aggregate counters are NOT pruned (we want lifetime stats).
	if s.TotalConnects != 2 {
		t.Errorf("TotalConnects = %d, want 2 (aggregate must survive prune)", s.TotalConnects)
	}
}

func TestConcurrentObserveDoesNotRace(t *testing.T) {
	o := newTestObserver()
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func(lid LineageID) {
			for j := 0; j < 200; j++ {
				o.Observe(lid, net.ParseIP("8.8.8.8"), "github.com", 443)
			}
			done <- struct{}{}
		}(LineageID(i + 100))
	}
	for i := 0; i < 4; i++ {
		<-done
	}
	all := o.Snapshot(0)
	total := 0
	for _, s := range all {
		total += s.TotalConnects
	}
	if total != 4*200 {
		t.Errorf("total connects = %d, want 800", total)
	}
}

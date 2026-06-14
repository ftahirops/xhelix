package contracthealth

import (
	"sort"
	"sync"
	"testing"
	"time"
)

func TestBreaker_TripsOnceAtThreshold(t *testing.T) {
	var trips []int
	b := NewBreaker(time.Minute, 5, func(app string, count int) { trips = append(trips, count) })
	base := time.Unix(1700000000, 0)
	for i := 0; i < 10; i++ {
		b.RecordDeny("app", base.Add(time.Duration(i)*time.Second))
	}
	if !b.Tripped("app") {
		t.Error("expected breaker to be tripped after 10 denies (threshold 5)")
	}
	if len(trips) != 1 {
		t.Errorf("onTrip should fire exactly once (latched), fired %d times", len(trips))
	}
	if trips[0] != 5 {
		t.Errorf("trip count = %d, want 5 (the threshold crossing)", trips[0])
	}
}

func TestBreaker_RollingWindowExpiry(t *testing.T) {
	b := NewBreaker(10*time.Second, 5, nil)
	base := time.Unix(1700000000, 0)
	// 4 denies, then jump past the window — count should reset.
	for i := 0; i < 4; i++ {
		b.RecordDeny("app", base.Add(time.Duration(i)*time.Second))
	}
	later := base.Add(time.Hour)
	if got := b.RecentDenies("app", later); got != 0 {
		t.Errorf("recent denies after window = %d, want 0", got)
	}
	if b.Tripped("app") {
		t.Error("should not be tripped — never reached threshold in window")
	}
}

func TestBreaker_ResetClearsLatch(t *testing.T) {
	b := NewBreaker(time.Minute, 3, nil)
	base := time.Unix(1700000000, 0)
	for i := 0; i < 3; i++ {
		b.RecordDeny("app", base.Add(time.Duration(i)*time.Second))
	}
	if !b.Tripped("app") {
		t.Fatal("setup: should be tripped")
	}
	b.Reset("app")
	if b.Tripped("app") {
		t.Error("Reset should clear the latch")
	}
}

func TestBreaker_ConcurrentRecordNoRace(t *testing.T) {
	b := NewBreaker(time.Minute, 1000, nil)
	base := time.Unix(1700000000, 0)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			b.RecordDeny("app", base.Add(time.Duration(n)*time.Millisecond))
		}(i)
	}
	wg.Wait()
	if got := b.RecentDenies("app", base.Add(time.Second)); got != 50 {
		t.Errorf("concurrent record lost events: got %d, want 50", got)
	}
}

func TestReconciler_DisarmsOrphans(t *testing.T) {
	// app "ghost" is armed on disk but no longer desired (deleted).
	// app "down" is armed but mode downgraded (ShouldArm=false).
	// app "live" is armed and still locked → keep.
	armed := map[string][]string{
		"ghost": {"nginx.service"},
		"down":  {"php-fpm.service"},
		"live":  {"nginx.service"},
	}
	desired := []AppDesired{
		{App: "down", ShouldArm: false, Units: []string{"php-fpm.service"}},
		{App: "live", ShouldArm: true, Units: []string{"nginx.service"}},
	}
	var disarmed []string
	r := NewReconciler(
		func() []AppDesired { return desired },
		func() (map[string][]string, error) { return armed, nil },
		func(app string, units []string) (int, error) {
			disarmed = append(disarmed, app)
			return len(units), nil
		},
		nil, nil,
	)
	rep := r.ReconcileOnce()
	sort.Strings(disarmed)
	if len(disarmed) != 2 || disarmed[0] != "down" || disarmed[1] != "ghost" {
		t.Errorf("expected ghost+down disarmed, got %v", disarmed)
	}
	if len(rep.OrphansDisarmed) != 2 {
		t.Errorf("report should list 2 orphans, got %d", len(rep.OrphansDisarmed))
	}
}

func TestReconciler_FlagsMissingArmAsDrift(t *testing.T) {
	// "live" should be armed on nginx + php-fpm, but only nginx is on disk.
	armed := map[string][]string{"live": {"nginx.service"}}
	desired := []AppDesired{
		{App: "live", ShouldArm: true, Units: []string{"nginx.service", "php-fpm.service"}},
	}
	r := NewReconciler(
		func() []AppDesired { return desired },
		func() (map[string][]string, error) { return armed, nil },
		func(string, []string) (int, error) { return 0, nil },
		nil, nil,
	)
	rep := r.ReconcileOnce()
	if len(rep.MissingArm) != 1 || rep.MissingArm[0].Unit != "php-fpm.service" {
		t.Errorf("expected php-fpm flagged as missing-arm drift, got %v", rep.MissingArm)
	}
	if len(rep.OrphansDisarmed) != 0 {
		t.Errorf("should not disarm a legitimately-armed app, got %v", rep.OrphansDisarmed)
	}
}

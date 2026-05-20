package evidence

import (
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/xhelix/xhelix/pkg/model"
)

func makeAlert(rule, sensor string, t time.Time, sev model.Severity, tags map[string]string) *model.Alert {
	return &model.Alert{
		RuleID: rule,
		Event: model.Event{
			ID:       ulid.MustNew(ulid.Timestamp(t), nil),
			Time:     t,
			Sensor:   sensor,
			Severity: sev,
			CGroupID: 4242,
			Tags:     tags,
		},
	}
}

func TestObserve_NewAndExistingBucket(t *testing.T) {
	a := New(Options{})
	now := time.Now()

	// Three alerts in the same minute, same rule/kind → one bucket.
	for i := 0; i < 3; i++ {
		a.Observe(makeAlert("rule_x", "fim", now.Add(time.Duration(i)*time.Second), model.SeverityNotice, nil))
	}
	snap := a.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(snap))
	}
	if snap[0].Count != 3 {
		t.Errorf("count = %d, want 3", snap[0].Count)
	}
	if len(snap[0].SampleEventIDs) != 3 {
		t.Errorf("sample ids = %d, want 3", len(snap[0].SampleEventIDs))
	}
}

func TestObserve_DifferentMinutes_SeparateBuckets(t *testing.T) {
	a := New(Options{})
	base := time.Now().Truncate(time.Minute)
	a.Observe(makeAlert("rule_x", "fim", base, model.SeverityNotice, nil))
	a.Observe(makeAlert("rule_x", "fim", base.Add(time.Minute), model.SeverityNotice, nil))

	if got := len(a.Snapshot()); got != 2 {
		t.Errorf("two minutes should make two buckets, got %d", got)
	}
}

func TestObserve_SampleCap(t *testing.T) {
	a := New(Options{MaxSamples: 3})
	now := time.Now()
	for i := 0; i < 10; i++ {
		a.Observe(makeAlert("rule_x", "fim", now.Add(time.Duration(i)*time.Millisecond), model.SeverityNotice, nil))
	}
	snap := a.Snapshot()
	if len(snap[0].SampleEventIDs) != 3 {
		t.Errorf("samples capped to MaxSamples=3, got %d", len(snap[0].SampleEventIDs))
	}
	if snap[0].Count != 10 {
		t.Errorf("count = %d, want 10 (samples cap shouldn't affect count)", snap[0].Count)
	}
}

func TestObserve_TracksMaxSeverity(t *testing.T) {
	a := New(Options{})
	now := time.Now()
	a.Observe(makeAlert("r", "s", now, model.SeverityNotice, nil))
	a.Observe(makeAlert("r", "s", now, model.SeverityCritical, nil))
	a.Observe(makeAlert("r", "s", now, model.SeverityNotice, nil))

	snap := a.Snapshot()
	if snap[0].MaxSeverity != model.SeverityCritical {
		t.Errorf("MaxSeverity = %v, want critical", snap[0].MaxSeverity)
	}
}

func TestObserve_NilAndEmptyRule(t *testing.T) {
	a := New(Options{})
	if a.Observe(nil) != nil {
		t.Error("nil alert should be ignored")
	}
	if a.Observe(makeAlert("", "fim", time.Now(), model.SeverityNotice, nil)) != nil {
		t.Error("empty RuleID should be ignored")
	}
}

func TestObserve_KeyDimensions(t *testing.T) {
	a := New(Options{})
	now := time.Now()

	// Same rule + sensor, different cgroup → different buckets.
	a1 := makeAlert("r", "fim", now, model.SeverityNotice, nil)
	a1.Event.CGroupID = 1
	a.Observe(a1)
	a2 := makeAlert("r", "fim", now, model.SeverityNotice, nil)
	a2.Event.CGroupID = 2
	a.Observe(a2)

	if got := len(a.Snapshot()); got != 2 {
		t.Errorf("different cgroup → two buckets, got %d", got)
	}

	// Same rule + sensor + cgroup, different exe_sha tag → different buckets.
	a.Observe(makeAlert("r2", "fim", now, model.SeverityNotice, map[string]string{"exe_sha": "abc"}))
	a.Observe(makeAlert("r2", "fim", now, model.SeverityNotice, map[string]string{"exe_sha": "def"}))

	// Now total = 4 (2 cgroups + 2 exe_shas).
	if got := len(a.Snapshot()); got != 4 {
		t.Errorf("different exe_sha → two more buckets, got %d total", got)
	}
}

func TestSweep_RemovesStaleNonPromoted(t *testing.T) {
	a := New(Options{})
	old := time.Now().Add(-2 * time.Hour)
	fresh := time.Now()

	a.Observe(makeAlert("old_rule", "s", old, model.SeverityNotice, nil))
	a.Observe(makeAlert("fresh_rule", "s", fresh, model.SeverityNotice, nil))

	n := a.Sweep(time.Now().Add(-time.Hour))
	if n != 1 {
		t.Errorf("swept = %d, want 1", n)
	}
	snap := a.Snapshot()
	if len(snap) != 1 || snap[0].RuleID != "fresh_rule" {
		t.Errorf("after sweep: %+v, want fresh_rule only", snap)
	}
}

func TestSweep_PreservesPromoted(t *testing.T) {
	a := New(Options{})
	old := time.Now().Add(-2 * time.Hour)
	a.Observe(makeAlert("important", "s", old, model.SeverityCritical, nil))

	snap := a.Snapshot()
	a.Promote(snap[0].Key)

	n := a.Sweep(time.Now().Add(-time.Hour))
	if n != 0 {
		t.Errorf("promoted bucket should not be swept, swept=%d", n)
	}
	if len(a.Snapshot()) != 1 {
		t.Error("promoted bucket disappeared")
	}
}

func TestEviction_AtCapacityDropsOldest(t *testing.T) {
	a := New(Options{MaxBuckets: 3})
	base := time.Now()
	// Distinct windows so each is its own bucket.
	for i := 0; i < 5; i++ {
		a.Observe(makeAlert("r", "s", base.Add(time.Duration(i)*time.Minute), model.SeverityNotice, nil))
	}
	if got := len(a.Snapshot()); got != 3 {
		t.Errorf("size = %d, want 3 (bounded)", got)
	}
	if a.Stats().Dropped == 0 {
		t.Error("expected drops")
	}
}

func TestEviction_PromotedSurvivesCapacity(t *testing.T) {
	a := New(Options{MaxBuckets: 2})
	base := time.Now()
	a.Observe(makeAlert("r", "s", base, model.SeverityNotice, nil))
	pinKey := a.Snapshot()[0].Key
	a.Promote(pinKey)

	// Fill above cap. The promoted bucket must survive.
	for i := 1; i < 5; i++ {
		a.Observe(makeAlert("r", "s", base.Add(time.Duration(i)*time.Minute), model.SeverityNotice, nil))
	}
	if _, ok := a.Get(pinKey); !ok {
		t.Error("promoted bucket evicted under capacity pressure")
	}
}

func TestStats(t *testing.T) {
	a := New(Options{})
	now := time.Now()
	a.Observe(makeAlert("r", "s", now, model.SeverityNotice, nil))
	a.Observe(makeAlert("r", "s", now.Add(time.Second), model.SeverityNotice, nil))
	a.Promote(a.Snapshot()[0].Key)

	s := a.Stats()
	if s.Observed != 2 {
		t.Errorf("Observed = %d, want 2", s.Observed)
	}
	if s.Buckets != 1 {
		t.Errorf("Buckets = %d, want 1 (same window)", s.Buckets)
	}
	if s.Promoted != 1 {
		t.Errorf("Promoted = %d, want 1", s.Promoted)
	}
}

func BenchmarkObserve_Hot(b *testing.B) {
	a := New(Options{})
	alert := makeAlert("rule_x", "fim", time.Now(), model.SeverityNotice, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Observe(alert)
	}
}

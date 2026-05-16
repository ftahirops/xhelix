package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeBaselineDir produces a JSONL file with the given windows for
// the scorer test.
func writeBaselineDir(t *testing.T, windows []*Window) string {
	t.Helper()
	dir := t.TempDir()
	if len(windows) == 0 {
		return dir
	}
	day := windows[0].Hour.UTC().Format("2006-01-02")
	f, err := os.OpenFile(filepath.Join(dir, day+".jsonl"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, w := range windows {
		if err := enc.Encode(w); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestScorerLoadBaseline(t *testing.T) {
	t0 := time.Date(2026, 5, 4, 10, 0, 0, 0, time.UTC)
	windows := []*Window{
		{
			Binary:    "/usr/sbin/nginx",
			Hour:      t0,
			Events:    100,
			Endpoints: map[string]uint64{"10.0.0.0/16:443": 50},
			Children:  map[string]uint64{"nginx-worker": 10},
			Syscalls:  map[string]uint64{"ebpf.spawn": 100},
		},
		{
			Binary:    "/usr/sbin/nginx",
			Hour:      t0.Add(time.Hour),
			Events:    120,
			Endpoints: map[string]uint64{"10.0.1.0/16:443": 60},
		},
	}
	dir := writeBaselineDir(t, windows)
	s := NewScorer(ScorerConfig{BaselineDir: dir, LookbackDays: 7})
	n, err := s.LoadBaseline(t0.Add(2 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("learned binaries = %d, want 1", n)
	}
	st := s.Stats(t0.Add(2 * time.Hour))
	if st.Binaries != 1 {
		t.Errorf("stats binaries = %d", st.Binaries)
	}
}

func TestScorerWarmupSilencesNewBinary(t *testing.T) {
	dir := t.TempDir()
	s := NewScorer(ScorerConfig{
		BaselineDir: dir,
		WarmupHours: 24,
		HysteresisN: 1,
	})
	t0 := time.Now().UTC().Truncate(time.Hour)
	w := &Window{
		Binary:    "/usr/local/bin/new-tool",
		Hour:      t0,
		Events:    10,
		Endpoints: map[string]uint64{"203.0.113.0/16:443": 1},
	}
	if v := s.Score(w, t0); v != nil {
		t.Errorf("first window for a new binary must not score: %+v", v)
	}
	// A second window 1 hour later — still in warmup.
	w2 := &Window{
		Binary:    "/usr/local/bin/new-tool",
		Hour:      t0.Add(time.Hour),
		Events:    10,
		Endpoints: map[string]uint64{"198.51.100.0/16:443": 1},
	}
	if v := s.Score(w2, t0.Add(time.Hour)); v != nil {
		t.Errorf("during warmup must not score: %+v", v)
	}
}

func TestScorerFiresAfterWarmup(t *testing.T) {
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	// 30 hourly windows of "normal" nginx behavior.
	hist := []*Window{}
	for i := 0; i < 30; i++ {
		hist = append(hist, &Window{
			Binary:    "/usr/sbin/nginx",
			Hour:      t0.Add(time.Duration(i) * time.Hour),
			Events:    100,
			Endpoints: map[string]uint64{"10.0.0.0/16:443": 50},
			Children:  map[string]uint64{"nginx-worker": 5},
		})
	}
	dir := writeBaselineDir(t, hist)
	s := NewScorer(ScorerConfig{
		BaselineDir:       dir,
		LookbackDays:      30,
		WarmupHours:       24,
		HysteresisN:       1, // disable hysteresis to keep the test simple
		MinFeatureClasses: 1,
	})
	if _, err := s.LoadBaseline(t0.Add(48 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Now a fresh window with a never-seen endpoint.
	cur := &Window{
		Binary: "/usr/sbin/nginx",
		Hour:   t0.Add(48 * time.Hour),
		Events: 100,
		Endpoints: map[string]uint64{
			"10.0.0.0/16:443":   30,
			"203.0.113.0/16:443": 5, // NEW
		},
	}
	v := s.Score(cur, cur.Hour)
	if v == nil {
		t.Fatal("expected a verdict for the new endpoint")
	}
	if len(v.NewEndpoints) != 1 || v.NewEndpoints[0] != "203.0.113.0/16:443" {
		t.Errorf("new endpoints = %v", v.NewEndpoints)
	}
}

func TestScorerHysteresis(t *testing.T) {
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	hist := []*Window{}
	for i := 0; i < 30; i++ {
		hist = append(hist, &Window{
			Binary: "x",
			Hour:   t0.Add(time.Duration(i) * time.Hour),
			Events: 10,
		})
	}
	dir := writeBaselineDir(t, hist)
	s := NewScorer(ScorerConfig{
		BaselineDir: dir, LookbackDays: 30,
		WarmupHours: 24, HysteresisN: 3, MinFeatureClasses: 1,
	})
	s.LoadBaseline(t0.Add(48 * time.Hour))

	mk := func(hour int) *Window {
		return &Window{
			Binary: "x",
			Hour:   t0.Add(time.Duration(hour) * time.Hour),
			Events: 10,
			Endpoints: map[string]uint64{
				"203.0.113.0/16:443": 1, // same "new" endpoint each window
			},
		}
	}
	if v := s.Score(mk(48), mk(48).Hour); v != nil {
		t.Errorf("hysteresis=3 must not fire on first new appearance: %+v", v)
	}
	if v := s.Score(mk(49), mk(49).Hour); v != nil {
		t.Error("must not fire on second")
	}
	v := s.Score(mk(50), mk(50).Hour)
	if v == nil {
		t.Fatal("must fire on third")
	}
	if len(v.NewEndpoints) != 1 {
		t.Errorf("expected 1 endpoint, got %v", v.NewEndpoints)
	}
}

func TestScorerMarkBenign(t *testing.T) {
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	hist := []*Window{}
	for i := 0; i < 30; i++ {
		hist = append(hist, &Window{
			Binary: "x",
			Hour:   t0.Add(time.Duration(i) * time.Hour),
			Events: 10,
		})
	}
	dir := writeBaselineDir(t, hist)
	s := NewScorer(ScorerConfig{
		BaselineDir: dir, LookbackDays: 30, WarmupHours: 24,
		HysteresisN: 1, MinFeatureClasses: 1,
	})
	s.LoadBaseline(t0.Add(48 * time.Hour))

	// Pre-mark as benign — subsequent score() should not flag it.
	s.MarkBenign("x", "endpoint", "203.0.113.0/16:443")

	cur := &Window{
		Binary: "x",
		Hour:   t0.Add(48 * time.Hour),
		Events: 10,
		Endpoints: map[string]uint64{"203.0.113.0/16:443": 1},
	}
	if v := s.Score(cur, cur.Hour); v != nil {
		t.Errorf("benign-marked feature should not fire: %+v", v)
	}
}

func TestSetDiff(t *testing.T) {
	current := map[string]uint64{"a": 1, "b": 1, "c": 1}
	baseline := map[string]struct{}{"a": {}, "c": {}}
	got := setDiff(current, baseline)
	if len(got) != 1 || got[0] != "b" {
		t.Errorf("got %v", got)
	}
}

func TestRateDetectorWarmup(t *testing.T) {
	d := NewRateDetector(RateConfig{MinHistory: 24, SigmaThreshold: 3})
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 23; i++ {
		w := &Window{Binary: "x", Hour: t0.Add(time.Duration(i) * time.Hour), Events: 1000}
		if v := d.Observe(w); v != nil {
			t.Errorf("warmup must not fire (i=%d): %+v", i, v)
		}
	}
}

func TestRateDetectorFiresOnSpike(t *testing.T) {
	d := NewRateDetector(RateConfig{
		MinHistory: 12, SigmaThreshold: 3, Alpha: 0.2, MinAbsoluteEvents: 100,
	})
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	// 30 windows around 1000 events with small jitter.
	for i := 0; i < 30; i++ {
		count := uint64(1000 + (i%5)*10)
		w := &Window{Binary: "x", Hour: t0.Add(time.Duration(i) * time.Hour), Events: count}
		d.Observe(w)
	}
	// Spike: 100x.
	spike := &Window{Binary: "x", Hour: t0.Add(31 * time.Hour), Events: 100000}
	v := d.Observe(spike)
	if v == nil {
		t.Fatal("expected a rate verdict for 100x spike")
	}
	if v.SigmaAbove < 3 {
		t.Errorf("sigma_above = %f, want > 3", v.SigmaAbove)
	}
}

func TestRateDetectorIgnoresLowVolume(t *testing.T) {
	d := NewRateDetector(RateConfig{
		MinHistory: 12, SigmaThreshold: 3, MinAbsoluteEvents: 100,
	})
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		d.Observe(&Window{Binary: "x", Hour: t0.Add(time.Duration(i) * time.Hour), Events: 5})
	}
	// 50 events — still below MinAbsoluteEvents floor.
	if v := d.Observe(&Window{Binary: "x", Hour: t0.Add(31 * time.Hour), Events: 50}); v != nil {
		t.Errorf("low-volume binary must not fire: %+v", v)
	}
}

func TestRateDetectorPercentile(t *testing.T) {
	got := percentile([]uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 95)
	if got != 10 {
		t.Errorf("p95 = %d", got)
	}
	if percentile(nil, 95) != 0 {
		t.Error("nil → 0")
	}
}

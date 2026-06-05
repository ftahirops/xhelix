package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/baseline"
	"github.com/xhelix/xhelix/pkg/model"
)

// TestBaselineNoveltyReachesAlertBus proves the cmd-level glue that was
// reported (wrongly) as "not wired": a Scorer verdict on novel behaviour
// must be turned by scoreOneWindow into a baseline.behavioural_deviation
// model.Alert handed to emit. Combined with the aggregator feed
// (pkg/pipeline/pipeline.go BaselineAgg.Observe) and the flush goroutine
// in runDaemon, this closes the loop: novel behaviour -> alert bus.
//
// It also pins the WordPress-dropper shape the prod incident missed:
// php-fpm suddenly writing a .php into a docroot AND fetching from a
// code host it has never contacted -> two new feature classes -> verdict.
func TestBaselineNoveltyReachesAlertBus(t *testing.T) {
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	// 30 hourly windows of "normal" php-fpm: only ever talks to one CDN
	// and only ever writes to its own cache dir.
	writeBaselineWindows(t, dir, t0, 30,
		map[string]uint64{"151.101.0.0/16:443": 50},
		map[string]uint64{"/var/lib/php/sessions/sess_x": 3})

	s := baseline.NewScorer(baseline.ScorerConfig{
		BaselineDir:       dir,
		LookbackDays:      30,
		WarmupHours:       24,
		HysteresisN:       1, // single-window so the test is deterministic
		MinFeatureClasses: 1,
	})
	if _, err := s.LoadBaseline(t0.Add(48 * time.Hour)); err != nil {
		t.Fatal(err)
	}

	novel := &baseline.Window{
		Binary: "php-fpm",
		Hour:   t0.Add(48 * time.Hour),
		Events: 60,
		Endpoints: map[string]uint64{
			"151.101.0.0/16:443":   30, // known CDN (baseline)
			"185.199.108.0/16:443": 4,  // NEW: code-host (githubusercontent-style)
		},
		FileWrites: map[string]uint64{
			"/var/www/html/wp-content/uploads/x.php": 1, // NEW: docroot PHP write
		},
	}

	var got []model.Alert
	emit := func(a model.Alert) { got = append(got, a) }
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	scoreOneWindow(log, s, nil, novel, emit)

	if len(got) != 1 {
		t.Fatalf("expected exactly 1 baseline alert on the bus, got %d", len(got))
	}
	a := got[0]
	if a.RuleID != "baseline.behavioural_deviation" {
		t.Errorf("RuleID = %q, want baseline.behavioural_deviation", a.RuleID)
	}
	if a.Mode != model.ModeDetect {
		t.Errorf("Mode = %v, want ModeDetect (observe-only)", a.Mode)
	}
	if fw := a.Event.Tags["new_file_writes"]; !strings.Contains(fw, "/var/www/html/wp-content/uploads/x.php") {
		t.Errorf("new_file_writes tag = %q, want the docroot php write", fw)
	}
	if ep := a.Event.Tags["new_endpoints"]; !strings.Contains(ep, "185.199.108.0/16:443") {
		t.Errorf("new_endpoints tag = %q, want the new code-host endpoint", ep)
	}
}

// TestBaselineNilEmitDoesNotPanic guards the documented startup window
// where the scoring goroutine could fire before emit is assigned.
func TestBaselineNilEmitDoesNotPanic(t *testing.T) {
	s := baseline.NewScorer(baseline.ScorerConfig{BaselineDir: t.TempDir()})
	w := &baseline.Window{Binary: "x", Hour: time.Now().UTC(), Events: 1}
	scoreOneWindow(slog.New(slog.NewTextHandler(io.Discard, nil)), s, nil, w, nil) // must not panic
}

// writeBaselineWindows writes n hourly windows for php-fpm into a single
// day file the scorer's LoadBaseline will read.
func writeBaselineWindows(t *testing.T, dir string, t0 time.Time, n int,
	endpoints, fileWrites map[string]uint64) {
	t.Helper()
	day := t0.UTC().Format("2006-01-02")
	f, err := os.OpenFile(filepath.Join(dir, day+".jsonl"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for i := 0; i < n; i++ {
		w := &baseline.Window{
			Binary:     "php-fpm",
			Hour:       t0.Add(time.Duration(i) * time.Hour),
			Events:     50,
			Endpoints:  endpoints,
			FileWrites: fileWrites,
		}
		if err := enc.Encode(w); err != nil {
			t.Fatal(err)
		}
	}
}

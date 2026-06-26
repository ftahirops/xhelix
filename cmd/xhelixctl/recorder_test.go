package main

import (
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/recorder"
)

func TestRenderCoverage_ShowsAppsAndShapes(t *testing.T) {
	t0 := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	rep := recorder.CoverageReport{
		Apps:              2,
		Shapes:            3,
		TotalObservations: 18,
		ByApp: map[string]recorder.AppCoverage{
			"shop": {Shapes: 2, Observations: 15, NewestShape: t0.Add(2 * time.Hour), OldestShape: t0},
			"blog": {Shapes: 1, Observations: 3, NewestShape: t0, OldestShape: t0},
		},
	}
	out := renderCoverage(rep)

	if !strings.Contains(out, "2 apps") {
		t.Errorf("expected '2 apps' in output: %q", out)
	}
	if !strings.Contains(out, "3 shapes") {
		t.Errorf("expected '3 shapes' in output: %q", out)
	}
	if !strings.Contains(out, "18 total observations") {
		t.Errorf("expected '18 total observations' in output: %q", out)
	}
	if !strings.Contains(out, "shop") {
		t.Errorf("expected 'shop' in output: %q", out)
	}
	if !strings.Contains(out, "blog") {
		t.Errorf("expected 'blog' in output: %q", out)
	}
}

func TestRenderCoverage_Empty(t *testing.T) {
	rep := recorder.CoverageReport{ByApp: map[string]recorder.AppCoverage{}}
	out := renderCoverage(rep)
	if !strings.Contains(out, "0 apps") {
		t.Errorf("expected '0 apps': %q", out)
	}
	if !strings.Contains(out, "no data") {
		t.Errorf("expected 'no data' hint: %q", out)
	}
}

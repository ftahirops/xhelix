package recorder

import (
	"testing"
	"time"
)

func TestCoverage_AggregatesByApp(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	rows := []ShapeRow{
		{AppID: "shop", ShapeHash: "a", Count: 10, FirstSeen: t0, LastSeen: t0.Add(time.Hour)},
		{AppID: "shop", ShapeHash: "b", Count: 5, FirstSeen: t0, LastSeen: t0.Add(2 * time.Hour)},
		{AppID: "blog", ShapeHash: "c", Count: 3, FirstSeen: t0, LastSeen: t0},
	}
	rep := Coverage(rows)
	if rep.Apps != 2 || rep.Shapes != 3 || rep.TotalObservations != 18 {
		t.Fatalf("totals wrong: %+v", rep)
	}
	if rep.ByApp["shop"].Shapes != 2 || rep.ByApp["shop"].Observations != 15 {
		t.Errorf("shop coverage wrong: %+v", rep.ByApp["shop"])
	}
	if !rep.ByApp["shop"].NewestShape.Equal(t0.Add(2 * time.Hour)) {
		t.Errorf("shop newest wrong: %v", rep.ByApp["shop"].NewestShape)
	}
}

func TestCoverage_Empty(t *testing.T) {
	rep := Coverage(nil)
	if rep.Apps != 0 || rep.Shapes != 0 || rep.TotalObservations != 0 {
		t.Errorf("empty rows should yield zero report: %+v", rep)
	}
	if rep.ByApp == nil {
		t.Error("ByApp must be non-nil map")
	}
}

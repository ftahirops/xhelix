package main

import (
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/fleetrarity"
	"github.com/xhelix/xhelix/pkg/lineagescore"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/rulecat"
)

// fakeFleet implements fleetrarity.Provider for the test: an endpoint is
// rare iff in `rare`, and the whole answer is Unknown when cohort<5.
type fakeFleet struct {
	rare   map[string]bool
	cohort int
}

func (f fakeFleet) Lookup(binary, endpoint string) fleetrarity.Rarity {
	if f.cohort < 5 {
		return fleetrarity.Rarity{Known: false, CohortSize: f.cohort}
	}
	return fleetrarity.Rarity{Known: true, Rare: f.rare[endpoint], CohortSize: f.cohort}
}

// scoreWithFleet mirrors the verdict router's default-branch weight calc:
// sensitivity boost, then (if a fleet provider exists and the event has a
// dst_ip) fleet adjust, then observe. Keep in sync with cmd/xhelix/run.go.
func scoreWithFleet(eng *lineagescore.Engine, res *rulecat.Resolver, fc fleetrarity.Provider, a model.Alert) *lineagescore.Verdict {
	w := lineagescore.SensitivityBoost(res.Weight(a.RuleID), a.Event.Tags)
	if fc != nil {
		if ep := a.Event.Tags["dst_ip"]; ep != "" {
			w = fleetrarity.FleetWeightAdjust(w, fc.Lookup("nginx", ep))
		}
	}
	return eng.Observe(lineagescore.Signal{PID: a.Event.PID, RuleID: a.RuleID, Weight: w, At: a.Event.Time})
}

func newWeakResolver(t *testing.T) *rulecat.Resolver {
	t.Helper()
	r := rulecat.NewResolver()
	r.AddRules([]model.Rule{{ID: "outbound", CategoryRaw: "weak_signal", Category: model.CategoryWeakSignal}}) // base weight 20
	return r
}

func mkOutbound(ip string, ts time.Time) model.Alert {
	return model.Alert{RuleID: "outbound", Event: model.Event{PID: 5, Time: ts, Tags: map[string]string{"dst_ip": ip}}}
}

func TestFleetRare_RaisesScoreAcrossThreshold(t *testing.T) {
	res := newWeakResolver(t)
	now := time.Unix(1000, 0)
	rareFleet := fakeFleet{rare: map[string]bool{"1.2.3.4": true}, cohort: 50}
	// Threshold 55: weak base 20 + fleet-rare 40 = 60 → crosses.
	eng := lineagescore.New(lineagescore.Opts{Threshold: 55, Window: time.Hour, LineageOf: func(uint32) uint32 { return 1 }})
	if scoreWithFleet(eng, res, rareFleet, mkOutbound("1.2.3.4", now)) == nil {
		t.Fatal("rare endpoint (20+40=60) must cross threshold 55")
	}
}

func TestFleetCommon_DoesNotCross(t *testing.T) {
	res := newWeakResolver(t)
	now := time.Unix(1000, 0)
	rareFleet := fakeFleet{rare: map[string]bool{"1.2.3.4": true}, cohort: 50}
	eng := lineagescore.New(lineagescore.Opts{Threshold: 55, Window: time.Hour, LineageOf: func(uint32) uint32 { return 1 }})
	// 9.9.9.9 not in rare set → common → weight stays 20 < 55.
	if scoreWithFleet(eng, res, rareFleet, mkOutbound("9.9.9.9", now)) != nil {
		t.Fatal("common endpoint (20) must not cross threshold 55")
	}
}

func TestFleetSmallCohort_NoEffect(t *testing.T) {
	res := newWeakResolver(t)
	now := time.Unix(1000, 0)
	smallFleet := fakeFleet{rare: map[string]bool{"1.2.3.4": true}, cohort: 3} // < 5 → Unknown
	eng := lineagescore.New(lineagescore.Opts{Threshold: 55, Window: time.Hour, LineageOf: func(uint32) uint32 { return 1 }})
	if scoreWithFleet(eng, res, smallFleet, mkOutbound("1.2.3.4", now)) != nil {
		t.Fatal("cohort 3 < min 5 → no fleet boost → 20 < 55 → no verdict")
	}
}

func TestFleetDisabled_NilProvider_NoEffect(t *testing.T) {
	res := newWeakResolver(t)
	now := time.Unix(1000, 0)
	eng := lineagescore.New(lineagescore.Opts{Threshold: 55, Window: time.Hour, LineageOf: func(uint32) uint32 { return 1 }})
	// nil provider (fleet disabled) → weight stays 20 < 55.
	if scoreWithFleet(eng, res, nil, mkOutbound("1.2.3.4", now)) != nil {
		t.Fatal("nil fleet provider → no boost → no verdict")
	}
}

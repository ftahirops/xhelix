package main

import (
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/lineagescore"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/rulecat"
)

// scoreSignal reproduces the router's scoring decision in isolation
// (same as cmd/xhelix/run.go's router default branch): boost the
// category weight by event tags, observe on the shared engine.
func scoreSignal(eng *lineagescore.Engine, res *rulecat.Resolver, a model.Alert) *lineagescore.Verdict {
	return eng.Observe(lineagescore.Signal{
		PID:    a.Event.PID,
		RuleID: a.RuleID,
		Weight: lineagescore.SensitivityBoost(res.Weight(a.RuleID), a.Event.Tags),
		At:     a.Event.Time,
		Reason: a.Reason,
	})
}

func TestCanonicalWebshellChain_OneCriticalVerdict(t *testing.T) {
	res := rulecat.NewResolver()
	res.AddRules([]model.Rule{
		{ID: "web_server_spawns_shell", CategoryRaw: "incident", Category: model.CategoryIncident},
		{ID: "download_then_run", CategoryRaw: "incident", Category: model.CategoryIncident},
		{ID: "env_secret_read_by_web", CategoryRaw: "incident", Category: model.CategoryIncident},
		{ID: "outbound_to_known_bad", CategoryRaw: "incident", Category: model.CategoryIncident},
	})
	// One source lineage (root 42) for the whole chain.
	eng := lineagescore.New(lineagescore.Opts{
		Threshold: 80, Window: time.Hour, Cooldown: time.Hour,
		LineageOf: func(uint32) uint32 { return 42 },
	})
	now := time.Unix(1000, 0)
	mk := func(rid string, tags map[string]string, off int) model.Alert {
		return model.Alert{RuleID: rid, Event: model.Event{PID: uint32(100 + off), Time: now.Add(time.Duration(off) * time.Second), Tags: tags}}
	}
	chain := []model.Alert{
		mk("web_server_spawns_shell", nil, 0),
		mk("download_then_run", nil, 1),
		mk("env_secret_read_by_web", map[string]string{"secret_taint": "secret_touched", "asset_class": "secret_file"}, 2),
		mk("outbound_to_known_bad", map[string]string{"secret_taint": "outbound_restricted"}, 3),
	}
	var verdicts []*lineagescore.Verdict
	for _, a := range chain {
		if v := scoreSignal(eng, res, a); v != nil {
			verdicts = append(verdicts, v)
		}
	}
	if len(verdicts) == 0 {
		t.Fatal("canonical chain must produce at least one verdict")
	}
	last := verdicts[len(verdicts)-1]
	if last.Tier != "critical" {
		t.Fatalf("final verdict tier=%q score=%d want critical", last.Tier, last.Score)
	}
}

func TestThreeBenignSignals_DifferentLineages_NoVerdict(t *testing.T) {
	res := rulecat.NewResolver()
	res.AddRules([]model.Rule{
		{ID: "lolbin.suspicious", CategoryRaw: "weak_signal", Category: model.CategoryWeakSignal},
	})
	eng := lineagescore.New(lineagescore.Opts{
		Threshold: 80, Window: time.Hour, LineageOf: func(p uint32) uint32 { return p },
	})
	now := time.Unix(1000, 0)
	for i, pid := range []uint32{1, 2, 3} {
		a := model.Alert{RuleID: "lolbin.suspicious", Event: model.Event{PID: pid, Time: now.Add(time.Duration(i) * time.Second)}}
		if v := scoreSignal(eng, res, a); v != nil {
			t.Fatalf("benign weak signal on lineage %d must not verdict", pid)
		}
	}
}

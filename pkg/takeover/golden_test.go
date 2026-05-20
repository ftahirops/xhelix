package takeover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/actionlog"
	"github.com/xhelix/xhelix/pkg/decision"
	"github.com/xhelix/xhelix/pkg/model"
)

// Golden tests for the takeover Planner — the first live consumer
// of decision.Plan(). Walks an attacker-narrative corpus:
//   "ingest N signals → call Plan(lineageID, now) → check the
//    emitted ActionPlan shape".
//
// Corpus lives in pkg/takeover/testdata/golden/*.json.
//
// To regenerate after an intentional behaviour change:
//   UPDATE_GOLDEN=1 go test -run TestGolden ./pkg/takeover/

type goldenCase struct {
	Name    string         `json:"name"`
	Signals []goldenSignal `json:"signals"`

	// Planner inputs
	LineageID      uint64    `json:"lineage_id"`
	CrownJewelTier string    `json:"crown_jewel_tier,omitempty"`
	StatePreset    string    `json:"state_preset,omitempty"`
	BastionAvail   bool      `json:"bastion_available,omitempty"`
	OffHostMirror  bool      `json:"off_host_mirror_available,omitempty"`
	MinScoreToPlan int       `json:"min_score_to_plan,omitempty"`

	// Alert used in PlanFromAlert (Plan() builds its own from the
	// last signal).
	UseAlert bool        `json:"use_alert,omitempty"`
	Alert    goldenAlert `json:"alert,omitempty"`

	// At — fixed observation time for determinism. Defaults to
	// 2026-05-20T00:00:00Z.
	AtUnix int64 `json:"at_unix,omitempty"`

	Expected goldenExpected `json:"expected"`

	// Sanity-check inputs we don't compare across runs:
	ExpectNilPlan bool `json:"expect_nil_plan,omitempty"`
}

type goldenSignal struct {
	Kind       string `json:"kind"`        // takeover.SignalKind
	Source     string `json:"source,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	Weight     int    `json:"weight,omitempty"` // overrides table
	// OffsetMs from "At" — lets the corpus express ordering.
	OffsetMs int64 `json:"offset_ms,omitempty"`
}

type goldenAlert struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

type goldenExpected struct {
	Tier                 string   `json:"tier"`
	Actions              []string `json:"actions"`
	Reversible           bool     `json:"reversible"`
	Score                int      `json:"score"`
	IsHardAction         bool     `json:"is_hard_action"`
	HasDestructiveAction bool     `json:"has_destructive_action"`
	ReasonsContain       []string `json:"reasons_contain,omitempty"`
	WarningsContain      []string `json:"warnings_contain,omitempty"`
}

const goldenDir = "testdata/golden"

func TestGolden_TakeoverPlanner(t *testing.T) {
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("read %s: %v", goldenDir, err)
	}
	if len(entries) == 0 {
		t.Fatal("golden corpus empty")
	}

	update := os.Getenv("UPDATE_GOLDEN") == "1"

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		t.Run(strings.TrimSuffix(e.Name(), ".json"), func(t *testing.T) {
			path := filepath.Join(goldenDir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			var c goldenCase
			if err := json.Unmarshal(data, &c); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}

			plan, gotNil := runScenario(t, c)

			if update {
				if gotNil {
					c.ExpectNilPlan = true
					c.Expected = goldenExpected{}
				} else {
					c.ExpectNilPlan = false
					c.Expected = summarisePlan(plan)
				}
				out, _ := json.MarshalIndent(c, "", "  ")
				_ = os.WriteFile(path, append(out, '\n'), 0o644)
				t.Logf("UPDATED %s", path)
				return
			}

			if c.ExpectNilPlan {
				if !gotNil {
					t.Fatalf("expected nil plan; got %+v", plan)
				}
				return
			}
			if gotNil {
				t.Fatalf("got nil plan but expected %+v", c.Expected)
			}
			assertEqual(t, c.Expected, summarisePlan(plan))
		})
	}
}

func runScenario(t *testing.T, c goldenCase) (*decision.ActionPlan, bool) {
	t.Helper()
	at := time.Unix(1747706400, 0).UTC() // 2026-05-20T00:00:00Z
	if c.AtUnix != 0 {
		at = time.Unix(c.AtUnix, 0).UTC()
	}

	p := NewPlanner(PlannerConfig{
		State:          stateForPreset(c.StatePreset, c.LineageID),
		MinScoreToPlan: c.MinScoreToPlan,
		ResolveCJTier: func(_ model.Alert) string {
			return c.CrownJewelTier
		},
		PreconditionProbe: func() (bool, bool) {
			return c.BastionAvail, c.OffHostMirror
		},
	})

	for _, s := range c.Signals {
		p.OnSignal(Signal{
			LineageID:  c.LineageID,
			Kind:       SignalKind(s.Kind),
			At:         at.Add(time.Duration(s.OffsetMs) * time.Millisecond),
			Source:     s.Source,
			Detail:     s.Detail,
			Confidence: s.Confidence,
			RemoteIP:   s.RemoteIP,
			Weight:     s.Weight,
		})
	}

	if c.UseAlert {
		alert := model.Alert{
			Event:  fixedEvent(),
			RuleID: c.Alert.RuleID,
			Reason: c.Alert.Reason,
			Mode:   parseRuleMode(c.Alert.Mode),
		}
		plan := p.PlanFromAlert(alert, c.LineageID, at)
		return plan, plan == nil
	}
	plan := p.Plan(c.LineageID, at)
	return plan, plan == nil
}

func summarisePlan(p *decision.ActionPlan) goldenExpected {
	return goldenExpected{
		Tier:                 p.Tier,
		Actions:              p.Actions(),
		Reversible:           p.Reversible,
		Score:                p.Score,
		IsHardAction:         p.IsHardAction(),
		HasDestructiveAction: p.HasDestructiveAction(),
		ReasonsContain:       passthrough(p.Reasons),
		WarningsContain:      passthrough(p.CapabilityWarnings),
	}
}

func passthrough(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}

func assertEqual(t *testing.T, want, got goldenExpected) {
	t.Helper()
	if want.Tier != got.Tier {
		t.Errorf("tier:   want %q   got %q", want.Tier, got.Tier)
	}
	if !slicesEqual(want.Actions, got.Actions) {
		t.Errorf("actions:\n  want %v\n  got  %v", want.Actions, got.Actions)
	}
	if want.Reversible != got.Reversible {
		t.Errorf("reversible: want %v   got %v", want.Reversible, got.Reversible)
	}
	if want.Score != got.Score {
		t.Errorf("score:  want %d   got %d", want.Score, got.Score)
	}
	if want.IsHardAction != got.IsHardAction {
		t.Errorf("is_hard_action: want %v   got %v", want.IsHardAction, got.IsHardAction)
	}
	if want.HasDestructiveAction != got.HasDestructiveAction {
		t.Errorf("has_destructive: want %v   got %v",
			want.HasDestructiveAction, got.HasDestructiveAction)
	}
	for _, n := range want.ReasonsContain {
		if !contains(got.ReasonsContain, n) {
			t.Errorf("reasons missing %q   got %v", n, got.ReasonsContain)
		}
	}
	for _, n := range want.WarningsContain {
		if !contains(got.WarningsContain, n) {
			t.Errorf("warnings missing %q   got %v", n, got.WarningsContain)
		}
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}

// --- state presets ---

func stateForPreset(name string, lineageID uint64) *actionlog.Log {
	log := actionlog.New()
	switch name {
	case "", "observed":
		return log
	case "triaged":
		_ = log.Record(actionlog.Transition{LineageID: lineageID, To: actionlog.StateTriaged, Reason: "seed", PlanID: "seed"})
	case "suspended":
		_ = log.Record(actionlog.Transition{LineageID: lineageID, To: actionlog.StateSuspended, Reason: "seed", PlanID: "seed1"})
	case "isolated":
		_ = log.Record(actionlog.Transition{LineageID: lineageID, To: actionlog.StateSuspended, Reason: "seed", PlanID: "seed1"})
		_ = log.Record(actionlog.Transition{LineageID: lineageID, From: actionlog.StateSuspended, To: actionlog.StateIsolated, Reason: "seed", PlanID: "seed2"})
	}
	return log
}

func fixedEvent() model.Event {
	ev := model.NewEvent("golden", model.SeverityHigh)
	ev.Time = time.Unix(1747706400, 0).UTC()
	return ev
}

func parseRuleMode(s string) model.RuleMode {
	switch s {
	case "quarantine":
		return model.ModeQuarantine
	case "block":
		return model.ModeBlock
	}
	return model.ModeDetect
}

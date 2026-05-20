package decision

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/actionlog"
	"github.com/xhelix/xhelix/pkg/model"
)

// Golden tests for decision.Plan() — every refactor must produce
// the same ActionPlan shape for the same input. The corpus lives
// in pkg/decision/testdata/golden/*.json (one case per file).
//
// To regenerate after an intentional change:
//   UPDATE_GOLDEN=1 go test -run TestGolden ./pkg/decision/
//
// To verify (CI / pre-commit / pre-refactor diff):
//   go test -run TestGolden ./pkg/decision/
//
// PROCESS:
//   1. Refactor work that touches the planner runs go test FIRST
//   2. If the golden test fails, INSPECT the diff carefully —
//      every failing assertion is either:
//      (a) an intentional behavior change (then UPDATE_GOLDEN=1)
//      (b) a regression (then fix the refactor)
//   3. Never blanket-update goldens to make tests pass.

// goldenCase is the JSON shape on disk. Comments here serve as the
// schema; please document the WHY for every new field added.
type goldenCase struct {
	Name string `json:"name"`

	// --- inputs ---
	Alert                  goldenAlert `json:"alert"`
	Score                  int         `json:"score"`
	LineageID              uint64      `json:"lineage_id"`
	ProcKey                string      `json:"proc_key,omitempty"`
	CrownJewelTier         string     `json:"crown_jewel_tier,omitempty"`
	AttributedIPs          []string    `json:"attributed_ips,omitempty"`
	BastionAvailable       bool        `json:"bastion_available,omitempty"`
	OffHostMirrorAvailable bool        `json:"off_host_mirror_available,omitempty"`

	// CapsPreset / StatePreset select canned shapes — keeps the
	// corpus JSON small and human-readable rather than serialising
	// the full CapabilitySet / actionlog.Log every time.
	CapsPreset  string `json:"caps_preset,omitempty"`  // "none" | "all" | "no_bastion" | "no_memscan"
	StatePreset string `json:"state_preset,omitempty"` // "observed" | "triaged" | "suspended" | "isolated" | "contained"

	// --- expected output ---
	Expected goldenExpected `json:"expected"`
}

type goldenAlert struct {
	RuleID  string `json:"rule_id"`
	Reason  string `json:"reason,omitempty"`
	Mode    string `json:"mode"` // "detect" | "quarantine" | "block"
}

type goldenExpected struct {
	Tier                 string   `json:"tier"`
	Actions              []string `json:"actions"`
	Reversible           bool     `json:"reversible"`
	Score                int      `json:"score"`
	IsNoOp               bool     `json:"is_no_op"`
	IsHardAction         bool     `json:"is_hard_action"`
	HasDestructiveAction bool     `json:"has_destructive_action"`
	// Substring matches — keeps the corpus tolerant to phrasing
	// changes in helpers like AddCapabilityWarning.
	ReasonsContain  []string `json:"reasons_contain,omitempty"`
	WarningsContain []string `json:"warnings_contain,omitempty"`
}

// ------------------------------------------------------------
// Test harness
// ------------------------------------------------------------

const goldenDir = "testdata/golden"

func TestGolden_DecisionPlan(t *testing.T) {
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("read %s: %v", goldenDir, err)
	}
	if len(entries) == 0 {
		t.Fatal("golden corpus is empty — refusing to pass vacuously")
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

			plan := runPlan(t, c)
			got := summarisePlan(plan)

			if update {
				c.Expected = got
				out, err := json.MarshalIndent(c, "", "  ")
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
					t.Fatalf("write %s: %v", path, err)
				}
				t.Logf("UPDATED %s", path)
				return
			}

			assertEqual(t, c.Expected, got)
		})
	}
}

// runPlan builds the Input from the golden case and executes
// decision.Plan. Time-dependent helpers use a fixed Now via
// the constructor helpers' baked-in defaults (note: ExpiresAt
// will differ on every run — that's why we don't compare it).
func runPlan(t *testing.T, c goldenCase) *ActionPlan {
	t.Helper()
	alert := model.Alert{
		Event:  fixedEvent(),
		RuleID: c.Alert.RuleID,
		Reason: c.Alert.Reason,
		Mode:   parseRuleMode(c.Alert.Mode),
	}
	return Plan(Input{
		Alert:                  alert,
		Score:                  c.Score,
		LineageID:              c.LineageID,
		ProcKey:                c.ProcKey,
		Caps:                   capsForPreset(c.CapsPreset),
		State:                  stateForPreset(c.StatePreset, c.LineageID),
		CrownJewelTier:         c.CrownJewelTier,
		AttributedIPs:          c.AttributedIPs,
		BastionAvailable:       c.BastionAvailable,
		OffHostMirrorAvailable: c.OffHostMirrorAvailable,
	})
}

// summarisePlan compresses an *ActionPlan into the
// JSON-serialisable golden shape. Drops fields that vary per run
// (PlanID, AlertID, CreatedAt, ExpiresAt) so the corpus is
// reproducible.
func summarisePlan(p *ActionPlan) goldenExpected {
	if p == nil {
		return goldenExpected{}
	}
	return goldenExpected{
		Tier:                 p.Tier,
		Actions:              p.Actions(),
		Reversible:           p.Reversible,
		Score:                p.Score,
		IsNoOp:               p.IsNoOp(),
		IsHardAction:         p.IsHardAction(),
		HasDestructiveAction: p.HasDestructiveAction(),
		ReasonsContain:       passthroughStrs(p.Reasons),
		WarningsContain:      passthroughStrs(p.CapabilityWarnings),
	}
}

// passthroughStrs is identity for non-nil slices; nil for empty.
// Keeps the JSON tidy.
func passthroughStrs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

func assertEqual(t *testing.T, want, got goldenExpected) {
	t.Helper()
	if want.Tier != got.Tier {
		t.Errorf("tier:    want %q   got %q", want.Tier, got.Tier)
	}
	if !slicesEqual(want.Actions, got.Actions) {
		t.Errorf("actions: want %v\n         got  %v", want.Actions, got.Actions)
	}
	if want.Reversible != got.Reversible {
		t.Errorf("reversible: want %v   got %v", want.Reversible, got.Reversible)
	}
	if want.Score != got.Score {
		t.Errorf("score:   want %d   got %d", want.Score, got.Score)
	}
	if want.IsNoOp != got.IsNoOp {
		t.Errorf("is_no_op: want %v   got %v", want.IsNoOp, got.IsNoOp)
	}
	if want.IsHardAction != got.IsHardAction {
		t.Errorf("is_hard_action: want %v   got %v", want.IsHardAction, got.IsHardAction)
	}
	if want.HasDestructiveAction != got.HasDestructiveAction {
		t.Errorf("has_destructive: want %v   got %v",
			want.HasDestructiveAction, got.HasDestructiveAction)
	}
	for _, needle := range want.ReasonsContain {
		if !containsAny(got.ReasonsContain, needle) {
			t.Errorf("reasons missing substring %q   reasons=%v", needle, got.ReasonsContain)
		}
	}
	for _, needle := range want.WarningsContain {
		if !containsAny(got.WarningsContain, needle) {
			t.Errorf("warnings missing substring %q   warnings=%v", needle, got.WarningsContain)
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

func containsAny(strs []string, needle string) bool {
	for _, s := range strs {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------
// Preset capability sets
// ------------------------------------------------------------

func capsForPreset(name string) CapabilityChecker {
	switch name {
	case "", "all":
		return canonCapsAll{}
	case "none":
		return canonCapsNone{}
	case "no_bastion":
		return canonCapsNoBastion{}
	case "no_memscan":
		return canonCapsNoMemscan{}
	}
	panic("unknown caps preset: " + name)
}

// canonCapsAll attaches no warnings — represents a fully-ready host.
type canonCapsAll struct{}

func (canonCapsAll) AnnotatePlan(*ActionPlan) {}

// canonCapsNone marks every action as missing its required capability.
type canonCapsNone struct{}

func (canonCapsNone) AnnotatePlan(p *ActionPlan) {
	if p == nil {
		return
	}
	for _, action := range p.Actions() {
		p.CapabilityWarnings = append(p.CapabilityWarnings, action+" requires runtime support")
	}
}

// canonCapsNoBastion attaches the bastion warning if IsolateHost is on.
type canonCapsNoBastion struct{}

func (canonCapsNoBastion) AnnotatePlan(p *ActionPlan) {
	if p != nil && p.IsolateHost {
		p.CapabilityWarnings = append(p.CapabilityWarnings, "isolate_host requires BastionCount>=2")
	}
}

// canonCapsNoMemscan attaches a memscan warning if memscan is on.
type canonCapsNoMemscan struct{}

func (canonCapsNoMemscan) AnnotatePlan(p *ActionPlan) {
	if p != nil && p.Memscan {
		p.CapabilityWarnings = append(p.CapabilityWarnings, "memscan requires pkg/memscan ready")
	}
}

// ------------------------------------------------------------
// Preset containment-log states
// ------------------------------------------------------------

func stateForPreset(name string, lineageID uint64) *actionlog.Log {
	log := actionlog.New()
	switch name {
	case "", "observed":
		return log
	case "triaged":
		_ = log.Record(actionlog.Transition{
			LineageID: lineageID, To: actionlog.StateTriaged,
			Reason: "seed", PlanID: "seed",
		})
	case "suspended":
		_ = log.Record(actionlog.Transition{
			LineageID: lineageID, To: actionlog.StateSuspended,
			Reason: "seed", PlanID: "seed1",
		})
	case "isolated":
		_ = log.Record(actionlog.Transition{
			LineageID: lineageID, To: actionlog.StateSuspended,
			Reason: "seed", PlanID: "seed1",
		})
		_ = log.Record(actionlog.Transition{
			LineageID: lineageID, From: actionlog.StateSuspended,
			To: actionlog.StateIsolated, Reason: "seed", PlanID: "seed2",
		})
	case "contained":
		_ = log.Record(actionlog.Transition{
			LineageID: lineageID, To: actionlog.StateSuspended,
			Reason: "seed", PlanID: "seed1",
		})
		_ = log.Record(actionlog.Transition{
			LineageID: lineageID, From: actionlog.StateSuspended,
			To: actionlog.StateIsolated, Reason: "seed", PlanID: "seed2",
		})
		_ = log.Record(actionlog.Transition{
			LineageID: lineageID, From: actionlog.StateIsolated,
			To: actionlog.StateContained, Reason: "seed", PlanID: "seed3",
		})
	default:
		panic("unknown state preset: " + name)
	}
	return log
}

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

func parseRuleMode(s string) model.RuleMode {
	switch s {
	case "quarantine":
		return model.ModeQuarantine
	case "block":
		return model.ModeBlock
	}
	return model.ModeDetect
}

func fixedEvent() model.Event {
	ev := model.NewEvent("golden", model.SeverityHigh)
	ev.Time = time.Unix(1700000000, 0).UTC()
	return ev
}

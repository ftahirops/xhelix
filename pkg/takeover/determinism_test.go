// P-PS.32 — F-03 replay determinism.
//
// The system's audit story depends on this guarantee: feed the
// SAME signal trace twice and the planner produces byte-equivalent
// plans (modulo PlanID + timestamps). Any deviation means hidden
// global state, map-iteration leakage, or time.Now() in a hot
// path — bugs that make audit reports irreproducible.
//
// This is a structural-equivalence check, not a textual one:
//   PlanID and ActionPlan.PlannedAt are intentionally per-run.
//   Everything else (Tier, Score, Actions, Warnings, CapabilityWarnings)
//   must match exactly.

package takeover

import (
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/actionlog"
)

// fixedSignals returns a representative input trace covering all
// major signal kinds. Used twice in the determinism test.
func fixedSignals(base time.Time) []Signal {
	return []Signal{
		{LineageID: 1, Kind: SignalShellAttempt, Source: "atk", At: base.Add(1 * time.Second)},
		{LineageID: 1, Kind: SignalRWXMemory, Source: "atk", At: base.Add(2 * time.Second)},
		{LineageID: 1, Kind: SignalPersistence, Source: "atk", At: base.Add(3 * time.Second)},
		{LineageID: 2, Kind: SignalNewBinary, Source: "apt", At: base.Add(4 * time.Second)},
		{LineageID: 2, Kind: SignalNewEndpoint, Source: "snap", At: base.Add(5 * time.Second)},
		{LineageID: 3, Kind: SignalCredAccess, Source: "atk", At: base.Add(6 * time.Second)},
		{LineageID: 3, Kind: SignalLOTL, Source: "atk", At: base.Add(7 * time.Second)},
		{LineageID: 3, Kind: SignalBase64Decode, Source: "atk", At: base.Add(8 * time.Second)},
		{LineageID: 4, Kind: SignalCanaryTouch, Source: "atk", At: base.Add(9 * time.Second)},
	}
}

// runOnce builds a fresh planner, feeds the trace, and returns
// per-lineage plans as a comparable map (no PlanID, no timestamps).
type comparablePlan struct {
	Tier      string
	Score     int
	Actions   []string // sorted
	Warnings  []string // sorted
	RuleID    string
}

func runOnce(t *testing.T, sigs []Signal, queryAt time.Time) map[uint64]*comparablePlan {
	t.Helper()
	p := NewPlanner(PlannerConfig{
		State: actionlog.New(),
		TTL:   time.Hour,
	})
	for _, s := range sigs {
		p.OnSignal(s)
	}
	out := map[uint64]*comparablePlan{}
	for _, l := range []uint64{1, 2, 3, 4} {
		plan := p.Plan(l, queryAt)
		if plan == nil {
			out[l] = nil
			continue
		}
		actions := append([]string(nil), plan.Actions()...)
		// Already sorted by ActionPlan.Actions() per canonical order;
		// re-sort defensively in case the canonical changes.
		sortStrings(actions)
		warns := append([]string(nil), plan.CapabilityWarnings...)
		sortStrings(warns)
		out[l] = &comparablePlan{
			Tier:     plan.Tier,
			Score:    plan.Score,
			Actions:  actions,
			Warnings: warns,
			RuleID:   plan.RuleID,
		}
	}
	return out
}

func sortStrings(s []string) {
	// Tiny stdlib-free sort because pkg/takeover doesn't already
	// import sort and this file keeps deps minimal.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// F-03: same trace fed to two independent planner instances must
// produce identical per-lineage plans (modulo PlanID/timestamps).
func TestF_03_ReplayDeterminism(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	sigs := fixedSignals(base)
	queryAt := base.Add(20 * time.Second)

	first := runOnce(t, sigs, queryAt)
	second := runOnce(t, sigs, queryAt)

	if len(first) != len(second) {
		t.Fatalf("plan count differs: first=%d second=%d", len(first), len(second))
	}
	for lin, a := range first {
		b := second[lin]
		if (a == nil) != (b == nil) {
			t.Errorf("lineage %d: presence differs first=%v second=%v", lin, a, b)
			continue
		}
		if a == nil {
			continue
		}
		if a.Tier != b.Tier {
			t.Errorf("lineage %d: Tier differs %q vs %q", lin, a.Tier, b.Tier)
		}
		if a.Score != b.Score {
			t.Errorf("lineage %d: Score differs %d vs %d", lin, a.Score, b.Score)
		}
		if a.RuleID != b.RuleID {
			t.Errorf("lineage %d: RuleID differs %q vs %q", lin, a.RuleID, b.RuleID)
		}
		if !equalStringSlice(a.Actions, b.Actions) {
			t.Errorf("lineage %d: Actions differ %v vs %v", lin, a.Actions, b.Actions)
		}
		if !equalStringSlice(a.Warnings, b.Warnings) {
			t.Errorf("lineage %d: Warnings differ %v vs %v", lin, a.Warnings, b.Warnings)
		}
	}
}

// F-03b: replay determinism across signal order. The same signal
// SET in two different ORDERS should produce the same plan,
// because the scorer normalises by kind and timestamp.
func TestF_03b_OrderInsensitivity(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	sigs := fixedSignals(base)
	queryAt := base.Add(20 * time.Second)

	first := runOnce(t, sigs, queryAt)

	// Reverse order
	reversed := make([]Signal, len(sigs))
	for i, s := range sigs {
		reversed[len(sigs)-1-i] = s
	}
	second := runOnce(t, reversed, queryAt)

	for lin, a := range first {
		b := second[lin]
		if (a == nil) != (b == nil) {
			t.Errorf("lineage %d: order-flip changed plan presence first=%v second=%v", lin, a, b)
			continue
		}
		if a == nil {
			continue
		}
		if a.Tier != b.Tier || a.Score != b.Score {
			t.Errorf("lineage %d: order-flip changed plan: tier %q→%q score %d→%d",
				lin, a.Tier, b.Tier, a.Score, b.Score)
		}
	}
}

func equalStringSlice(a, b []string) bool {
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

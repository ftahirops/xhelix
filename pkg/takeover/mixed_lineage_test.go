// P-PS.32 — the β-tier "mixed lineage isolation" tests.
//
// These are the most important tests for the production claim:
// the takeover scorer + planner must produce a high-score
// isolation plan for an attacker lineage WITHOUT poisoning the
// scores of legitimate lineages running concurrently. If signals
// leak between lineages, every legit process gets quarantined by
// association — that is the user's nightmare scenario.

package takeover

import (
	"sync"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/actionlog"
)

// helper: build a planner with TTL long enough to keep all signals in
// the window. Returns a fresh actionlog so each test is isolated.
func newPlannerForTest(_ *testing.T) *Planner {
	return NewPlanner(PlannerConfig{
		State: actionlog.New(),
		TTL:   time.Hour,
	})
}

// L3-07: mixed legit + attack signals across 11 lineages.
// One attack lineage fires 10 attack-class signals; ten legit
// lineages each fire 2 noisy-but-legit signals. Assert:
//   - The attack lineage produces a hard-action plan (Suspend or stronger)
//   - NO legit lineage produces a hard-action plan
//   - Each lineage's plan refers to its own LineageID, never a
//     neighbour's (no cross-pollination via map iteration order
//     or mutex bugs).
func TestL3_07_MixedLineage_AttackIsolated(t *testing.T) {
	p := newPlannerForTest(t)
	const attackLineage = uint64(9999)

	// Drop the full attack chain on the attacker lineage.
	attackSignals := []SignalKind{
		SignalShellAttempt,     // hard signal
		SignalRWXMemory,        // memory-exploit primitive
		SignalForbiddenSyscall, // seccomp denial
		SignalForbiddenConnect, // outbound to unknown
		SignalBase64Decode,     // dropper staging
		SignalChmodExec,        // dropper finalize
		SignalCredAccess,       // /etc/shadow read
		SignalPersistence,      // cron drop
		SignalLOTL,             // living-off-the-land
		SignalRecursiveDelete,  // anti-forensics
	}
	for _, k := range attackSignals {
		p.OnSignal(Signal{LineageID: attackLineage, Kind: k, Source: "attack-pod"})
	}

	// Ten legit lineages each fire 2 low-severity signals that
	// alone should not promote them past tier-observed.
	legitLineages := make([]uint64, 0, 10)
	for i := 0; i < 10; i++ {
		l := uint64(1000 + i)
		legitLineages = append(legitLineages, l)
		// "Noisy" but individually low-weight: a new binary
		// (could be apt installing) + a new endpoint (could be
		// snap refresh phoning home).
		p.OnSignal(Signal{LineageID: l, Kind: SignalNewBinary, Source: "apt"})
		p.OnSignal(Signal{LineageID: l, Kind: SignalNewEndpoint, Source: "snap"})
	}

	now := time.Now().UTC()

	attackPlan := p.Plan(attackLineage, now)
	if attackPlan == nil {
		t.Fatal("attacker lineage produced NO plan — scorer failure")
	}
	if !attackPlan.IsHardAction() {
		t.Errorf("attacker plan not hard-action: tier=%s actions=%v",
			attackPlan.Tier, attackPlan.Actions())
	}
	if attackPlan.LineageID != attackLineage {
		t.Errorf("attacker plan.LineageID = %d, want %d", attackPlan.LineageID, attackLineage)
	}

	for _, l := range legitLineages {
		got := p.Plan(l, now)
		if got != nil && got.IsHardAction() {
			t.Errorf("LEGIT lineage %d incorrectly produced hard-action plan: tier=%s actions=%v",
				l, got.Tier, got.Actions())
		}
		// Cross-pollination guard: if a plan exists, its LineageID
		// must match the queried lineage.
		if got != nil && got.LineageID != l {
			t.Errorf("legit lineage %d's plan reports lineage_id=%d (cross-pollination!)",
				l, got.LineageID)
		}
	}
}

// L3-07b: same setup but with attack signals INTERLEAVED with
// legit signals — order-of-arrival sensitivity check. Some bugs
// only surface when signals interleave (shared mutex bug, map
// iteration order, ttl bucket cross-contamination).
func TestL3_07b_InterleavedSignals(t *testing.T) {
	p := newPlannerForTest(t)
	const attackLineage = uint64(7777)

	for i := 0; i < 5; i++ {
		// Fire one attack signal
		p.OnSignal(Signal{
			LineageID: attackLineage,
			Kind:      []SignalKind{SignalShellAttempt, SignalRWXMemory, SignalCredAccess, SignalPersistence, SignalLOTL}[i],
			Source:    "attacker",
		})
		// Then fire two legit signals on five distinct legit lineages
		for j := 0; j < 2; j++ {
			l := uint64(2000 + i*2 + j)
			p.OnSignal(Signal{LineageID: l, Kind: SignalNewBinary, Source: "apt"})
		}
	}

	now := time.Now().UTC()
	attackPlan := p.Plan(attackLineage, now)
	if attackPlan == nil || !attackPlan.IsHardAction() {
		t.Errorf("interleaved attack signals failed to promote: plan=%+v", attackPlan)
	}
	for i := 0; i < 10; i++ {
		l := uint64(2000 + i)
		got := p.Plan(l, now)
		if got != nil && got.IsHardAction() {
			t.Errorf("legit lineage %d incorrectly hard-action under interleaved feed", l)
		}
	}
}

// E-01: TWO INDEPENDENT ATTACKERS on the same host must produce
// TWO distinct hard-action plans (one per attacker lineage). The
// scorer must not merge them or drop one.
func TestE_01_TwoAttackersIsolation(t *testing.T) {
	p := newPlannerForTest(t)
	const a, b = uint64(111), uint64(222)

	// Two distinct attack chains, same signal mix, different lineage.
	for _, l := range []uint64{a, b} {
		p.OnSignal(Signal{LineageID: l, Kind: SignalShellAttempt, Source: "atk"})
		p.OnSignal(Signal{LineageID: l, Kind: SignalRWXMemory, Source: "atk"})
		p.OnSignal(Signal{LineageID: l, Kind: SignalPersistence, Source: "atk"})
		p.OnSignal(Signal{LineageID: l, Kind: SignalCredAccess, Source: "atk"})
	}

	now := time.Now().UTC()
	planA := p.Plan(a, now)
	planB := p.Plan(b, now)

	if planA == nil || planB == nil {
		t.Fatalf("one of the two attackers got no plan: A=%v B=%v", planA, planB)
	}
	if !planA.IsHardAction() || !planB.IsHardAction() {
		t.Errorf("both should be hard-action; A.tier=%s B.tier=%s", planA.Tier, planB.Tier)
	}
	if planA.LineageID == planB.LineageID {
		t.Errorf("plans collapsed onto same LineageID: A=%d B=%d", planA.LineageID, planB.LineageID)
	}
	if planA.PlanID == planB.PlanID {
		t.Errorf("plans share PlanID — must be distinct: %q", planA.PlanID)
	}
}

// L1.5 DoS: attacker spams 10,000 of the same signal kind on one
// lineage. The diminishing-returns logic must prevent that
// lineage's score from monotonically rising past the per-kind
// ceiling AND must not exhaust memory.
func TestDoS_SameKindFloodHandled(t *testing.T) {
	p := newPlannerForTest(t)
	const flooder = uint64(31337)

	for i := 0; i < 10000; i++ {
		p.OnSignal(Signal{
			LineageID: flooder,
			Kind:      SignalNewEndpoint, // low-weight kind
			Source:    "noise",
		})
	}
	now := time.Now().UTC()
	plan := p.Plan(flooder, now)
	// With diminishing returns the single-kind flood should NOT
	// produce a hard-action plan even at 10k signals. The right
	// answer: either nil or a soft action only.
	if plan != nil && plan.IsHardAction() {
		t.Errorf("10k same-kind signals incorrectly promoted to hard-action: tier=%s actions=%v",
			plan.Tier, plan.Actions())
	}

	// Now add ONE additional high-weight signal of a different
	// kind. The combo should now correctly fire.
	p.OnSignal(Signal{LineageID: flooder, Kind: SignalShellAttempt, Source: "real-atk"})
	plan = p.Plan(flooder, now)
	if plan == nil || !plan.IsHardAction() {
		t.Errorf("flood + one high-weight signal failed to promote: plan=%+v", plan)
	}
}

// Concurrency variant of L3-07: lineages fed from 50 parallel
// goroutines must not produce score-leakage across boundaries.
// Catches races in the per-lineage signal map.
func TestL3_07c_ConcurrentLineages_NoLeakage(t *testing.T) {
	p := newPlannerForTest(t)
	const attackLineage = uint64(8888)

	var wg sync.WaitGroup
	// Goroutine fires attack signals on 8888.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			kinds := []SignalKind{
				SignalShellAttempt, SignalRWXMemory, SignalPersistence,
				SignalCredAccess, SignalLOTL,
			}
			p.OnSignal(Signal{
				LineageID: attackLineage,
				Kind:      kinds[i%len(kinds)],
				Source:    "atk",
			})
		}
	}()
	// 50 goroutines fire legit signals on 50 distinct lineages.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(l uint64) {
			defer wg.Done()
			p.OnSignal(Signal{LineageID: l, Kind: SignalNewBinary, Source: "apt"})
			p.OnSignal(Signal{LineageID: l, Kind: SignalNewEndpoint, Source: "snap"})
		}(uint64(5000 + i))
	}
	wg.Wait()

	now := time.Now().UTC()
	attackPlan := p.Plan(attackLineage, now)
	if attackPlan == nil || !attackPlan.IsHardAction() {
		t.Errorf("concurrent attack lineage failed to promote: %+v", attackPlan)
	}
	for i := 0; i < 50; i++ {
		l := uint64(5000 + i)
		got := p.Plan(l, now)
		if got != nil && got.IsHardAction() {
			t.Errorf("concurrent legit lineage %d incorrectly hard-action: %+v", l, got)
		}
	}
}

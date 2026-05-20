package takeover

import (
	"time"

	"github.com/xhelix/xhelix/pkg/actionlog"
	"github.com/xhelix/xhelix/pkg/decision"
	"github.com/xhelix/xhelix/pkg/model"
)

// Planner glues the per-lineage Aggregator + Scorer to
// decision.Plan(). It is the FIRST live consumer of all three
// foundation types from P-RF.2/3/4.
//
// Usage:
//
//   p := takeover.NewPlanner(takeover.PlannerConfig{...})
//   // dispatcher calls p.OnSignal(s) as signals fan in
//   // dispatcher periodically calls p.Tick(now) to emit plans
//
// Planner is pure-Go and side-effect-free — it never executes
// actions. The dispatcher (P-RF.7) decides what to do with the
// emitted ActionPlan: pass it to actionlog.Log.Record() and to the
// executor (P-RF.9).
type Planner struct {
	Agg    *Aggregator
	Scorer *Scorer
	State  *actionlog.Log
	Caps   decision.CapabilityChecker

	// MinScoreToPlan filters: scores below this don't produce a
	// non-trivial plan. Tunable per deployment. Default 50 — matches
	// FULL_TAKEOVER §4.1 lower threshold (Triaged).
	MinScoreToPlan int

	// CrownJewelTier resolver — optional. Looks up the protection
	// tier (L1..L6) for the targeted resource of an alert. nil ⇒
	// always "" (treated as non-CJ).
	ResolveCJTier func(alert model.Alert) string

	// PreconditionProbe — optional. Called when the planner is about
	// to emit an Isolate/Contained plan; returns whether bastion +
	// off-host mirror are available right now. nil ⇒ both false,
	// which makes the planner downgrade Layer-5 to Layer-4.
	PreconditionProbe func() (bastion, mirror bool)
}

// PlannerConfig is a small constructor struct.
type PlannerConfig struct {
	TTL               time.Duration
	Weights           Weights
	State             *actionlog.Log
	Caps              decision.CapabilityChecker
	MinScoreToPlan    int
	ResolveCJTier     func(alert model.Alert) string
	PreconditionProbe func() (bastion, mirror bool)
}

// NewPlanner wires up an Aggregator + Scorer with the given config.
func NewPlanner(c PlannerConfig) *Planner {
	min := c.MinScoreToPlan
	if min <= 0 {
		min = 50
	}
	return &Planner{
		Agg:               NewAggregator(c.TTL),
		Scorer:            NewScorer(c.Weights),
		State:             c.State,
		Caps:              c.Caps,
		MinScoreToPlan:    min,
		ResolveCJTier:     c.ResolveCJTier,
		PreconditionProbe: c.PreconditionProbe,
	}
}

// OnSignal records a signal in the aggregator. Cheap; safe to call
// from sensor goroutines.
func (p *Planner) OnSignal(s Signal) {
	p.Agg.Record(s)
}

// Plan computes an ActionPlan for one lineage at `now`. Returns nil
// if the lineage has no signals or the score is sub-threshold AND
// no current ContainmentState would be held.
//
// Note: this DOES NOT consult Alert — it builds a synthetic Alert
// using the most recent signal as provenance. The dispatcher
// version (PlanFromAlert below) takes a model.Alert directly.
func (p *Planner) Plan(lineageID uint64, now time.Time) *decision.ActionPlan {
	sigs := p.Agg.Snapshot(lineageID, now)
	if len(sigs) == 0 {
		return nil
	}
	res := p.Scorer.Score(sigs)

	// Skip emission entirely if score is sub-threshold AND no current
	// state to hold.
	if res.Score < p.MinScoreToPlan {
		if p.State == nil || p.State.State(lineageID) == actionlog.StateObserved {
			return nil
		}
	}

	// Build a synthetic alert from the latest signal.
	last := sigs[len(sigs)-1]
	alert := model.Alert{
		Event:  syntheticEvent(last),
		RuleID: "takeover.composite",
		Reason: lineageReason(res, last),
	}

	return p.planWithAlert(alert, res, lineageID, now)
}

// PlanFromAlert builds an ActionPlan for the lineage referenced by a
// specific alert. Used when the dispatcher already has an Alert in
// hand and wants the planner's verdict on it.
func (p *Planner) PlanFromAlert(alert model.Alert, lineageID uint64, now time.Time) *decision.ActionPlan {
	sigs := p.Agg.Snapshot(lineageID, now)
	res := p.Scorer.Score(sigs)
	return p.planWithAlert(alert, res, lineageID, now)
}

func (p *Planner) planWithAlert(alert model.Alert, res Result, lineageID uint64, now time.Time) *decision.ActionPlan {
	in := decision.Input{
		Alert:         alert,
		Score:         res.Score,
		LineageID:     lineageID,
		Caps:          p.Caps,
		State:         p.State,
		AttributedIPs: p.Agg.AttributedIPs(lineageID),
	}
	if p.ResolveCJTier != nil {
		in.CrownJewelTier = p.ResolveCJTier(alert)
	}
	if p.PreconditionProbe != nil {
		in.BastionAvailable, in.OffHostMirrorAvailable = p.PreconditionProbe()
	}
	return decision.Plan(in)
}

// Forget drops aggregator state for a lineage. Caller invokes this
// after a Released or Terminated transition is logged.
func (p *Planner) Forget(lineageID uint64) { p.Agg.Forget(lineageID) }

// syntheticEvent builds a thin model.Event from the most recent
// signal, just enough for ActionPlan provenance. Real events from
// sensors come through PlanFromAlert.
func syntheticEvent(s Signal) model.Event {
	ev := model.NewEvent("takeover.planner", model.SeverityHigh)
	ev.Time = s.At
	if s.Detail != "" {
		ev.Tags["last_signal"] = string(s.Kind) + ":" + s.Detail
	} else {
		ev.Tags["last_signal"] = string(s.Kind)
	}
	return ev
}

func lineageReason(res Result, last Signal) string {
	// Keep it short — the full breakdown is in Result.Contributions
	// and gets logged separately by the dispatcher.
	if last.Detail != "" {
		return "takeover score=" + itoa(res.Score) + " last=" + string(last.Kind) + ":" + last.Detail
	}
	return "takeover score=" + itoa(res.Score) + " last=" + string(last.Kind)
}

// itoa avoids importing strconv just for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

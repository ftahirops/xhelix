// Package wire is the daemon-side glue that connects the legacy
// pkg/alert path to the canonical pkg/decision + pkg/takeover +
// pkg/response.Executor pipeline.
//
// Shadow mode by default: the planner observes signals derived
// from legacy alerts and computes ActionPlans, but the executor
// only LOGS what it would do — the legacy pkg/response.Engine
// remains the authoritative action path. Operators flip
// Config.Active to migrate authority over.
//
// Why shadow first: the planner pipeline is brand-new code. Until
// operators have verified that "the plans look right" on their
// own traffic, the daemon must not double-execute (or, worse,
// regress). Shadow mode catches drift without changing behaviour.
//
// Daemon wiring lands in P-RF.9b. The harness here is self-
// contained and unit-testable; runDaemon's actual wire-up is a
// ~10-line construction + emit-hook.
package wire

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/actionlog"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/response"
	"github.com/xhelix/xhelix/pkg/runtime"
	"github.com/xhelix/xhelix/pkg/takeover"
)

// Config tunes how the planner pipeline behaves.
type Config struct {
	Log *slog.Logger

	// Active flips authority: false (default) = shadow mode (log only),
	// true = ActionPlans actually run via Executor.
	Active bool

	// TickInterval — how often to walk active lineages and emit
	// plans. Default 5s.
	TickInterval time.Duration

	// MinScoreToPlan — passed to takeover.PlannerConfig.
	// Default 50 (the planner's own default).
	MinScoreToPlan int

	// Bastion + OffHostMirror availability for Layer-5 plans.
	// Defaults: false (Layer-5 plans downgrade to Layer-4).
	BastionAvailable       bool
	OffHostMirrorAvailable bool
}

func (c Config) defaulted() Config {
	d := c
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.TickInterval <= 0 {
		d.TickInterval = 5 * time.Second
	}
	return d
}

// PlannerWiring is the runtime composition. One per daemon.
type PlannerWiring struct {
	cfg    Config // immutable after New
	active atomic.Bool

	Caps *runtime.CapabilitySet
	Log  *actionlog.Log
	Plan *takeover.Planner
	Exec *response.Executor

	// shadowed counts ActionPlans the planner emitted while in
	// shadow mode (would-have-executed). Exported via Stats.
	shadowed atomic.Int64
	executed atomic.Int64
	rejected atomic.Int64
}

// New constructs a fully wired PlannerWiring. The caller supplies
// the existing response.Engine (which Engine.OnAlert continues to
// own); the Executor here is a SIBLING consumer.
func New(cfg Config, engine *response.Engine) *PlannerWiring {
	cfg = cfg.defaulted()
	caps := runtime.New()
	caps.Discover()
	log := actionlog.New()

	planner := takeover.NewPlanner(takeover.PlannerConfig{
		State:          log,
		Caps:           caps,
		MinScoreToPlan: cfg.MinScoreToPlan,
		PreconditionProbe: func() (bool, bool) {
			return cfg.BastionAvailable, cfg.OffHostMirrorAvailable
		},
	})
	exec := response.NewExecutor(engine)

	pw := &PlannerWiring{
		cfg:  cfg,
		Caps: caps,
		Log:  log,
		Plan: planner,
		Exec: exec,
	}
	pw.active.Store(cfg.Active)
	return pw
}

// OnAlert is the bus-side hook. The daemon's emit closure calls
// this BEFORE / IN ADDITION TO Engine.OnAlert. Maps the alert to a
// takeover.Signal and feeds the planner. Does NOT execute — the
// periodic Tick() does that.
func (p *PlannerWiring) OnAlert(a model.Alert) {
	sig := AlertToSignal(a)
	if sig.Kind == "" {
		return
	}
	p.Plan.OnSignal(sig)
}

// Tick runs the periodic plan-and-execute loop. Returns when ctx
// is cancelled. Caller invokes via `go pw.Tick(ctx)`.
func (p *PlannerWiring) Tick(ctx context.Context) {
	t := time.NewTicker(p.cfg.TickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			p.tickOnce(ctx, now)
		}
	}
}

// tickOnce walks every lineage with live signals, calls Plan(),
// and either executes (active mode) or logs (shadow mode).
func (p *PlannerWiring) tickOnce(ctx context.Context, now time.Time) {
	lineages := p.Plan.Agg.Lineages(now)
	for _, lid := range lineages {
		plan := p.Plan.Plan(lid, now)
		if plan == nil || plan.IsNoOp() {
			continue
		}
		// Build a synthetic alert from the most recent signal so
		// Engine's existing backends (which expect model.Alert)
		// can run unmodified.
		alert := lineageToSyntheticAlert(p.Plan.Agg.Snapshot(lid, now))

		if !p.active.Load() {
			p.shadowed.Add(1)
			p.cfg.Log.Info("planner shadow",
				"plan_id", plan.PlanID,
				"lineage", lid,
				"tier", plan.Tier,
				"score", plan.Score,
				"actions", plan.Actions(),
				"warnings", plan.CapabilityWarnings,
			)
			continue
		}

		// Active mode — run the ActionPlan through Executor.
		// Also record the state transition in actionlog so the
		// audit trail captures what authority changed when.
		from := p.Log.State(lid)
		to := tierToState(plan.Tier)
		if from != to && actionlog.CanTransition(from, to) {
			if err := p.Log.Record(actionlog.Transition{
				LineageID: lid, From: from, To: to,
				Reason: "planner: " + plan.RuleID, PlanID: plan.PlanID,
			}); err != nil {
				p.rejected.Add(1)
				p.cfg.Log.Warn("actionlog record refused",
					"err", err, "plan_id", plan.PlanID, "from", from, "to", to)
				continue
			}
		}
		res := p.Exec.Execute(ctx, plan, alert)
		p.executed.Add(1)
		if res != nil {
			p.cfg.Log.Info("planner executed",
				"plan_id", plan.PlanID, "lineage", lid,
				"ran", res.Ran, "deferred", res.Deferred,
				"warnings", res.Warnings)
		}
	}
}

// Stats are observable counters for the wiring.
type Stats struct {
	Shadowed int64
	Executed int64
	Rejected int64
}

// Stats returns a snapshot of wiring counters.
func (p *PlannerWiring) Stats() Stats {
	return Stats{
		Shadowed: p.shadowed.Load(),
		Executed: p.executed.Load(),
		Rejected: p.rejected.Load(),
	}
}

// MarkActive flips the wiring from shadow → active. Caller is
// responsible for ensuring the legacy Engine.OnAlert path is
// stopped (or both paths will run, double-executing actions).
// Safe for concurrent use with Tick().
func (p *PlannerWiring) MarkActive() { p.active.Store(true) }

// IsActive reports the current authority mode.
func (p *PlannerWiring) IsActive() bool { return p.active.Load() }

// --- helpers ---

// AlertToSignal maps a legacy model.Alert into a takeover.Signal
// for the planner aggregator. The mapping is conservative:
// well-known RuleIDs become high-confidence signals; unknown rules
// become SignalRuleHit with weight derived from severity.
//
// CGroupID is used as the LineageID proxy. Real lineage tracking
// is P-RC.4 territory.
func AlertToSignal(a model.Alert) takeover.Signal {
	kind := mapRuleIDToKind(a.RuleID)
	if kind == "" {
		// Generic mapping by severity.
		switch a.Event.Severity {
		case model.SeverityCritical, model.SeverityHigh:
			kind = takeover.SignalRuleHit
		default:
			return takeover.Signal{}
		}
	}
	lid := uint64(a.Event.CGroupID)
	if lid == 0 {
		lid = uint64(a.Event.PID) // fall-back so the planner can still aggregate
	}
	return takeover.Signal{
		LineageID:  lid,
		Kind:       kind,
		At:         a.Event.Time,
		Source:     "alert:" + a.RuleID,
		Detail:     a.Reason,
		Confidence: severityToConfidence(a.Event.Severity),
		Weight:     weightForRuleMode(a.Mode),
		RemoteIP:   firstNonEmpty(a.Event.Tags["src_ip"], a.Event.Tags["dst_ip"]),
	}
}

// mapRuleIDToKind translates legacy RuleIDs the dispatcher emits
// into the new SignalKind taxonomy. Unmapped RuleIDs return ""
// (caller falls back to generic mapping).
func mapRuleIDToKind(ruleID string) takeover.SignalKind {
	switch ruleID {
	case "lolbin.suspicious":
		return takeover.SignalLOTL
	case "revshell.detected":
		return takeover.SignalShellAttempt
	case "shm.exec":
		return takeover.SignalRWXMemory
	case "webshell.argv":
		return takeover.SignalInterpAttempt
	case "cap.gained":
		return takeover.SignalCapAbuse
	case "contescape.detected":
		return takeover.SignalDefenseEvasion
	case "ptrace.suspicious":
		return takeover.SignalDefenseEvasion
	case "metadata.access_by_unexpected":
		return takeover.SignalLateralMove
	case "phishing.brand_lookalike":
		return takeover.SignalForbiddenConnect
	case "intel.bad_ip":
		return takeover.SignalC2Beacon
	case "beacon.periodic_callback":
		return takeover.SignalC2Beacon
	case "dnsexfil.tunnel_pattern":
		return takeover.SignalForbiddenConnect
	case "netids.dga":
		return takeover.SignalForbiddenConnect
	case "ml.anomaly":
		return takeover.SignalRuleHit
	case "baseline.behavioural_deviation",
		"baseline.rate_spike":
		return takeover.SignalNewBinary
	}
	return ""
}

func severityToConfidence(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "deterministic"
	case model.SeverityHigh:
		return "high"
	case model.SeverityWarn:
		return "medium"
	}
	return "low"
}

func weightForRuleMode(m model.RuleMode) int {
	// Override default-weight when the rule itself signals stronger
	// intent than the kind table would carry.
	switch m {
	case model.ModeBlock:
		return 95
	case model.ModeQuarantine:
		return 80
	}
	return 0 // 0 = use the kind's default weight
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func tierToState(tier string) actionlog.ContainmentState {
	switch tier {
	case "triaged":
		return actionlog.StateTriaged
	case "suspended":
		return actionlog.StateSuspended
	case "isolated":
		return actionlog.StateIsolated
	case "contained":
		return actionlog.StateContained
	}
	return actionlog.StateObserved
}

// lineageToSyntheticAlert builds a model.Alert from the snapshot
// of signals on one lineage. Used by the active-mode tick path
// where the Executor's backends still expect model.Alert.
func lineageToSyntheticAlert(sigs []takeover.Signal) model.Alert {
	ev := model.NewEvent("planner.tick", model.SeverityHigh)
	if len(sigs) == 0 {
		return model.Alert{Event: ev, RuleID: "takeover.composite"}
	}
	last := sigs[len(sigs)-1]
	ev.Time = last.At
	if last.RemoteIP != "" {
		// Engine.doNetBan reads src_ip — propagate so the ban path
		// can fire when the planner asked for BanRemoteIP.
		ev.Tags["src_ip"] = last.RemoteIP
		ev.Tags["dst_ip"] = last.RemoteIP
		ev.Tags["src"] = last.RemoteIP
	}
	// Use net.IP probe just to drop obviously-bad values from
	// downstream consumers.
	if ip := net.ParseIP(last.RemoteIP); ip != nil && !ip.IsUnspecified() {
		ev.Tags["src_ip"] = ip.String()
	}
	return model.Alert{
		Event:  ev,
		RuleID: "takeover.composite",
		Reason: last.Detail,
		Mode:   model.ModeDetect,
	}
}

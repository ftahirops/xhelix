package response

import (
	"context"
	"sync/atomic"

	"github.com/xhelix/xhelix/pkg/decision"
	"github.com/xhelix/xhelix/pkg/model"
)

// Executor is the canonical consumer of decision.ActionPlan.
// Bridges the new planner output (pkg/decision) to the existing
// Engine backends (do* methods on Engine).
//
// Extracted in P-RF.9. Behaviour-preserving: each action bit on
// ActionPlan maps 1:1 to an existing Engine.do* method, called in
// the same order as Engine.OnAlert's bitmask walk.
//
// Why a separate type rather than expanding Engine: the existing
// Engine takes a model.Alert + a RuleID-keyed policy map. The new
// path takes an ActionPlan directly — no policy lookup, the planner
// already decided. Keeping them as siblings means the legacy
// OnAlert flow (rules-engine alerts) and the new Execute flow
// (planner-emitted plans) can coexist during the migration without
// either having to know about the other.
type Executor struct {
	Engine *Engine

	// ResultSink, if set, is called once per Execute with the
	// recorded action outcomes. Lets the dispatcher push the
	// execution record into pkg/actionlog (transitions, audit).
	ResultSink func(*Result)

	// Stats
	plansExecuted atomic.Int64
	actionsRun    atomic.Int64
	actionsDeferred atomic.Int64 // skipped because the backend isn't available
}

// Result records what Execute() actually did. Includes which
// actions ran, which were deferred (no backend), and any capability
// warnings already carried by the plan.
type Result struct {
	PlanID         string
	LineageID      uint64
	Tier           string
	Ran            []string // action names that executed
	Deferred       []string // action names skipped (no backend or unsupported)
	Warnings       []string // copied from plan.CapabilityWarnings
}

// NewExecutor wraps an Engine.
func NewExecutor(e *Engine) *Executor {
	return &Executor{Engine: e}
}

// Execute walks the plan's enabled actions in canonical order
// (matching ActionPlan.Actions()) and dispatches each to the
// matching Engine backend. The alert provides the Event +
// RuleID context the existing do* methods need.
//
// If the panic switch is armed, Execute logs and returns a Result
// with everything in Deferred — same semantics as OnAlert under
// panic.
func (x *Executor) Execute(ctx context.Context, plan *decision.ActionPlan, alert model.Alert) *Result {
	if plan == nil || x.Engine == nil {
		return nil
	}
	x.plansExecuted.Add(1)
	res := &Result{
		PlanID:    plan.PlanID,
		LineageID: plan.LineageID,
		Tier:      plan.Tier,
		Warnings:  append([]string(nil), plan.CapabilityWarnings...),
	}

	if x.Engine.panicSwitch != nil && x.Engine.panicSwitch.Armed() {
		// Defer everything — same posture as the OnAlert path.
		res.Deferred = append(res.Deferred, plan.Actions()...)
		if x.ResultSink != nil {
			x.ResultSink(res)
		}
		return res
	}

	// Action order MUST match ActionPlan.Actions() — snapshot
	// FIRST (evidence preservation), kill_process LAST.
	if plan.Snapshot {
		x.run(res, "snapshot", func() { x.Engine.doSnapshot(alert) })
	}
	if plan.Memscan {
		x.run(res, "memscan", func() { x.Engine.doMemScan(alert) })
	}
	if plan.Delay > 0 {
		// Soft-enforce: no backend yet. Record + defer.
		x.defer_(res, "delay")
	}
	if plan.RequireStepUp {
		x.defer_(res, "require_step_up")
	}
	if plan.SuspendProcess {
		x.run(res, "suspend_process", func() { x.Engine.doQuarantine(alert) })
	}
	if plan.IsolateCgroup {
		// IsolateCgroup is fully covered by SuspendProcess + BanRemoteIP
		// in the existing Engine. If SuspendProcess didn't already
		// fire, do quarantine here too; otherwise mark deferred.
		if !plan.SuspendProcess {
			x.run(res, "isolate_cgroup", func() { x.Engine.doQuarantine(alert) })
		} else {
			x.defer_(res, "isolate_cgroup (covered by suspend_process)")
		}
	}
	if plan.BanRemoteIP {
		x.run(res, "ban_remote_ip", func() { x.Engine.doNetBan(alert) })
	}
	if plan.Tarpit {
		// Tarpit backend will land in a follow-on (P-FT.15 / P-PS
		// integration). For now log it deferred so operators see
		// what the planner asked for vs what shipped.
		x.defer_(res, "tarpit (backend pending P-FT.15)")
	}
	if plan.IsolateHost {
		x.run(res, "isolate_host", func() { x.Engine.doHostQuarantine(alert) })
	}
	if plan.RemediateFile {
		x.run(res, "remediate_file", func() { x.Engine.doRemediate(alert) })
	}
	if plan.LockLocalUser {
		x.run(res, "lock_local_user", func() { x.Engine.doLockUser(alert) })
	}
	if plan.KillProcess {
		// Kill ALWAYS runs after Snapshot (Validate() enforces it on
		// the plan side).
		x.run(res, "kill_process", func() { x.Engine.doKill(alert) })
	}

	// Webhook is not on ActionPlan — but the Engine ALWAYS sends a
	// webhook for the underlying alert when configured. Trigger it
	// here so the Execute path matches OnAlert observability.
	if x.Engine.webhook != nil {
		x.Engine.doWebhook(alert)
	}

	if x.ResultSink != nil {
		x.ResultSink(res)
	}
	return res
}

func (x *Executor) run(res *Result, name string, fn func()) {
	fn()
	res.Ran = append(res.Ran, name)
	x.actionsRun.Add(1)
}

func (x *Executor) defer_(res *Result, name string) {
	res.Deferred = append(res.Deferred, name)
	x.actionsDeferred.Add(1)
}

// ExecutorStats are observable counters for the Execute path.
type ExecutorStats struct {
	PlansExecuted   int64
	ActionsRun      int64
	ActionsDeferred int64
}

// Stats returns a snapshot of executor counters. Independent from
// Engine.Stats (which counts OnAlert dispatch).
func (x *Executor) Stats() ExecutorStats {
	return ExecutorStats{
		PlansExecuted:   x.plansExecuted.Load(),
		ActionsRun:      x.actionsRun.Load(),
		ActionsDeferred: x.actionsDeferred.Load(),
	}
}

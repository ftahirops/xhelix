// Package decision defines the canonical decision output for xhelix.
// Every detection-and-decision path emits an ActionPlan; every executor
// consumes only this. No more RuleID bitmasks, no more loose
// Alert.Mode strings, no more direct quarantine.Stop() shortcuts.
//
// See REFACTOR_ROADMAP.md §2.1 for the type contract and §3 for how
// each existing design (CONTAINMENT_DESIGN, FULL_TAKEOVER_DETECTION,
// BEHAVIORAL_DEFENSE) maps to ActionPlan field semantics.
//
// This package is the FOUNDATION. It has no consumers yet — the
// planner (P-RF.5) and executor (P-RF.9) consume it. Building the
// type first lets the planner and existing design docs reference
// concrete fields instead of placeholders.
package decision

import (
	"errors"
	"fmt"
	"time"
)

// ActionPlan is what every detection-and-decision path emits.
// Stable wire format — fields added with omitempty, never removed
// or renamed. Reversibility and audit are first-class.
type ActionPlan struct {
	// Provenance — who decided this and why.
	AlertID   string    `json:"alert_id"`
	PlanID    string    `json:"plan_id"`             // unique per ActionPlan emission
	RuleID    string    `json:"rule_id,omitempty"`   // "" for composition-derived plans
	LineageID uint64    `json:"lineage_id,omitempty"`
	ProcKey   string    `json:"proc_key,omitempty"`  // "pid@start_ticks"
	CreatedAt time.Time `json:"created_at"`

	// Confidence + tier — operator-readable summary.
	Score      int    `json:"score"`               // 0-100; see FULL_TAKEOVER_DETECTION.md §4.1
	Tier       string `json:"tier"`                // "observed", "triaged", "suspended", ...
	Confidence string `json:"confidence,omitempty"` // "deterministic", "high", "medium", "low"

	// Action bits — what to execute. Executor runs ENABLED actions
	// in the order documented below.
	Snapshot       bool          `json:"snapshot,omitempty"`        // /proc + memory snapshot BEFORE destructive ops
	Memscan        bool          `json:"memscan,omitempty"`         // YARA + IOC scan against process memory
	Delay          time.Duration `json:"delay,omitempty"`           // soft-enforce: inject latency on next sensitive op
	RequireStepUp  bool          `json:"require_step_up,omitempty"` // soft-enforce: fresh WebAuthn before next op
	SuspendProcess bool          `json:"suspend_process,omitempty"` // Layer 2 — SIGSTOP the lineage tree
	IsolateCgroup  bool          `json:"isolate_cgroup,omitempty"`  // Layers 3+4 — nft deny + LSM fs-jail + cap strip
	BanRemoteIP    bool          `json:"ban_remote_ip,omitempty"`   // pkg/netban — block destination
	Tarpit         bool          `json:"tarpit,omitempty"`          // Layer 6 — QoS slow-fail attacker IP
	IsolateHost    bool          `json:"isolate_host,omitempty"`    // Layer 5 — host-wide lockdown
	RemediateFile  bool          `json:"remediate_file,omitempty"`  // pkg/remediate — restore from baseline (non-reversible)
	LockLocalUser  bool          `json:"lock_local_user,omitempty"` // pkg/lockout — refuse new login sessions
	KillProcess    bool          `json:"kill_process,omitempty"`    // SIGKILL — ONLY after Snapshot completes (non-reversible)

	// Provenance + safety
	Reasons            []string  `json:"reasons,omitempty"`             // human-readable: "canary touched", "passport missing"
	Preconditions      []string  `json:"preconditions,omitempty"`       // must hold before action runs
	CapabilityWarnings []string  `json:"capability_warnings,omitempty"` // explicit degraded-mode reasons

	// Reversibility — see REFACTOR_ROADMAP.md §6 rule #2.
	Reversible bool      `json:"reversible"`            // defaults true; KillProcess/RemediateFile flip it false
	ExpiresAt  time.Time `json:"expires_at,omitempty"`  // auto-rollback boundary; zero = no expiry
}

// Action bit ordering for the executor. The planner sets bits; the
// executor walks this list and runs each enabled action in turn.
// Snapshot ALWAYS runs first (preserves evidence); KillProcess
// ALWAYS last (irreversible).
var actionOrder = []struct {
	name string
	get  func(*ActionPlan) bool
}{
	{"snapshot", func(p *ActionPlan) bool { return p.Snapshot }},
	{"memscan", func(p *ActionPlan) bool { return p.Memscan }},
	{"delay", func(p *ActionPlan) bool { return p.Delay > 0 }},
	{"require_step_up", func(p *ActionPlan) bool { return p.RequireStepUp }},
	{"suspend_process", func(p *ActionPlan) bool { return p.SuspendProcess }},
	{"isolate_cgroup", func(p *ActionPlan) bool { return p.IsolateCgroup }},
	{"ban_remote_ip", func(p *ActionPlan) bool { return p.BanRemoteIP }},
	{"tarpit", func(p *ActionPlan) bool { return p.Tarpit }},
	{"isolate_host", func(p *ActionPlan) bool { return p.IsolateHost }},
	{"remediate_file", func(p *ActionPlan) bool { return p.RemediateFile }},
	{"lock_local_user", func(p *ActionPlan) bool { return p.LockLocalUser }},
	{"kill_process", func(p *ActionPlan) bool { return p.KillProcess }},
}

// Actions returns the ordered list of enabled action names.
// Useful for the executor walk + operator dashboards.
func (p *ActionPlan) Actions() []string {
	out := make([]string, 0, len(actionOrder))
	for _, a := range actionOrder {
		if a.get(p) {
			out = append(out, a.name)
		}
	}
	return out
}

// IsNoOp reports whether the plan has zero enabled actions.
func (p *ActionPlan) IsNoOp() bool {
	return len(p.Actions()) == 0
}

// HasDestructiveAction reports whether the plan includes any
// destructive action (SIGKILL or remediate-file). Used to gate the
// operator confirmation flow described in CONTAINMENT_DESIGN.md §5.5.
func (p *ActionPlan) HasDestructiveAction() bool {
	return p.KillProcess || p.RemediateFile
}

// IsHardAction reports whether the plan represents a hard
// containment action (not just soft enforce). Per
// BEHAVIORAL_DEFENSE.md §5 composition rule: hard actions require a
// Tier-1 signal OR multiple stacked Tier-2/3.
func (p *ActionPlan) IsHardAction() bool {
	return p.SuspendProcess || p.IsolateCgroup || p.IsolateHost ||
		p.BanRemoteIP || p.KillProcess || p.RemediateFile ||
		p.LockLocalUser
}

// HasExpired reports whether the plan's auto-rollback timer has
// passed. Zero ExpiresAt means "no expiry" — returns false.
func (p *ActionPlan) HasExpired(now time.Time) bool {
	if p.ExpiresAt.IsZero() {
		return false
	}
	return now.After(p.ExpiresAt)
}

// Validate checks structural invariants. Returns the first error
// encountered. Called by the planner before emission; defensive
// against bugs in plan construction.
func (p *ActionPlan) Validate() error {
	if p == nil {
		return errors.New("decision: nil ActionPlan")
	}
	if p.AlertID == "" && p.RuleID == "" {
		return errors.New("decision: ActionPlan needs either AlertID or RuleID for provenance")
	}
	if p.PlanID == "" {
		return errors.New("decision: ActionPlan.PlanID is required")
	}
	if p.Score < 0 || p.Score > 100 {
		return fmt.Errorf("decision: Score %d out of range [0,100]", p.Score)
	}

	// Per REFACTOR_ROADMAP.md §6 rule #2: non-reversible actions
	// require Reversible=false explicitly. KillProcess and
	// RemediateFile cannot be reversible.
	if p.KillProcess && p.Reversible {
		return errors.New("decision: KillProcess actions cannot be Reversible=true")
	}
	if p.RemediateFile && p.Reversible {
		return errors.New("decision: RemediateFile actions cannot be Reversible=true")
	}

	// Per CONTAINMENT_DESIGN.md §13.3: IsolateHost requires
	// bastion + off-host mirror preconditions.
	if p.IsolateHost && len(p.Preconditions) == 0 {
		return errors.New("decision: IsolateHost requires Preconditions (bastion + off-host mirror)")
	}

	// Snapshot must come before destructive actions. The planner is
	// expected to set Snapshot=true alongside KillProcess; this
	// validator enforces it.
	if p.KillProcess && !p.Snapshot {
		return errors.New("decision: KillProcess requires Snapshot=true (evidence preservation)")
	}

	// Tarpit is opt-in per CONTAINMENT_DESIGN.md §2 — requires
	// high-confidence attribution. Validator can't check confidence
	// directly, but it requires the plan to indicate where
	// attribution came from via Reasons.
	if p.Tarpit && len(p.Reasons) == 0 {
		return errors.New("decision: Tarpit requires non-empty Reasons (attribution evidence)")
	}

	return nil
}

// Constructor helpers — make it harder to forget invariants.
//
// These don't allocate PlanID or AlertID; caller fills those in
// from the upstream alert.

// NewNoOp returns an ActionPlan with no enabled actions. Used by the
// planner when the alert is sub-threshold.
func NewNoOp(alertID, planID string) *ActionPlan {
	return &ActionPlan{
		AlertID:    alertID,
		PlanID:     planID,
		CreatedAt:  time.Now().UTC(),
		Tier:       "observed",
		Reversible: true,
	}
}

// NewSoftBlock returns a Layer-1 soft-enforce plan: delay + step-up.
// Reversibility is implicit (timeouts naturally end).
func NewSoftBlock(alertID, planID string, score int) *ActionPlan {
	return &ActionPlan{
		AlertID:       alertID,
		PlanID:        planID,
		CreatedAt:     time.Now().UTC(),
		Score:         score,
		Tier:          "triaged",
		Delay:         2 * time.Second,
		RequireStepUp: true,
		Reversible:    true,
		ExpiresAt:     time.Now().Add(15 * time.Minute),
	}
}

// NewSuspend returns a Layer-2 plan: SIGSTOP the lineage + snapshot
// + network jail. Default operating containment for confirmed
// suspicious activity.
func NewSuspend(alertID, planID string, score int) *ActionPlan {
	return &ActionPlan{
		AlertID:        alertID,
		PlanID:         planID,
		CreatedAt:      time.Now().UTC(),
		Score:          score,
		Tier:           "suspended",
		Snapshot:       true,
		SuspendProcess: true,
		IsolateCgroup:  true,
		BanRemoteIP:    true,
		Reversible:     true,
		ExpiresAt:      time.Now().Add(2 * time.Hour),
	}
}

// NewIsolate returns a Layer-4 plan: full per-process isolation.
// Adds capability strip + LSM fs-jail to the Suspend plan.
func NewIsolate(alertID, planID string, score int) *ActionPlan {
	p := NewSuspend(alertID, planID, score)
	p.Tier = "isolated"
	p.Memscan = true
	p.LockLocalUser = true
	return p
}

// NewContain returns a Layer-5 plan: host-wide lockdown.
// REQUIRES caller to populate Preconditions with bastion +
// off-host mirror availability — Validate() will reject otherwise.
func NewContain(alertID, planID string, score int, preconditions []string) *ActionPlan {
	p := NewIsolate(alertID, planID, score)
	p.Tier = "contained"
	p.IsolateHost = true
	p.Preconditions = preconditions
	return p
}

// AddCapabilityWarning records that an action couldn't fully
// execute due to a missing runtime capability. Per
// REFACTOR_ROADMAP.md §6 rule #3 — no silent degradation.
func (p *ActionPlan) AddCapabilityWarning(missing, action string) {
	p.CapabilityWarnings = append(p.CapabilityWarnings,
		fmt.Sprintf("%s skipped: missing capability %s", action, missing))
}

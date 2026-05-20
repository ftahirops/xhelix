package decision

import (
	"fmt"

	"github.com/oklog/ulid/v2"

	"github.com/xhelix/xhelix/pkg/actionlog"
	"github.com/xhelix/xhelix/pkg/model"
)

// CapabilityChecker is the contract Plan() needs from a runtime
// inventory. pkg/runtime.CapabilitySet satisfies it. Defining the
// interface here keeps pkg/decision free of dependencies on the
// (heavier) pkg/runtime — pkg/runtime depends on pkg/decision, not
// the other way around.
type CapabilityChecker interface {
	AnnotatePlan(*ActionPlan)
}

// Input is what Plan() consumes. The planner is a pure function of
// these inputs — it has no goroutines and no side effects on
// CapabilitySet or actionlog. The dispatcher records the resulting
// transition; the executor runs the plan.
type Input struct {
	// Alert is the upstream alert that triggered this planning call.
	// Alert.Mode and Alert.RuleID participate in the decision.
	Alert model.Alert

	// Score is the 0-100 composite from the scorer (pkg/takeover in
	// the post-refactor world). The planner does NOT compute the
	// score — it consumes it. Per FULL_TAKEOVER_DETECTION.md §4.1
	// thresholds: 50→triaged, 75→suspended, 90→isolated, 100→contained.
	Score int

	// LineageID identifies the process lineage this plan applies to.
	// Used to look up current ContainmentState and to stamp the plan.
	LineageID uint64

	// ProcKey is the PID-reuse-safe key ("pid@start_ticks").
	ProcKey string

	// Caps is the runtime capability set; annotates the plan with
	// warnings for missing capabilities. Nil = skip annotation
	// (useful for tests that don't care).
	Caps CapabilityChecker

	// State is the action log used to query current state and (after
	// the dispatcher records the transition) update it. Plan() only
	// reads.
	State *actionlog.Log

	// CrownJewelTier identifies the protection tier of the targeted
	// resource. "" means non-CJ; "L1".."L6" upgrade the plan per
	// CROWN_JEWEL_PROFILE.md §5. L1/L2 force at least Suspended even
	// at sub-threshold scores.
	CrownJewelTier string

	// AttributedIPs lists remote IPs attributed to this lineage by
	// high-confidence sensors. Non-empty enables BanRemoteIP at
	// suspended+, and enables Tarpit at isolated+. Empty disables.
	AttributedIPs []string

	// BastionAvailable + OffHostMirrorAvailable are operator-supplied
	// preconditions for IsolateHost (Layer 5). If either is false,
	// Plan() refuses to set IsolateHost and falls back to Isolated.
	BastionAvailable      bool
	OffHostMirrorAvailable bool
}

// Plan computes the canonical ActionPlan for an Input. Pure function.
//
// Composition logic, per REFACTOR_ROADMAP.md §2 + BEHAVIORAL_DEFENSE.md §5:
//
//  1. Map score → base tier (NoOp / Triaged / Suspended / Isolated / Contained).
//  2. Crown-jewel upgrade: L1/L2 force min Suspended; L3 forces min Triaged.
//  3. Rule mode upgrade: Alert.Mode=Quarantine forces min Suspended;
//     ModeBlock forces min Isolated.
//  4. No de-escalation: if current ContainmentState is higher than
//     the proposed tier, hold at current tier (only operator-driven
//     transitions de-escalate).
//  5. Layer-5 (Contained / IsolateHost) requires bastion + off-host
//     mirror; refuse to set if missing and downgrade to Isolated +
//     record a CapabilityWarning.
//  6. Tarpit + BanRemoteIP: enable only with at least one
//     AttributedIP and only at Suspended+.
//  7. Capability annotation: walk Caps.CanExecute(plan) and attach
//     warnings — never silently drop actions.
func Plan(in Input) *ActionPlan {
	planID := ulid.Make().String()

	tier := tierFromScore(in.Score)
	tier = upgradeForCrownJewel(tier, in.CrownJewelTier)
	tier = upgradeForRuleMode(tier, in.Alert.Mode)

	// No de-escalation: hold at current state if it's higher.
	if in.State != nil {
		currentTier := tierFromState(in.State.State(in.LineageID))
		if currentTier > tier {
			tier = currentTier
		}
	}

	p := buildPlanForTier(tier, in)
	p.PlanID = planID
	p.LineageID = in.LineageID
	p.ProcKey = in.ProcKey
	p.RuleID = in.Alert.RuleID
	p.Score = in.Score

	// Wire alert provenance.
	if p.AlertID == "" {
		// Use Event.ID as the alert id (alerts don't carry their own).
		p.AlertID = in.Alert.Event.ID.String()
	}

	// Layer-5 precondition check. The planner downgrades rather than
	// emitting an invalid plan; operator gets the warning.
	if p.IsolateHost && !(in.BastionAvailable && in.OffHostMirrorAvailable) {
		p.IsolateHost = false
		p.Tier = "isolated"
		p.AddCapabilityWarning("bastion+off-host-mirror", "isolate_host")
	} else if p.IsolateHost {
		p.Preconditions = append(p.Preconditions,
			"bastion_count>=2", "off_host_mirror")
	}

	// Attribution-gated actions.
	if p.BanRemoteIP && len(in.AttributedIPs) == 0 {
		p.BanRemoteIP = false
		p.Reasons = append(p.Reasons,
			"ban_remote_ip skipped: no attributed remote IPs")
	}
	if p.Tarpit && len(in.AttributedIPs) == 0 {
		p.Tarpit = false
	} else if p.Tarpit {
		p.Reasons = append(p.Reasons,
			fmt.Sprintf("tarpit attribution: %v", in.AttributedIPs))
	}

	// Provenance reason for the operator.
	if in.Alert.Reason != "" {
		p.Reasons = append(p.Reasons, in.Alert.Reason)
	}
	if in.CrownJewelTier != "" {
		p.Reasons = append(p.Reasons,
			fmt.Sprintf("crown-jewel tier=%s", in.CrownJewelTier))
	}

	// Annotate with capability warnings — explicit degraded mode.
	if in.Caps != nil {
		in.Caps.AnnotatePlan(p)
	}

	return p
}

// --- tier ladder ---

// internal tier ordering; higher = stronger containment.
type tier int

const (
	tierObserved tier = iota
	tierTriaged
	tierSuspended
	tierIsolated
	tierContained
)

func tierFromScore(score int) tier {
	switch {
	case score >= 100:
		return tierContained
	case score >= 90:
		return tierIsolated
	case score >= 75:
		return tierSuspended
	case score >= 50:
		return tierTriaged
	}
	return tierObserved
}

func tierFromState(s actionlog.ContainmentState) tier {
	switch s {
	case actionlog.StateContained:
		return tierContained
	case actionlog.StateIsolated:
		return tierIsolated
	case actionlog.StateSuspended:
		return tierSuspended
	case actionlog.StateTriaged:
		return tierTriaged
	}
	return tierObserved
}

// upgradeForCrownJewel: L1/L2 means "treat any suspicious activity
// as containment-worthy". See CROWN_JEWEL_PROFILE.md §5.
func upgradeForCrownJewel(base tier, cjTier string) tier {
	switch cjTier {
	case "L1", "L2":
		if base < tierSuspended {
			return tierSuspended
		}
	case "L3":
		if base < tierTriaged {
			return tierTriaged
		}
	}
	return base
}

// upgradeForRuleMode: legacy RuleMode field maps to minimum tiers.
// ModeQuarantine → at least Suspended; ModeBlock → at least Isolated.
func upgradeForRuleMode(base tier, mode model.RuleMode) tier {
	switch mode {
	case model.ModeQuarantine:
		if base < tierSuspended {
			return tierSuspended
		}
	case model.ModeBlock:
		if base < tierIsolated {
			return tierIsolated
		}
	}
	return base
}

func buildPlanForTier(t tier, in Input) *ActionPlan {
	switch t {
	case tierContained:
		return NewContain(in.Alert.Event.ID.String(), "", in.Score,
			[]string{"bastion_count>=2", "off_host_mirror"})
	case tierIsolated:
		return NewIsolate(in.Alert.Event.ID.String(), "", in.Score)
	case tierSuspended:
		return NewSuspend(in.Alert.Event.ID.String(), "", in.Score)
	case tierTriaged:
		return NewSoftBlock(in.Alert.Event.ID.String(), "", in.Score)
	}
	return NewNoOp(in.Alert.Event.ID.String(), "")
}

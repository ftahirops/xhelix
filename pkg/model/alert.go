package model

import (
	"context"

	"github.com/oklog/ulid/v2"
)

// RuleMode controls what a fired rule does.
//
// Detect (default) logs and alerts only. Quarantine adds SIGSTOP-style
// pid pause with a forensic snapshot. Block returns -EPERM via LSM
// hooks or drops via XDP. v0.1 ignores anything other than ModeDetect;
// quarantine and block are unlocked in Phase 7 (v1.0).
type RuleMode uint8

const (
	ModeDetect RuleMode = iota
	ModeQuarantine
	ModeBlock
)

// String returns the mode as a short, lowercase token.
func (m RuleMode) String() string {
	switch m {
	case ModeDetect:
		return "detect"
	case ModeQuarantine:
		return "quarantine"
	case ModeBlock:
		return "block"
	}
	return "unknown"
}

// Alert is the bus-level notification that a rule fired.
//
// Sinks consume Alert (not Event directly) so they can include the
// rule's reason and any enforcement action that was taken.
type Alert struct {
	Event       Event       `json:"event"`
	RuleID      string      `json:"rule_id"`
	Reason      string      `json:"reason,omitempty"`
	EvidenceIDs []ulid.ULID `json:"evidence_ids,omitempty"`
	Mode        RuleMode    `json:"mode"`
	Action      string      `json:"action,omitempty"`

	// Class buckets the firing rule for per-class FP accounting.
	//   1 = hard invariant       (auto-deny candidate;   FP <0.1%)
	//   2 = strong exploit signal (freeze candidate;     FP <0.5%)
	//   3 = soft behavior drift   (alert-only;           FP <5%)
	// Populated by the rule engine from model.Rule.Class.
	Class int `json:"class,omitempty"`
}

// Sink consumes alerts. Implementations must be safe for concurrent
// Send calls and must never block longer than their configured
// timeout. Unavailable sinks should fail fast and let the bus log.
type Sink interface {
	Name() string
	Send(ctx context.Context, a Alert) error
	Close() error
}

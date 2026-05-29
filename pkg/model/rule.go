package model

import (
	"strings"
	"time"
)

// Category classifies a rule by what its match means in the verdict
// model defined in docs/XHELIX_VERDICT_ENGINE_EDR_MODEL_2026-05-29.md.
//
//	fact         — structural observation. Records only. Never alerts on its
//	               own. Examples: process gained capability, TLS without SNI,
//	               namespace change.
//	weak_signal  — contributes to a per-PID score in the verdict engine.
//	               Never alerts on its own.
//	incident     — alerts when chain-confirmed (verdict engine threshold).
//	               May contribute to active response.
//	hard_deny    — explicit invariant violation. Alerts on every fire. May
//	               block depending on enforce mode. FP budget < 0.1%.
type Category uint8

const (
	CategoryWeakSignal Category = iota // default — explicit re-classification required
	CategoryFact
	CategoryIncident
	CategoryHardDeny
)

func (c Category) String() string {
	switch c {
	case CategoryFact:
		return "fact"
	case CategoryWeakSignal:
		return "weak_signal"
	case CategoryIncident:
		return "incident"
	case CategoryHardDeny:
		return "hard_deny"
	}
	return "weak_signal"
}

// ParseCategory accepts the YAML form (case-insensitive) and returns the
// matching Category. Unknown values return (CategoryWeakSignal, false) so
// the caller can still proceed safely while flagging the misconfiguration.
func ParseCategory(raw string) (Category, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "weak_signal":
		return CategoryWeakSignal, true
	case "fact":
		return CategoryFact, true
	case "incident":
		return CategoryIncident, true
	case "hard_deny":
		return CategoryHardDeny, true
	}
	return CategoryWeakSignal, false
}

// Rule is the parsed form of a YAML detection rule.
//
// Match is a CEL expression (compiled lazily by the rule engine).
// In Phase 0 we only carry the structural fields; the engine wires
// in compilation in Phase 1.
type Rule struct {
	ID          string    `yaml:"id" json:"id"`
	Desc        string    `yaml:"desc" json:"desc"`
	Severity    Severity  `yaml:"-" json:"severity"`
	SeverityRaw string    `yaml:"severity" json:"-"`
	Mode        RuleMode  `yaml:"-" json:"mode"`
	ModeRaw     string    `yaml:"mode" json:"-"`
	Mitre       []string  `yaml:"mitre" json:"mitre,omitempty"`
	Match       string    `yaml:"match" json:"match"`
	Tags        []string  `yaml:"tags" json:"tags,omitempty"`
	Remediation string    `yaml:"remediation" json:"remediation,omitempty"`
	TestID      string    `yaml:"test_id" json:"test_id,omitempty"`
	Soak        SoakState `yaml:"-" json:"soak,omitempty"`

	// Class buckets the rule for the per-class FP metric model
	// (LOW_FALSE_POSITIVE_ARCHITECTURE_2026-05-21.md §3+§12):
	//   1 = hard invariant (auto-deny candidate; FP target <0.1%)
	//   2 = strong exploit signal (freeze candidate; FP target <0.5%)
	//   3 = soft behavior drift (alert-only; FP target <5%)
	// Empty/zero defaults to 3 in NormalizeClass so untagged rules
	// don't accidentally get auto-block treatment.
	Class int `yaml:"class" json:"class,omitempty"`

	// Category replaces Class for routing decisions in the verdict engine.
	// Empty defaults to CategoryWeakSignal in NormalizeCategory so untagged
	// rules cannot escalate to alerts by accident.
	Category    Category `yaml:"-" json:"category"`
	CategoryRaw string   `yaml:"category" json:"-"`

	RateLimit *RuleRateLimit `yaml:"rate_limit" json:"rate_limit,omitempty"`
}

// NormalizeClass returns the rule's class with safe default 3.
// Centralised so every consumer (lint, runtime, metrics, CLI) sees
// the same default.
func (r *Rule) NormalizeClass() int {
	c := r.Class
	if c < 1 || c > 3 {
		return 3
	}
	return c
}

// NormalizeCategory parses CategoryRaw into Category. Returns a non-nil
// error if the raw value was a non-empty unknown string; the Category
// field is still set to the safe default (weak_signal) so processing
// can continue.
func (r *Rule) NormalizeCategory() error {
	c, ok := ParseCategory(r.CategoryRaw)
	r.Category = c
	if !ok {
		return &ParseError{Field: "category", Value: r.CategoryRaw}
	}
	return nil
}

// RuleRateLimit caps how often a rule may fire.
//
// PerKey may be one of "pid", "comm", "host", or "rule" (default).
type RuleRateLimit struct {
	PerMinute uint   `yaml:"per_minute" json:"per_minute"`
	PerKey    string `yaml:"per_key" json:"per_key,omitempty"`
}

// SoakState tracks how long a rule has run without operator-marked
// false positives, used to gate auto-promotion to enforcement modes
// in Phase 7.
type SoakState struct {
	Since                time.Time `json:"since,omitempty"`
	FPCount              uint64    `json:"fp_count"`
	ConsecutiveCleanDays uint      `json:"consecutive_clean_days"`
	ZeroFPSince          time.Time `json:"zero_fp_since,omitempty"`
	Promotable           bool      `json:"promotable"`
}

// Normalize fills computed fields from raw YAML strings. Returns an
// error if any raw field is invalid.
func (r *Rule) Normalize() error {
	if s, ok := ParseSeverity(r.SeverityRaw); ok {
		r.Severity = s
	} else if r.SeverityRaw != "" {
		return &ParseError{Field: "severity", Value: r.SeverityRaw}
	}
	switch r.ModeRaw {
	case "", "detect":
		r.Mode = ModeDetect
	case "quarantine":
		r.Mode = ModeQuarantine
	case "block":
		r.Mode = ModeBlock
	default:
		return &ParseError{Field: "mode", Value: r.ModeRaw}
	}
	if err := r.NormalizeCategory(); err != nil {
		return err
	}
	return nil
}

// ParseError indicates a YAML field could not be parsed.
type ParseError struct {
	Field string
	Value string
}

func (e *ParseError) Error() string {
	return "model: invalid " + e.Field + " value: " + e.Value
}

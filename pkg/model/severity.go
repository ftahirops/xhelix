// Package model defines the canonical event, alert, and rule types
// shared across xhelix.
package model

// Severity classifies the operator-action expectation of an event
// or alert. Higher values demand sooner action.
type Severity uint8

const (
	SeverityInfo Severity = iota
	SeverityNotice
	SeverityWarn
	SeverityHigh
	SeverityCritical
)

// String returns the severity as a short, lowercase token.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityNotice:
		return "notice"
	case SeverityWarn:
		return "warn"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "unknown"
}

// ParseSeverity parses a severity from its string form.
// Returns SeverityInfo and false on unknown input.
func ParseSeverity(s string) (Severity, bool) {
	switch s {
	case "info":
		return SeverityInfo, true
	case "notice":
		return SeverityNotice, true
	case "warn", "warning":
		return SeverityWarn, true
	case "high":
		return SeverityHigh, true
	case "critical", "crit":
		return SeverityCritical, true
	}
	return SeverityInfo, false
}

// Verdict is the agent's classification of an event's intent.
type Verdict uint8

const (
	VerdictUnknown Verdict = iota
	VerdictBenign
	VerdictSuspicious
	VerdictMalicious
)

// String returns the verdict as a short, lowercase token.
func (v Verdict) String() string {
	switch v {
	case VerdictBenign:
		return "benign"
	case VerdictSuspicious:
		return "suspicious"
	case VerdictMalicious:
		return "malicious"
	}
	return "unknown"
}

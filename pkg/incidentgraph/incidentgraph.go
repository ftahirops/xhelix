// Package incidentgraph assembles correlated incidents from streams of
// events, alerts, and verifier results. It is the layer above
// pkg/source (which tracks per-anchor provenance) and pkg/correlator
// (which tracks short-window chains). Incidents are the operator-facing
// unit of investigation — many alerts roll up into one incident with
// shared lineage, intent classification, and TTP/MITRE tagging.
//
// Phase D.1 of the BRP implementation plan. Build spec §3.4.
//
// Architectural distinction (build spec §6.6.2):
//
//   source graph     — provenance + lineage reconstruction for ONE anchor
//   incident graph   — correlated multi-chain attack story across events
//                      and possibly multiple anchors
//
// The two are distinct stores with distinct shapes. Incidentgraph
// CONSUMES source-graph queries; it does NOT replace them.
package incidentgraph

import (
	"time"

	"github.com/xhelix/xhelix/pkg/sourcescore"
)

// IntentCategory enumerates the broad attack objectives an incident
// can be classified into. Used by the operator UI to triage and by
// the response engine to choose containment actions.
//
// Per build spec §3.4.
type IntentCategory string

const (
	IntentUnknown     IntentCategory = ""
	IntentTheft       IntentCategory = "theft"
	IntentC2          IntentCategory = "c2"
	IntentPersistence IntentCategory = "persistence"
	IntentPrivilege   IntentCategory = "privilege"
	IntentLateral     IntentCategory = "lateral"
	IntentImpact      IntentCategory = "impact"
)

// Severity buckets incidents by operator urgency. Mapped from the
// highest-severity alert that contributes to the incident, with
// confidence weighting.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// EvidenceRef is one piece of evidence attached to an incident.
// Captures enough context for an operator to find the originating
// event/alert/graph-node without storing the full payload (the
// hot/cold/forensic stores hold those).
//
// Per build spec §3.4.
type EvidenceRef struct {
	EventID   string    `json:"event_id,omitempty"`
	AlertID   string    `json:"alert_id,omitempty"`
	GraphNode string    `json:"graph_node,omitempty"`
	Kind      string    `json:"kind"`               // "event" / "alert" / "verifier_result"
	Summary   string    `json:"summary"`            // one-line operator hint
	At        time.Time `json:"at"`
}

// Incident is the operator-facing investigation unit. Lifecycle:
//
//	open → updating (more evidence arrives) → closed (operator action OR
//	         24h inactivity for short-window OR Phase H.2 long-window)
//
// IDs are stable across daemon restarts (Phase D.1.6 SQLite persistence).
type Incident struct {
	ID         string         `json:"id"`
	StartedAt  time.Time      `json:"started_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	Severity   Severity       `json:"severity"`
	Confidence float64        `json:"confidence"`
	Intent     IntentCategory `json:"intent"`
	Summary    string         `json:"summary"`

	// SourceIDs links the incident back to the originating source
	// anchors (sshd login, HTTP request, cron fire). Multiple anchors
	// per incident = multi-source attack chain.
	SourceIDs []uint64 `json:"source_ids,omitempty"`

	// LineageIDs are the affected lineage identifiers.
	LineageIDs []uint64 `json:"lineage_ids,omitempty"`

	// TTPTags are short stable tokens like "shell_spawn",
	// "metadata_access", "novel_outbound". Used by the response
	// engine and operator dashboard.
	TTPTags []string `json:"ttp_tags,omitempty"`

	// MitreIDs are the MITRE ATT&CK technique IDs corresponding to
	// the rule_ids that contributed evidence. e.g. ["T1059.004",
	// "T1071"].
	MitreIDs []string `json:"mitre_ids,omitempty"`

	// Evidence is the bounded ring of evidence refs. Capped at
	// maxEvidencePerIncident (50) to prevent unbounded growth on
	// long-window incidents.
	Evidence []EvidenceRef `json:"evidence,omitempty"`
}

// Engine is the operator-facing API for the incidentgraph subsystem.
// Implementations must be safe for concurrent use.
//
// Per build spec §3.4 — three Observe methods so the pipeline can
// fan out events / alerts / verifier results into the graph without
// reflection or tag-sniffing.
type Engine interface {
	// Observe records a normalised event. The engine groups by source
	// anchor (with lineage fallback) and updates the matching incident.
	Observe(ev observableEvent)

	// ObserveAlert records an alert. Alerts carry higher signal than
	// events; they always create or update an incident and contribute
	// MITRE/TTP tags.
	ObserveAlert(a observableAlert)

	// ObserveVerifierResult records a verifier outcome. Used for
	// confidence calibration and intent refinement when the verifier
	// promotes a Verify decision.
	ObserveVerifierResult(ev observableEvent, vr observableVerifierResult)

	// Snapshot returns a copy of all currently-open incidents,
	// ordered by UpdatedAt descending (most-recent first).
	Snapshot() []Incident

	// Get returns the incident with the given ID, or false if not found.
	Get(id string) (Incident, bool)

	// Close marks an incident as closed (operator action). Closed
	// incidents are removed from Snapshot but persist in the audit
	// log (Phase D.1.6).
	Close(id string, reason string) bool

	// Size returns the count of open incidents (metrics helper).
	Size() int

	// SourceScoreTracker returns the per-source TTP-token tracker
	// (T08.1). Nil-safe — implementations that don't track scores
	// return nil and the caller's downstream Engine handles that.
	SourceScoreTracker() *sourcescore.Tracker
}

// observableEvent is the minimal event view incidentgraph consumes.
// Pipeline adapts a model.Event into this shape so incidentgraph
// doesn't depend on pkg/model directly.
type observableEvent struct {
	ID          string
	At          time.Time
	Sensor      string
	Kind        string
	SourceID    uint64
	LineageID   uint64
	RuleID      string
	Severity    Severity
	Summary     string
	AssetClass  string
	SecretTaint string
	Tags        map[string]string
}

// observableAlert is the minimal alert view.
type observableAlert struct {
	ID          string
	At          time.Time
	RuleID      string
	Severity    Severity
	Reason      string
	SourceID    uint64
	LineageID   uint64
	Class       int
}

// observableVerifierResult is the minimal verifier-output view.
type observableVerifierResult struct {
	Outcome    string // "benign" / "suspicious" / "promote"
	Score      float64
	TopDomain  string
	Reason     string
}

// Public wrappers so callers can construct the observable types
// without crossing through unexported names. The pipeline imports
// these to bridge from model.Event → observable.

// Event is the public observable shape.
type Event = observableEvent

// Alert is the public observable shape.
type Alert = observableAlert

// VerifierResult is the public observable shape.
type VerifierResult = observableVerifierResult

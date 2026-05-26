package incidentgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// memEngine is the in-memory Engine implementation. Per-incident
// updates are protected by a single store-wide RWMutex; the working
// set is small (typically <100 open incidents) so contention is
// negligible.
type memEngine struct {
	mu sync.RWMutex

	// open maps incident ID → incident.
	open map[string]*Incident

	// bySource maps source_anchor_id → incident ID for the currently
	// open incident on that anchor. Used to merge new evidence into
	// an existing incident rather than spawning duplicates.
	bySource map[uint64]string

	// byLineage maps lineage_id → incident ID as a fallback when
	// SourceID is 0 (no anchor minted).
	byLineage map[uint64]string

	// activityWindow caps how long an incident stays open without
	// new evidence. Default 30 minutes per build spec — Phase H.2
	// extends this to 24h for long-window detection.
	activityWindow time.Duration
}

// maxEvidencePerIncident bounds the evidence ring per incident to
// keep memory bounded under attack. Operator-tunable in a follow-on.
const maxEvidencePerIncident = 50

// NewEngine returns a fresh in-memory engine. activityWindow defaults
// to 30 minutes when 0; pass >0 to override (e.g. 24h for long-window).
func NewEngine(activityWindow time.Duration) Engine {
	if activityWindow <= 0 {
		activityWindow = 30 * time.Minute
	}
	return &memEngine{
		open:           make(map[string]*Incident),
		bySource:       make(map[uint64]string),
		byLineage:      make(map[uint64]string),
		activityWindow: activityWindow,
	}
}

// Observe records an event. Events ENRICH an existing incident on
// the same routing key (source_anchor_id → lineage_id); they do NOT
// create new incidents. Only ObserveAlert creates incidents — this
// keeps the open-incident set bounded by the alert rate, not the
// raw event rate.
//
// Design note: an early version of this engine created incidents
// per distinct lineage on first event. On a 5-min canary that
// produced 900 open incidents from natural ebpf.net traffic alone.
// The current enrich-only semantics keeps the noise floor at zero.
func (e *memEngine) Observe(ev Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	inc := e.routeExisting(ev.SourceID, ev.LineageID)
	if inc == nil {
		return
	}
	e.appendEventEvidence(inc, ev)
	e.recomputeMetadata(inc, ev)
}

// ObserveAlert records an alert. Higher signal than Observe — also
// updates MITRE tags + intent classification.
func (e *memEngine) ObserveAlert(a Alert) {
	e.mu.Lock()
	defer e.mu.Unlock()
	inc := e.routeOrCreate(a.SourceID, a.LineageID, a.At)
	e.appendAlertEvidence(inc, a)
	// Lift severity if this alert is higher than current.
	if severityRank(a.Severity) > severityRank(inc.Severity) {
		inc.Severity = a.Severity
	}
	// Add MITRE ID + TTP tags from rule.
	if mitre := mitreForRule(a.RuleID); mitre != "" {
		inc.MitreIDs = appendUnique(inc.MitreIDs, mitre)
	}
	if ttp := ttpForRule(a.RuleID); ttp != "" {
		inc.TTPTags = appendUnique(inc.TTPTags, ttp)
	}
	inc.UpdatedAt = a.At
	// Re-classify intent every time TTP tags change.
	inc.Intent = classifyIntent(inc.TTPTags, inc.MitreIDs)
	// Re-compute confidence — Class 1 alerts (hard invariant) bump high.
	switch a.Class {
	case 1:
		inc.Confidence = maxF(inc.Confidence, 0.9)
	case 2:
		inc.Confidence = maxF(inc.Confidence, 0.7)
	case 3:
		inc.Confidence = maxF(inc.Confidence, 0.5)
	}
}

// ObserveVerifierResult records a verifier outcome. Used for
// intent refinement: a Promote outcome lifts confidence even
// without an alert. Like Observe, this is enrich-only — does
// nothing if no incident is open on the route. The verifier alone
// does not create incidents; if a Promote is significant enough,
// the rule engine will fire an alert which creates the incident.
func (e *memEngine) ObserveVerifierResult(ev Event, vr VerifierResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	inc := e.routeExisting(ev.SourceID, ev.LineageID)
	if inc == nil {
		return
	}
	switch vr.Outcome {
	case "promote":
		inc.Confidence = maxF(inc.Confidence, 0.85)
	case "suspicious":
		inc.Confidence = maxF(inc.Confidence, 0.65)
	}
	inc.Evidence = appendBounded(inc.Evidence, EvidenceRef{
		EventID: ev.ID,
		Kind:    "verifier_result",
		Summary: fmt.Sprintf("%s (score=%.2f) %s", vr.Outcome, vr.Score, vr.Reason),
		At:      ev.At,
	})
	inc.UpdatedAt = ev.At
}

// Snapshot returns currently-open incidents (most recent first).
func (e *memEngine) Snapshot() []Incident {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Incident, 0, len(e.open))
	for _, inc := range e.open {
		out = append(out, *inc)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	return out
}

// Get returns the incident with the given ID.
func (e *memEngine) Get(id string) (Incident, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	inc, ok := e.open[id]
	if !ok {
		return Incident{}, false
	}
	return *inc, true
}

// Close marks an incident closed. Removes from the open set; the
// audit log retains it (Phase D.1.6 persistence).
func (e *memEngine) Close(id, reason string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	inc, ok := e.open[id]
	if !ok {
		return false
	}
	// Audit close.
	slog.Info("incidentgraph close",
		"id", id, "reason", reason,
		"severity", string(inc.Severity), "intent", string(inc.Intent),
		"evidence_count", len(inc.Evidence))
	delete(e.open, id)
	for _, srcID := range inc.SourceIDs {
		if e.bySource[srcID] == id {
			delete(e.bySource, srcID)
		}
	}
	for _, lid := range inc.LineageIDs {
		if e.byLineage[lid] == id {
			delete(e.byLineage, lid)
		}
	}
	return true
}

// Size returns the count of open incidents.
func (e *memEngine) Size() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.open)
}

// Seed directly inserts a hydrated incident into the engine without
// running Observe semantics. Used by the persistence layer at
// startup to restore the routing maps for previously-open incidents.
// Caller-supplied IDs must be unique; duplicates are silently
// overwritten (last writer wins, matching disk-load order).
func (e *memEngine) Seed(inc Incident) {
	e.mu.Lock()
	defer e.mu.Unlock()
	copy := inc
	e.open[copy.ID] = &copy
	for _, srcID := range copy.SourceIDs {
		e.bySource[srcID] = copy.ID
	}
	for _, lid := range copy.LineageIDs {
		e.byLineage[lid] = copy.ID
	}
}

// RouteSnapshot returns the currently-routed incident for either ID
// as a value copy. Used by PersistingEngine.flushFor for O(1) lookup.
func (e *memEngine) RouteSnapshot(sourceID, lineageID uint64) (Incident, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	inc := e.routeExisting(sourceID, lineageID)
	if inc == nil {
		return Incident{}, false
	}
	return *inc, true
}

// Sweep closes incidents whose UpdatedAt is older than activityWindow.
// Returns the IDs swept. Caller runs this periodically (e.g. once per
// minute) to clean up inactive incidents.
func (e *memEngine) Sweep(now time.Time) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := now.Add(-e.activityWindow)
	var swept []string
	for id, inc := range e.open {
		if inc.UpdatedAt.Before(cutoff) {
			swept = append(swept, id)
		}
	}
	for _, id := range swept {
		inc := e.open[id]
		slog.Info("incidentgraph sweep close",
			"id", id, "intent", string(inc.Intent),
			"inactive_for", now.Sub(inc.UpdatedAt).String())
		delete(e.open, id)
		for _, srcID := range inc.SourceIDs {
			delete(e.bySource, srcID)
		}
		for _, lid := range inc.LineageIDs {
			delete(e.byLineage, lid)
		}
	}
	return swept
}

// ─────────────────────────────────────────────────────────────────
// Routing + merging
// ─────────────────────────────────────────────────────────────────

// routeExisting returns the incident currently routed to either ID,
// or nil if none. Never creates. Caller must hold e.mu.
func (e *memEngine) routeExisting(sourceID, lineageID uint64) *Incident {
	if sourceID != 0 {
		if id, ok := e.bySource[sourceID]; ok {
			if inc, found := e.open[id]; found {
				return inc
			}
		}
	}
	if lineageID != 0 {
		if id, ok := e.byLineage[lineageID]; ok {
			if inc, found := e.open[id]; found {
				return inc
			}
		}
	}
	return nil
}

func (e *memEngine) routeOrCreate(sourceID, lineageID uint64, at time.Time) *Incident {
	// Prefer source-anchor routing — most stable correlation key.
	if sourceID != 0 {
		if id, ok := e.bySource[sourceID]; ok {
			if inc, found := e.open[id]; found {
				return inc
			}
		}
	}
	// Fallback to lineage.
	if lineageID != 0 {
		if id, ok := e.byLineage[lineageID]; ok {
			if inc, found := e.open[id]; found {
				return inc
			}
		}
	}
	// Create new.
	inc := &Incident{
		ID:        generateIncidentID(sourceID, lineageID, at),
		StartedAt: at,
		UpdatedAt: at,
		Severity:  SeverityInfo,
		Confidence: 0.0,
		Intent:    IntentUnknown,
		Summary:   "incident assembling",
	}
	if sourceID != 0 {
		inc.SourceIDs = []uint64{sourceID}
		e.bySource[sourceID] = inc.ID
	}
	if lineageID != 0 {
		inc.LineageIDs = []uint64{lineageID}
		e.byLineage[lineageID] = inc.ID
	}
	e.open[inc.ID] = inc
	return inc
}

func (e *memEngine) appendEventEvidence(inc *Incident, ev Event) {
	inc.Evidence = appendBounded(inc.Evidence, EvidenceRef{
		EventID: ev.ID,
		Kind:    "event",
		Summary: ev.Summary,
		At:      ev.At,
	})
	inc.UpdatedAt = ev.At
	// Attach additional lineage IDs the event references.
	if ev.LineageID != 0 {
		inc.LineageIDs = appendUniqueUint64(inc.LineageIDs, ev.LineageID)
		if _, ok := e.byLineage[ev.LineageID]; !ok {
			e.byLineage[ev.LineageID] = inc.ID
		}
	}
}

func (e *memEngine) appendAlertEvidence(inc *Incident, a Alert) {
	inc.Evidence = appendBounded(inc.Evidence, EvidenceRef{
		AlertID: a.ID,
		Kind:    "alert",
		Summary: fmt.Sprintf("[%s] %s", a.RuleID, a.Reason),
		At:      a.At,
	})
}

func (e *memEngine) recomputeMetadata(inc *Incident, ev Event) {
	// Refresh summary as the incident accretes evidence.
	if inc.Summary == "incident assembling" && ev.Summary != "" {
		inc.Summary = ev.Summary
	}
}

// generateIncidentID is a stable hash of (sourceID, lineageID,
// rounded-to-minute timestamp). Same inputs produce same ID for
// audit-trail consistency across restarts.
func generateIncidentID(sourceID, lineageID uint64, at time.Time) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d|%d|%d", sourceID, lineageID, at.Unix()/60)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

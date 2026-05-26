package main

import (
	"strconv"
	"time"

	"github.com/xhelix/xhelix/pkg/incidentgraph"
	"github.com/xhelix/xhelix/pkg/model"
)

// incidentSink bridges a model.Alert into the incidentgraph engine.
// Kept here (not in pkg/pipeline) so the daemon owns the wiring
// decisions about which alerts contribute to incidents.
//
// Routing: source_anchor_id tag (preferred) → cgroup_id → pid. Same
// fallback chain used by secret-taint + the pipeline's event bridge.
func incidentSink(eng incidentgraph.Engine, a model.Alert) {
	ev := a.Event
	at := ev.Time
	if at.IsZero() {
		at = time.Now()
	}
	var sourceID uint64
	if s := ev.Tags["source_anchor_id"]; s != "" {
		if v, err := strconv.ParseUint(s, 10, 64); err == nil {
			sourceID = v
		}
	}
	lineage := ev.CGroupID
	if lineage == 0 {
		lineage = uint64(ev.PID)
	}
	eng.ObserveAlert(incidentgraph.Alert{
		ID:        ev.ID.String(),
		At:        at,
		RuleID:    a.RuleID,
		Severity:  mapSeverity(ev.Severity),
		Reason:    a.Reason,
		SourceID:  sourceID,
		LineageID: lineage,
		Class:     a.Class,
	})
}

func mapSeverity(s model.Severity) incidentgraph.Severity {
	switch s {
	case model.SeverityCritical:
		return incidentgraph.SeverityCritical
	case model.SeverityHigh:
		return incidentgraph.SeverityHigh
	case model.SeverityWarn:
		return incidentgraph.SeverityMedium
	case model.SeverityNotice:
		return incidentgraph.SeverityLow
	}
	return incidentgraph.SeverityInfo
}

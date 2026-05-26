package pipeline

import (
	"strconv"
	"time"

	"github.com/xhelix/xhelix/pkg/incidentgraph"
	"github.com/xhelix/xhelix/pkg/model"
)

// observeIncident bridges a fully-enriched model.Event into the
// incidentgraph engine. Called at the tail of Handle when
// p.IncidentGraph != nil.
//
// Routing key: source_anchor_id (preferred) → lineage fallback
// (cgroup_id → pid). Same chain used by secret-taint.
func (p *Pipeline) observeIncident(ev model.Event) {
	sourceID := parseSourceID(ev.Tags["source_anchor_id"])
	lineage := lineageIDFromEvent(ev)
	at := ev.Time
	if at.IsZero() {
		at = time.Now()
	}
	summary := ev.Tags["reason"]
	if summary == "" {
		summary = ev.Sensor + " " + ev.Comm
	}
	p.IncidentGraph.Observe(incidentgraph.Event{
		ID:          ev.ID.String(),
		At:          at,
		Sensor:      ev.Sensor,
		Kind:        ev.Tags["kind"],
		SourceID:    sourceID,
		LineageID:   lineage,
		RuleID:      ev.Rule,
		Severity:    incidentSeverityFromModel(ev.Severity),
		Summary:     summary,
		AssetClass:  ev.Tags["asset_class"],
		SecretTaint: ev.Tags["secret_taint"],
		Tags:        ev.Tags,
	})
}

// IncidentAlertSink returns an Alert→nothing fan-out closure that
// the daemon can compose with its alert-bus Emit. Daemon usage:
//
//	emit := func(a model.Alert) {
//	    bus.Publish(a)
//	    incidentSink(a)
//	}
//
// Kept here so callers don't reach into incidentgraph types directly.
func (p *Pipeline) IncidentAlertSink() func(model.Alert) {
	if p.IncidentGraph == nil {
		return func(model.Alert) {}
	}
	return func(a model.Alert) {
		ev := a.Event
		at := ev.Time
		if at.IsZero() {
			at = time.Now()
		}
		sourceID := parseSourceID(ev.Tags["source_anchor_id"])
		lineage := lineageIDFromEvent(ev)
		p.IncidentGraph.ObserveAlert(incidentgraph.Alert{
			ID:        ev.ID.String(),
			At:        at,
			RuleID:    a.RuleID,
			Severity:  incidentSeverityFromModel(ev.Severity),
			Reason:    a.Reason,
			SourceID:  sourceID,
			LineageID: lineage,
			Class:     a.Class,
		})
	}
}

func parseSourceID(s string) uint64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func incidentSeverityFromModel(s model.Severity) incidentgraph.Severity {
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

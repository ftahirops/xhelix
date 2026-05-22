package main

import (
	"strings"

	"github.com/xhelix/xhelix/pkg/credbroker"
	"github.com/xhelix/xhelix/pkg/model"
)

// joinWithSpaces concatenates parts with a single space between each.
// Used to build lineage_chain tag values like "bash → sshd → root".
func joinWithSpaces(parts []string) string { return strings.Join(parts, " ") }

// castEmit unwraps the daemon's emit closure (declared as
// func(model.Alert) in run.go) through an `any` boundary. Used so
// startFanGate doesn't need to import model into its signature.
func castEmit(f func(a interface{})) func(model.Alert) {
	return func(a model.Alert) { f(a) }
}

// credBrokerAlertEmitter adapts credbroker.BrokerAlert into model.Alert
// and forwards through the daemon's emit closure. The emit closure
// feeds the alert bus AND the planner wiring, so credbroker decisions
// land in both legacy webhook sinks and the takeover scorer.
type credBrokerAlertEmitter struct {
	emit func(model.Alert)
	host string
}

// Emit converts and forwards. Safe to call from any goroutine.
func (e *credBrokerAlertEmitter) Emit(a credbroker.BrokerAlert) {
	if e == nil || e.emit == nil {
		return
	}
	ev := model.NewEvent("credbroker", model.SeverityCritical)
	ev.Time = a.At
	ev.PID = a.PID
	ev.Host = e.host
	if len(a.Lineage) > 0 {
		ev.Comm = a.Lineage[0].Comm
		ev.Image = a.Lineage[0].Image
		ev.UID = a.Lineage[0].UID
	}
	ev.Tags["sealed_path"] = a.SealedPath
	if a.HoneyMarker != "" {
		ev.Tags["honey_marker"] = a.HoneyMarker
	}
	if len(a.Lineage) > 1 {
		ev.Tags["parent_comm"] = a.Lineage[1].Comm
		ev.Tags["parent_image"] = a.Lineage[1].Image
	}
	// Walk the full ancestor chain so triage sees "this credential
	// was read by chrome → bash → sshd → root@1.2.3.4" not just
	// the immediate reader.
	if len(a.Lineage) > 0 {
		var chain []string
		for i, n := range a.Lineage {
			if i > 0 {
				chain = append(chain, "→")
			}
			chain = append(chain, n.Comm)
		}
		ev.Tags["lineage_chain"] = joinWithSpaces(chain)
	}
	ruleID := string(a.Kind)
	severity := model.SeverityCritical
	switch a.Kind {
	case credbroker.AlertSealedDenied:
		ruleID = "credbroker.unauthentic_open"
	case credbroker.AlertHoneyTouched:
		ruleID = "credbroker.honey_touched"
	case credbroker.AlertHoneyMarkerSeen:
		ruleID = "credbroker.honey_marker_in_flight"
	case credbroker.AlertPlaintextRead:
		ruleID = "credbroker.plaintext_read"
		// Plaintext-read alerts are warn rather than critical by
		// default — they fire on every legit aws-cli call too, so
		// the takeover scorer needs to weight them lower than the
		// sealed-denied / honey-touched alerts which are by
		// construction adversarial.
		severity = model.SeverityWarn
		ev.Severity = severity
	}
	e.emit(model.Alert{
		Event:  ev,
		RuleID: ruleID,
		Reason: a.Reason,
		Mode:   model.ModeDetect,
		Class:  1,
	})
}

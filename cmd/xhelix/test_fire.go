package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/xhelix/xhelix/pkg/alert"
	"github.com/xhelix/xhelix/pkg/model"
)

// testFireAlert publishes a synthetic alert through the live alert
// bus. Operators run `xhelixctl alerts test-webhook` to confirm sink
// wiring (file + webhook) end-to-end without waiting for a real
// detection. The response engine receives it too, so the alert is
// also a smoke-test for the monitor_mode + autobaseline gates.
//
// Optional payload fields:
//
//	rule_id   default "test.synthetic"
//	severity  default "high" — accepts info|notice|warn|high|critical
//	reason    default "synthetic alert from xhelixctl alerts test-webhook"
func testFireAlert(bus *alert.Bus, host string, raw json.RawMessage) (any, error) {
	if bus == nil {
		return nil, fmt.Errorf("alert bus not initialised")
	}
	var req struct {
		RuleID   string `json:"rule_id,omitempty"`
		Severity string `json:"severity,omitempty"`
		Reason   string `json:"reason,omitempty"`
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &req)
	}
	if req.RuleID == "" {
		req.RuleID = "test.synthetic"
	}
	if req.Reason == "" {
		req.Reason = "synthetic alert published by xhelixctl alerts test-webhook"
	}
	sev := model.SeverityHigh
	switch req.Severity {
	case "info":
		sev = model.SeverityInfo
	case "notice":
		sev = model.SeverityNotice
	case "warn":
		sev = model.SeverityWarn
	case "critical":
		sev = model.SeverityCritical
	}

	a := model.Alert{
		Event: model.Event{
			ID:        ulid.Make(),
			Time:      time.Now().UTC(),
			Sensor:    "test.synthetic",
			Severity:  sev,
			Host:      host,
			PID:       uint32(time.Now().Unix() % 65535),
			ParentPID: 1,
			Comm:      "xhelixctl",
			UID:       0,
			GID:       0,
			Image:     "/usr/local/bin/xhelixctl",
			ProcTree: []model.ProcNode{
				{PID: 9999, Comm: "xhelixctl", Image: "/usr/local/bin/xhelixctl", UID: 0,
					Argv: []string{"xhelixctl", "alerts", "test-webhook"}},
				{PID: 1, Comm: "systemd", Image: "/lib/systemd/systemd", UID: 0},
			},
			Tags: map[string]string{
				"test_fire": "true",
				"note":      "this is a synthetic alert; no real activity",
			},
		},
		RuleID: req.RuleID,
		Reason: req.Reason,
		Mode:   model.ModeDetect,
	}

	delivered := bus.Send(a)
	return map[string]any{
		"sent":      delivered,
		"alert_id":  a.Event.ID.String(),
		"rule_id":   a.RuleID,
		"severity":  sev.String(),
		"host":      host,
		"note":      "check Slack + /var/log/xhelix/alerts.jsonl",
	}, nil
}

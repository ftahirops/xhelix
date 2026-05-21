package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// WebhookSink ships alerts as POST JSON to a configured URL. The
// payload format auto-detects:
//   - Slack incoming-webhook (URL contains "hooks.slack.com")
//   - Microsoft Teams (URL contains "webhook.office.com")
//   - generic JSON (everything else)
type WebhookSink struct {
	URL    string
	Client *http.Client
	Host   string // hostname for context
}

// NewWebhookSink builds a sink. urlStr empty disables (NopSink-ish).
func NewWebhookSink(urlStr, host string) *WebhookSink {
	return &WebhookSink{
		URL:    urlStr,
		Host:   host,
		Client: &http.Client{Timeout: 5 * time.Second},
	}
}

// Name implements model.Sink.
func (s *WebhookSink) Name() string { return "webhook" }

// Close implements model.Sink. Nothing to close — http.Client is GC'd.
func (s *WebhookSink) Close() error { return nil }

// Send posts the alert.
func (s *WebhookSink) Send(ctx context.Context, a model.Alert) error {
	if s.URL == "" {
		return nil
	}
	body, contentType := s.format(a)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL,
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *WebhookSink) format(a model.Alert) ([]byte, string) {
	switch {
	case strings.Contains(s.URL, "hooks.slack.com"):
		return slackPayload(a, s.Host), "application/json"
	case strings.Contains(s.URL, "webhook.office.com"):
		return teamsPayload(a, s.Host), "application/json"
	default:
		return genericPayload(a, s.Host), "application/json"
	}
}

// slackPayload renders a single alert as a Slack attachment with full
// causal evidence. Operator's mental model of the alert is meant to
// be reconstructable from the message alone — no need to ssh in.
//
// Sections, in order:
//   - title + severity color
//   - one-line reason (rule_id + human reason)
//   - detection: sensor, rule_id, MITRE tags from event.tags
//   - process: pid, ppid, uid, comm, image
//   - causal chain: ancestry from event.ProcTree, most recent → root
//   - action taken: from a.Action (set by response.Engine post-gate)
//   - gate reason: from event.tags["xhelix_gate_reason"] when set
//   - all event tags (truncated per value to keep payload <40KB)
func slackPayload(a model.Alert, host string) []byte {
	colour := severityColor(a.Event.Severity)

	gateReason := ""
	mitre := ""
	if a.Event.Tags != nil {
		gateReason = a.Event.Tags["xhelix_gate_reason"]
		mitre = a.Event.Tags["mitre"]
	}

	procBlock := fmt.Sprintf(
		"pid=%d ppid=%d uid=%d gid=%d\ncomm=%s\nimage=%s\ncontainer=%s",
		a.Event.PID, a.Event.ParentPID, a.Event.UID, a.Event.GID,
		nz(a.Event.Comm), nz(a.Event.Image), nz(a.Event.Container))

	chainBlock := renderCausalChain(a.Event.ProcTree)
	if chainBlock == "" {
		chainBlock = "(no ancestry available — proc tree not enriched for this event)"
	}

	actionLine := nz(a.Action)
	if actionLine == "" {
		actionLine = "log"
	}
	if gateReason != "" {
		actionLine = fmt.Sprintf("%s   (gate: %s)", actionLine, gateReason)
	}

	detection := fmt.Sprintf("sensor = %s\nrule   = %s\nseverity = %s",
		a.Event.Sensor, a.RuleID, a.Event.Severity.String())
	if mitre != "" {
		detection += "\nmitre  = " + mitre
	}

	fields := []map[string]any{
		{"title": "Host", "value": host, "short": true},
		{"title": "Time", "value": a.Event.Time.UTC().Format(time.RFC3339), "short": true},
		{"title": "Detection", "value": "```" + detection + "```", "short": false},
		{"title": "Process", "value": "```" + procBlock + "```", "short": false},
		{"title": "Causal chain (most-recent → root)",
			"value": "```" + chainBlock + "```", "short": false},
		{"title": "Action taken", "value": "`" + actionLine + "`", "short": false},
		{"title": "All tags", "value": "```" + fullTags(a.Event.Tags) + "```", "short": false},
	}
	if len(a.EvidenceIDs) > 0 {
		ids := []string{}
		for _, id := range a.EvidenceIDs {
			ids = append(ids, id.String())
		}
		fields = append(fields, map[string]any{
			"title": "Evidence chain IDs",
			"value": "```" + strings.Join(ids, "\n") + "```",
			"short": false,
		})
	}

	body, _ := json.Marshal(map[string]any{
		"attachments": []map[string]any{{
			"color":  colour,
			"title":  fmt.Sprintf("[%s] %s", a.Event.Severity.String(), a.RuleID),
			"text":   a.Reason,
			"fields": fields,
			"footer": "xhelix · " + host,
			"ts":     a.Event.Time.Unix(),
		}},
	})
	return body
}

// renderCausalChain walks the ProcTree (already sorted child→root by
// the enricher) and produces a multi-line code block. One node per
// line: pid (uid) comm  image  start.
func renderCausalChain(tree []model.ProcNode) string {
	if len(tree) == 0 {
		return ""
	}
	var b strings.Builder
	for i, n := range tree {
		arrow := "└─"
		if i == 0 {
			arrow = "* "
		}
		img := nz(n.Image)
		if img == "" {
			img = "?"
		}
		argv := ""
		if len(n.Argv) > 0 {
			a := strings.Join(n.Argv, " ")
			if len(a) > 120 {
				a = a[:120] + "…"
			}
			argv = "  argv=[" + a + "]"
		}
		fmt.Fprintf(&b, "%s pid=%d uid=%d comm=%s image=%s%s\n",
			arrow, n.PID, n.UID, nz(n.Comm), img, argv)
	}
	return b.String()
}

// fullTags renders every tag on the event, sorted, with values
// truncated to 160 chars apiece. Slack message hard-cap is ~40KB
// total; truncation keeps a runaway tag from blowing the payload.
func fullTags(tags map[string]string) string {
	if len(tags) == 0 {
		return "(none)"
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var b strings.Builder
	total := 0
	for _, k := range keys {
		v := tags[k]
		if len(v) > 160 {
			v = v[:160] + "…"
		}
		line := fmt.Sprintf("%-22s = %s\n", k, v)
		// Soft cap of 6KB so the rest of the payload (chain, evidence
		// IDs) doesn't get truncated by Slack.
		if total+len(line) > 6000 {
			b.WriteString("… (truncated)\n")
			break
		}
		b.WriteString(line)
		total += len(line)
	}
	return b.String()
}

func nz(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func sortStrings(s []string) {
	// avoid pulling in sort just for this in a hot path? cheap.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func teamsPayload(a model.Alert, host string) []byte {
	body, _ := json.Marshal(map[string]any{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"themeColor": severityColor(a.Event.Severity),
		"summary":    a.RuleID,
		"title": fmt.Sprintf("[%s] %s @ %s",
			a.Event.Severity.String(), a.RuleID, host),
		"text": a.Reason,
		"sections": []map[string]any{{
			"facts": []map[string]string{
				{"name": "Sensor", "value": a.Event.Sensor},
				{"name": "PID", "value": fmt.Sprintf("%d", a.Event.PID)},
				{"name": "Comm", "value": a.Event.Comm},
				{"name": "Image", "value": a.Event.Image},
			},
		}},
	})
	return body
}

func genericPayload(a model.Alert, host string) []byte {
	body, _ := json.Marshal(map[string]any{
		"host":     host,
		"rule_id":  a.RuleID,
		"reason":   a.Reason,
		"severity": a.Event.Severity.String(),
		"time":     a.Event.Time.UTC(),
		"event":    a.Event,
	})
	return body
}

func severityColor(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "#ff0000"
	case model.SeverityHigh:
		return "#ff8800"
	case model.SeverityWarn:
		return "#ffd000"
	case model.SeverityNotice:
		return "#0099ff"
	}
	return "#888888"
}


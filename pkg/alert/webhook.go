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

func slackPayload(a model.Alert, host string) []byte {
	colour := severityColor(a.Event.Severity)
	tagsBlock := tagsTable(a.Event.Tags)

	body, _ := json.Marshal(map[string]any{
		"attachments": []map[string]any{{
			"color":      colour,
			"title":      fmt.Sprintf("[%s] %s", a.Event.Severity.String(), a.RuleID),
			"text":       a.Reason,
			"fields": []map[string]any{
				{"title": "Host", "value": host, "short": true},
				{"title": "Sensor", "value": a.Event.Sensor, "short": true},
				{"title": "PID", "value": fmt.Sprintf("%d", a.Event.PID), "short": true},
				{"title": "Comm", "value": a.Event.Comm, "short": true},
				{"title": "Image", "value": a.Event.Image, "short": false},
				{"title": "Tags", "value": "```" + tagsBlock + "```", "short": false},
			},
			"footer":   "xhelix",
			"ts":       a.Event.Time.Unix(),
		}},
	})
	return body
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

func tagsTable(tags map[string]string) string {
	if len(tags) == 0 {
		return "(none)"
	}
	out := ""
	keys := []string{
		"path", "src", "src_ip", "dst_ip", "argv", "method",
		"user", "kind", "persona", "token_id",
	}
	for _, k := range keys {
		if v := tags[k]; v != "" {
			if len(v) > 80 {
				v = v[:80] + "..."
			}
			out += fmt.Sprintf("%-12s = %s\n", k, v)
		}
	}
	return out
}

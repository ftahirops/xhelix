package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestWebhookGenericPayload(t *testing.T) {
	var mu sync.Mutex
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		mu.Lock()
		got = body
		mu.Unlock()
	}))
	defer srv.Close()

	s := NewWebhookSink(srv.URL, "test-host")
	ev := model.NewEvent("ebpf.proc", model.SeverityCritical)
	ev.Comm = "evil"
	ev.Tags["src_ip"] = "198.51.100.5"
	a := model.Alert{Event: ev, RuleID: "test_rule", Reason: "boom"}

	if err := s.Send(context.Background(), a); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	var parsed map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if parsed["rule_id"] != "test_rule" {
		t.Errorf("rule_id = %v", parsed["rule_id"])
	}
	if parsed["host"] != "test-host" {
		t.Errorf("host = %v", parsed["host"])
	}
}

func TestWebhookSlackFormat(t *testing.T) {
	a := model.Alert{
		Event:  model.NewEvent("ebpf.proc", model.SeverityCritical),
		RuleID: "shell_with_socket_fd",
		Reason: "reverse shell pattern",
	}
	a.Event.Tags["src_ip"] = "198.51.100.5"

	body := slackPayload(a, "host-01")
	if !strings.Contains(string(body), "attachments") {
		t.Errorf("not slack-shaped: %s", body)
	}
	if !strings.Contains(string(body), "shell_with_socket_fd") {
		t.Errorf("rule id missing")
	}
}

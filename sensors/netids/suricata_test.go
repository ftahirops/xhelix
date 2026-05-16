package netids

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestSuricataSupervisorMissingBinaryIsNoOp(t *testing.T) {
	s := &SuricataSupervisor{
		BinaryPath: "/nonexistent/suricata-not-here",
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start should be no-op when binary missing, got %v", err)
	}
	if s.Healthy() {
		t.Error("missing binary should not be healthy")
	}
	if err := s.Stop(ctx); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

func TestEveTailerProjectsAlerts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	tailer := NewEveTailer(path)
	out := make(chan model.Event, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tailer.Run(ctx, out) }()

	// Give the tailer a moment to open the file and seek to end
	// before we append. Without this, a fast writer can race ahead
	// and the tailer's seek lands past the new bytes.
	time.Sleep(150 * time.Millisecond)

	// Append an alert line.
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	_, _ = f.WriteString(`{"timestamp":"2026-04-30T16:02:01Z","event_type":"alert",` +
		`"src_ip":"10.0.0.5","dest_ip":"203.0.113.7","proto":"TCP",` +
		`"alert":{"action":"allowed","signature_id":2001234,` +
		`"signature":"ET WEB Log4j","severity":2,"category":"Web Attack"}}` + "\n")
	f.Close()

	select {
	case ev := <-out:
		if ev.Tags["sig_id"] != "2001234" {
			t.Errorf("sig_id = %q", ev.Tags["sig_id"])
		}
		if ev.Severity != model.SeverityHigh {
			t.Errorf("severity = %v, want high", ev.Severity)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event received from tailer")
	}
}

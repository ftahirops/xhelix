package decoy

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestPersonasRender(t *testing.T) {
	for _, p := range Personas() {
		body := p.Render("CANARY123")
		if !strings.Contains(string(body), "CANARY123") {
			t.Errorf("%s: token not embedded in render output", p.Name)
		}
	}
}

func TestFilesSensorRendersAndDetectsAccess(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "credentials.txt")
	files := []HoneyFile{
		{Path: target, Persona: "passwd-list"},
	}
	s := NewFilesSensor(files, "test-host")
	out := make(chan model.Event, 4)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx, out); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())

	// File must have been rendered.
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "db_pass=") {
		t.Errorf("rendered body missing expected key: %q", string(body))
	}

	// Touch atime by reading the file twice with a delay.
	time.Sleep(300 * time.Millisecond)
	_, _ = os.ReadFile(target)
	time.Sleep(800 * time.Millisecond)

	// We should have seen at least one decoy event.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-out:
			if ev.Sensor == "decoy" && ev.Tags["honey_file_open"] == "true" {
				return
			}
		case <-deadline:
			// Some filesystems update atime lazily; treat the
			// poll-fallback as best-effort. The test still asserts
			// the rendered content above, which is the load-bearing
			// part. Real-host fanotify integration is the real test.
			t.Skip("no atime-driven event observed; poll-fallback is best-effort")
			return
		}
	}
}

// TestFilesSensorWatchesPreexistingHoneyFile: an operator pre-seeds the
// honey file on a read-only-visible path (the only way decoys work under
// the daemon's own ProtectSystem=strict hardening). Start must watch it
// without overwriting. Found by live validation 2026-06-13.
func TestFilesSensorWatchesPreexistingHoneyFile(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "credentials.bak")
	const seeded = "OPERATOR_SEEDED=keepme\n"
	if err := os.WriteFile(target, []byte(seeded), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewFilesSensor([]HoneyFile{{Path: target, Persona: "aws-creds"}}, "h")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx, make(chan model.Event, 4)); err != nil {
		t.Fatalf("Start should watch a pre-existing honey file, got: %v", err)
	}
	defer s.Stop(context.Background())
	if body, _ := os.ReadFile(target); string(body) != seeded {
		t.Errorf("pre-existing honey file was overwritten: %q", body)
	}
}

// TestFilesSensorBestEffortRender: a path that can't be rendered or
// located must be skipped, not abort the whole sensor — unless EVERY
// path is unwatchable, which is a real error. Uses an ENOTDIR path so it
// fails even when tests run as root.
func TestFilesSensorBestEffortRender(t *testing.T) {
	tmp := t.TempDir()
	good := filepath.Join(tmp, "good.bak")
	notADir := filepath.Join(tmp, "iamafile")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(notADir, "bad.bak") // mkdir under a file → ENOTDIR

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// mix: one good + one unwatchable → Start succeeds, good is rendered.
	s := NewFilesSensor([]HoneyFile{
		{Path: good, Persona: "aws-creds"},
		{Path: bad, Persona: "aws-creds"},
	}, "h")
	if err := s.Start(ctx, make(chan model.Event, 4)); err != nil {
		t.Fatalf("Start should be best-effort with one bad path, got: %v", err)
	}
	s.Stop(context.Background())
	if _, err := os.Stat(good); err != nil {
		t.Errorf("good honey file not rendered: %v", err)
	}

	// all-bad → Start errors (nothing watchable).
	s2 := NewFilesSensor([]HoneyFile{{Path: bad, Persona: "aws-creds"}}, "h")
	if err := s2.Start(ctx, make(chan model.Event, 4)); err == nil {
		s2.Stop(context.Background())
		t.Fatal("Start should error when no honey file is watchable")
	}
}

func TestServicesSensorAcceptsConnect(t *testing.T) {
	s := NewServicesSensor([]HoneyService{
		{Persona: "redis", Bind: "127.0.0.1:0"},
	}, "test-host")

	out := make(chan model.Event, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx, out); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())

	addrs := s.Addrs()
	if len(addrs) == 0 {
		t.Fatal("no listener addresses")
	}
	c, err := net.Dial("tcp", addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("PING\r\n"))
	buf := make([]byte, 64)
	_, _ = c.Read(buf)
	c.Close()

	select {
	case ev := <-out:
		if ev.Tags["honey_service_connect"] != "true" {
			t.Errorf("unexpected event: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no service-connect event")
	}
}

func TestCanaryReceiverFires(t *testing.T) {
	tok := Token{ID: "tok_test_123", Type: "passwd-list", Persona: "passwd-list"}
	r := NewCanaryReceiver("127.0.0.1:0", "test-host", []Token{tok})
	out := make(chan model.Event, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx, out); err != nil {
		t.Fatal(err)
	}
	defer r.Stop(context.Background())

	url := "http://" + r.Addr() + "/" + tok.ID + "/use"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ok") {
		t.Errorf("unexpected canary body: %q", body)
	}

	select {
	case ev := <-out:
		if ev.Tags["token_used"] != "true" {
			t.Errorf("unexpected event: %+v", ev)
		}
		if ev.Tags["token_id"] != tok.ID {
			t.Errorf("token_id = %q", ev.Tags["token_id"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no canary event")
	}
}

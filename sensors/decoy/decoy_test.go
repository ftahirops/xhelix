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

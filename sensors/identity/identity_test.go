package identity

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestParseSSHAccepted(t *testing.T) {
	line := "Apr 30 16:02:00 host sshd[1234]: Accepted publickey for alice from 198.51.100.5 port 54321 ssh2"
	ev, ok := ParseSSHDLine(line, "host")
	if !ok {
		t.Fatal("expected match")
	}
	if ev.Tags["outcome"] != "success" {
		t.Errorf("outcome = %q", ev.Tags["outcome"])
	}
	if ev.Tags["user"] != "alice" {
		t.Errorf("user = %q", ev.Tags["user"])
	}
	if ev.Tags["src_ip"] != "198.51.100.5" {
		t.Errorf("src_ip = %q", ev.Tags["src_ip"])
	}
	if ev.Tags["method"] != "publickey" {
		t.Errorf("method = %q", ev.Tags["method"])
	}
}

func TestParseSSHFailed(t *testing.T) {
	line := "Apr 30 16:02:00 host sshd[1234]: Failed password for root from 192.0.2.5 port 12345 ssh2"
	ev, ok := ParseSSHDLine(line, "host")
	if !ok {
		t.Fatal("expected match")
	}
	if ev.Tags["outcome"] != "failure" {
		t.Errorf("outcome = %q", ev.Tags["outcome"])
	}
	if ev.Severity != model.SeverityWarn {
		t.Errorf("severity = %v, want warn", ev.Severity)
	}
}

func TestParseSudo(t *testing.T) {
	line := "Apr 30 16:02:00 host sudo[1234]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
	ev, ok := ParseSSHDLine(line, "host")
	if !ok {
		t.Fatal("expected match")
	}
	if ev.Sensor != "identity.sudo" {
		t.Errorf("sensor = %q", ev.Sensor)
	}
	if ev.Tags["user"] != "alice" {
		t.Errorf("user = %q", ev.Tags["user"])
	}
	if ev.Tags["target_user"] != "root" {
		t.Errorf("target_user = %q", ev.Tags["target_user"])
	}
	if ev.Tags["command"] != "/usr/bin/cat /etc/shadow" {
		t.Errorf("command = %q", ev.Tags["command"])
	}
}

func TestPAMBridgeReceivesJSON(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "pam.sock")
	b := NewPAMBridge(sock, "host")
	out := make(chan model.Event, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := b.Start(ctx, out); err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body, _ := json.Marshal(pamMessage{
		Type: "open_session", Service: "sshd",
		User: "alice", RHost: "198.51.100.5", TTY: "pts/0",
	})
	c.Write(append(body, '\n'))

	select {
	case ev := <-out:
		if ev.Tags["user"] != "alice" {
			t.Errorf("user = %q", ev.Tags["user"])
		}
		if ev.Tags["pam_type"] != "open_session" {
			t.Errorf("pam_type = %q", ev.Tags["pam_type"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no PAM event")
	}
}

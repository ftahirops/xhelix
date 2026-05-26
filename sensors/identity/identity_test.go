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

// TestParseSSHPIDExtraction is the regression test for the 2026-05-24
// fix: every identity line MUST stamp ev.PID so the source minter can
// attach the new SourceAnchor to a live process. Without this, the
// proctree never inherits the anchor and propagation chain breaks.
// Audited gap: 12 SSH anchors on dev host each had exactly 1 attributed
// event before this fix.
func TestParseSSH_PIDExtraction(t *testing.T) {
	cases := []struct {
		name string
		line string
		want uint32
	}{
		{
			name: "accepted",
			line: "May 24 11:07:20 vm sshd[721858]: Accepted publickey for root from 95.211.19.203 port 49694 ssh2",
			want: 721858,
		},
		{
			name: "failed",
			line: "Apr 30 16:02:00 host sshd[1234]: Failed password for root from 192.0.2.5 port 12345 ssh2",
			want: 1234,
		},
		{
			name: "invalid_user",
			line: "Apr 30 16:02:00 host sshd[999]: Invalid user nobody from 192.0.2.5",
			want: 999,
		},
		{
			name: "sudo",
			line: "Apr 30 16:02:00 host sudo[5555]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
			want: 5555,
		},
		{
			name: "su",
			line: "Apr 30 16:02:00 host su[12]: (to root) alice on pts/0",
			want: 12,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := ParseSSHDLine(c.line, "host")
			if !ok {
				t.Fatalf("line did not parse: %q", c.line)
			}
			if ev.PID != c.want {
				t.Errorf("PID=%d, want %d (line=%q)", ev.PID, c.want, c.line)
			}
		})
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

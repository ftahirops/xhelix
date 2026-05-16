package session

import (
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestSessionLifecycle(t *testing.T) {
	tr := New(0)

	// Login
	login := model.NewEvent("identity.sshd", model.SeverityInfo)
	login.Tags["outcome"] = "success"
	login.Tags["user"] = "alice"
	login.Tags["src_ip"] = "198.51.100.5"
	login.Tags["method"] = "publickey"
	login.PID = 1234
	login.Time = time.Now()
	tr.Ingest(login)

	sessions := tr.List()
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(sessions))
	}
	s := sessions[0]
	if s.User != "alice" || s.SrcIP != "198.51.100.5" || !s.Active {
		t.Errorf("session bad: %+v", s)
	}

	// Child process spawn — should attribute to session
	spawn := model.NewEvent("ebpf.proc", model.SeverityNotice)
	spawn.PID = 1235
	spawn.ParentPID = 1234
	spawn.Comm = "bash"
	spawn.Tags["argv"] = "bash -i"
	tr.Ingest(spawn)

	// Grand-child spawn
	gc := model.NewEvent("ebpf.proc", model.SeverityNotice)
	gc.PID = 1236
	gc.ParentPID = 1235
	gc.Comm = "curl"
	gc.Tags["argv"] = "curl http://malicious"
	tr.Ingest(gc)

	snap := s.Snapshot()
	if len(snap.Events) != 2 {
		t.Errorf("attributed events = %d, want 2", len(snap.Events))
	}
	if len(snap.Commands) != 2 {
		t.Errorf("commands = %v", snap.Commands)
	}

	// Disconnect
	dc := model.NewEvent("identity.sshd", model.SeverityInfo)
	dc.Tags["outcome"] = "disconnect"
	dc.Tags["user"] = "alice"
	dc.Tags["src_ip"] = "198.51.100.5"
	dc.Time = time.Now().Add(time.Minute)
	tr.Ingest(dc)

	if s.Active {
		t.Error("session should be inactive after disconnect")
	}
}

func TestAlertAttachedToSession(t *testing.T) {
	tr := New(0)
	login := model.NewEvent("identity.sshd", model.SeverityInfo)
	login.Tags["outcome"] = "success"
	login.Tags["user"] = "bob"
	login.Tags["src_ip"] = "203.0.113.10"
	login.PID = 2001
	tr.Ingest(login)

	bad := model.NewEvent("ebpf.proc", model.SeverityCritical)
	bad.PID = 2002
	bad.ParentPID = 2001
	tr.Ingest(bad)

	a := model.Alert{Event: bad, RuleID: "shell_with_socket_fd"}
	tr.IngestAlert(a)

	s := tr.List()[0]
	snap := s.Snapshot()
	if len(snap.Alerts) != 1 {
		t.Errorf("alerts = %d, want 1", len(snap.Alerts))
	}
}

package autobaseline

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestObserveThenIsKnownAfterSeal(t *testing.T) {
	db := filepath.Join(t.TempDir(), "ab.db")
	m, err := New(Options{DBPath: db, Observation: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if m.Mode() != ModeObserve {
		t.Fatalf("expected observe, got %s", m.Mode())
	}

	m.Observe("/usr/sbin/nginx", Behavior{Action: "syscall", Detail: "execve"})
	m.Observe("/usr/sbin/nginx", Behavior{Action: "outbound", Detail: "10.0.0.0/16:443"})

	// During observe IsKnown must be false.
	if m.IsKnown("/usr/sbin/nginx", Behavior{Action: "syscall", Detail: "execve"}) {
		t.Fatal("IsKnown returned true before seal")
	}

	// Sleep past the window, then tick.
	time.Sleep(60 * time.Millisecond)
	if err := m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.Mode() != ModeDetect {
		t.Fatalf("expected detect after window elapsed, got %s", m.Mode())
	}

	if !m.IsKnown("/usr/sbin/nginx", Behavior{Action: "syscall", Detail: "execve"}) {
		t.Fatal("expected execve to be known")
	}
	if m.IsKnown("/usr/sbin/nginx", Behavior{Action: "syscall", Detail: "ptrace"}) {
		t.Fatal("ptrace was never observed; must not be known")
	}
	if m.IsKnown("/usr/bin/some-other-binary", Behavior{Action: "syscall", Detail: "execve"}) {
		t.Fatal("unknown binary must not match")
	}
}

func TestForceSeal(t *testing.T) {
	db := filepath.Join(t.TempDir(), "ab.db")
	m, err := New(Options{DBPath: db, Observation: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	m.Observe("/usr/bin/sshd", Behavior{Action: "cap_gained", Detail: "CAP_SETUID"})
	if err := m.ForceSeal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.Mode() != ModeDetect {
		t.Fatalf("ForceSeal didn't advance mode")
	}
	if !m.IsKnown("/usr/bin/sshd", Behavior{Action: "cap_gained", Detail: "CAP_SETUID"}) {
		t.Fatal("sshd cap_gained should be known after force-seal")
	}
}

func TestPersistAcrossRestart(t *testing.T) {
	db := filepath.Join(t.TempDir(), "ab.db")
	m, err := New(Options{DBPath: db, Observation: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	m.Observe("/usr/sbin/cron", Behavior{Action: "child_spawn", Detail: "logrotate"})
	if err := m.ForceSeal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}

	m2, err := New(Options{DBPath: db, Observation: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	if m2.Mode() != ModeDetect {
		t.Fatalf("expected reload as detect, got %s", m2.Mode())
	}
	if !m2.IsKnown("/usr/sbin/cron", Behavior{Action: "child_spawn", Detail: "logrotate"}) {
		t.Fatal("reload lost cron behaviour")
	}
}

func TestEventToBehavior(t *testing.T) {
	type ev struct {
		sensor string
		tags   map[string]string
	}
	cases := []struct {
		name   string
		in     ev
		want   Behavior
		wantOK bool
	}{
		{"cap_gained", ev{"capwatch", map[string]string{"action": "cap_gained", "capability": "CAP_SYS_ADMIN"}},
			Behavior{Action: "cap_gained", Detail: "CAP_SYS_ADMIN"}, true},
		{"file_write_path_dir", ev{"fim", map[string]string{"path": "/etc/cron.d/evil"}},
			Behavior{Action: "file_write", Detail: "/etc/cron.d"}, true},
		{"outbound_endpoint", ev{"netids", map[string]string{"endpoint": "10.0.0.0/16:443"}},
			Behavior{Action: "outbound", Detail: "10.0.0.0/16:443"}, true},
		{"unrelated", ev{"heartbeat", map[string]string{}},
			Behavior{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := EventToBehavior(mkEvent(c.in.sensor, c.in.tags))
			if ok != c.wantOK {
				t.Fatalf("ok=%v want %v", ok, c.wantOK)
			}
			if ok && got != c.want {
				t.Fatalf("got %+v want %+v", got, c.want)
			}
		})
	}
}

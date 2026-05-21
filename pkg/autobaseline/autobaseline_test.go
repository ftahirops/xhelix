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

// TestEventToBehaviorRealSensors uses tag shapes captured from
// plesk.douxl.com hot.db on 2026-05-21 — proves the projection
// matches what the daemon actually emits, not what was guessed.
func TestEventToBehaviorRealSensors(t *testing.T) {
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
		// Real ebpf.cap shape from prod (sshd capset).
		{"ebpf.cap_set", ev{"ebpf.cap", map[string]string{
			"kind": "cap_set", "cap_effective": "0x1ffffffffff", "cap_permitted": "0x1ffffffffff",
		}}, Behavior{Action: "cap_set", Detail: "0x1ffffffffff"}, true},
		// Real ebpf.proc spawn.
		{"ebpf.proc_spawn", ev{"ebpf.proc", map[string]string{
			"kind": "proc_spawn", "path": "/usr/bin/date",
		}}, Behavior{Action: "spawn", Detail: "date"}, true},
		{"ebpf.proc_exit_skip", ev{"ebpf.proc", map[string]string{
			"kind": "proc_exit",
		}}, Behavior{}, false},
		// Memfd dominates regardless of sensor.
		{"memfd_spawn", ev{"ebpf.proc", map[string]string{
			"kind": "proc_spawn", "from_memfd": "true", "path": "/proc/self/fd/9",
		}}, Behavior{Action: "memfd_spawn", Detail: "9"}, true},
		// Net bind/connect.
		{"net_bind", ev{"ebpf.net", map[string]string{
			"kind": "net_bind", "dst_port": "443",
		}}, Behavior{Action: "net_bind", Detail: "443"}, true},
		{"net_connect", ev{"ebpf.net", map[string]string{
			"kind": "net_connect", "dst_port": "80",
		}}, Behavior{Action: "net_connect", Detail: "80"}, true},
		// SSL presence.
		{"ssl_io", ev{"ebpf.ssl", map[string]string{
			"kind": "ssl_read", "ssl_read": "true",
		}}, Behavior{Action: "ssl_io"}, true},
		// FIM with real-ish tag.
		{"fim_path", ev{"fim", map[string]string{
			"path": "/etc/cron.d/evil",
		}}, Behavior{Action: "file_write", Detail: "/etc/cron.d"}, true},
		// Identity success/failure.
		{"sshd_ok", ev{"identity.sshd", map[string]string{
			"outcome": "success", "user": "root",
		}}, Behavior{Action: "auth_ok", Detail: "root"}, true},
		{"sshd_fail", ev{"identity.sshd", map[string]string{
			"outcome": "failure", "user": "admin",
		}}, Behavior{Action: "auth_fail", Detail: "admin"}, true},
		// Tag-bit signals dominate.
		{"mprotect_rwx", ev{"ebpf.proc", map[string]string{
			"mprotect_rwx": "true", "kind": "proc_spawn",
		}}, Behavior{Action: "mprotect_rwx"}, true},
		{"shell_socket", ev{"ebpf.proc", map[string]string{
			"stdin_is_socket": "true", "kind": "proc_spawn",
		}}, Behavior{Action: "shell_socket"}, true},
		// Skip noise sensors.
		{"heartbeat", ev{"heartbeat", map[string]string{}}, Behavior{}, false},
		{"synthetic", ev{"test.synthetic", map[string]string{}}, Behavior{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := EventToBehavior(mkEvent(c.in.sensor, c.in.tags))
			if ok != c.wantOK {
				t.Fatalf("ok=%v want %v (got=%+v)", ok, c.wantOK, got)
			}
			if ok && got != c.want {
				t.Fatalf("got %+v want %+v", got, c.want)
			}
		})
	}
}

func TestImageKeyFallbacks(t *testing.T) {
	ev := mkEvent("ebpf.proc", map[string]string{"path": "/bin/ls"})
	ev.Comm = "ls"
	if got := ImageKey(ev); got != "/bin/ls" {
		t.Errorf("with tag.path: got %q", got)
	}
	ev2 := mkEvent("ebpf.cap", map[string]string{})
	ev2.Comm = "sshd"
	if got := ImageKey(ev2); got != "comm:sshd" {
		t.Errorf("comm fallback: got %q", got)
	}
	ev3 := mkEvent("heartbeat", map[string]string{})
	if got := ImageKey(ev3); got != "sensor:heartbeat" {
		t.Errorf("sensor fallback: got %q", got)
	}
}

package shmguard

import (
	"strings"
	"testing"
)

func TestNonTmpfsExecNoFire(t *testing.T) {
	d := NewDetector([]string{"/dev/shm", "/run/user/1000", "/tmp"})
	v := d.Evaluate(Spawn{Exe: "/usr/bin/firefox", UID: 1000})
	if v.Severity != SeverityNone {
		t.Fatalf("severity = %s, want none", v.Severity)
	}
}

func TestDevShmExec(t *testing.T) {
	d := NewDetector([]string{"/dev/shm"})
	v := d.Evaluate(Spawn{Exe: "/dev/shm/payload", UID: 1000})
	if v.Severity < SeverityHigh {
		t.Fatalf("severity = %s, want high+", v.Severity)
	}
	if v.Mount != "/dev/shm" {
		t.Fatalf("mount = %q", v.Mount)
	}
}

func TestDevShmExecAsRootIsCritical(t *testing.T) {
	d := NewDetector([]string{"/dev/shm"})
	v := d.Evaluate(Spawn{Exe: "/dev/shm/payload", UID: 0})
	if v.Severity != SeverityCritical {
		t.Fatalf("severity = %s, want critical", v.Severity)
	}
}

func TestSUIDOnTmpfsIsCritical(t *testing.T) {
	d := NewDetector([]string{"/dev/shm"})
	v := d.Evaluate(Spawn{Exe: "/dev/shm/x", UID: 1000, SUID: true})
	if v.Severity != SeverityCritical {
		t.Fatalf("severity = %s, want critical", v.Severity)
	}
}

func TestRunUserExec(t *testing.T) {
	d := NewDetector([]string{"/run/user/1000"})
	v := d.Evaluate(Spawn{Exe: "/run/user/1000/dropper", UID: 1000})
	if v.Severity < SeverityHigh {
		t.Fatalf("severity = %s, want high+", v.Severity)
	}
}

func TestPlainTmpfsMediumOnly(t *testing.T) {
	// A tmpfs mount that's not /dev/shm or /run/user — e.g.
	// /tmp on tmpfs. Still suspicious, but slightly less so.
	d := NewDetector([]string{"/tmp"})
	v := d.Evaluate(Spawn{Exe: "/tmp/blob", UID: 1000})
	if v.Severity != SeverityMedium {
		t.Fatalf("severity = %s, want medium", v.Severity)
	}
}

func TestLongestPrefixWins(t *testing.T) {
	d := NewDetector([]string{"/run", "/run/user/1000"})
	v := d.Evaluate(Spawn{Exe: "/run/user/1000/x"})
	if v.Mount != "/run/user/1000" {
		t.Fatalf("mount = %q, want /run/user/1000", v.Mount)
	}
}

func TestRootMountIgnored(t *testing.T) {
	d := NewDetector([]string{"/"})
	v := d.Evaluate(Spawn{Exe: "/usr/bin/curl"})
	if v.Severity != SeverityNone {
		t.Fatalf("severity = %s, want none (root tmpfs ignored)", v.Severity)
	}
}

func TestEmptyExe(t *testing.T) {
	d := NewDetector([]string{"/dev/shm"})
	v := d.Evaluate(Spawn{Exe: ""})
	if v.Severity != SeverityNone {
		t.Fatalf("severity = %s, want none", v.Severity)
	}
}

func TestParseProcMounts(t *testing.T) {
	content := `proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sys /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev,size=1631692k,mode=755 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
/dev/sda1 / ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev 0 0
devtmpfs /dev devtmpfs rw,nosuid,size=4k,nr_inodes=4080040,mode=755 0 0
`
	d := FromProcMounts(strings.NewReader(content))
	want := map[string]bool{"/run": true, "/dev/shm": true, "/tmp": true, "/dev": true}
	got := d.Mounts()
	if len(got) != len(want) {
		t.Fatalf("got %d mounts, want %d: %v", len(got), len(want), got)
	}
	for _, m := range got {
		if !want[m] {
			t.Fatalf("unexpected mount %q in %v", m, got)
		}
	}
}

func TestRefresh(t *testing.T) {
	d := NewDetector([]string{"/dev/shm"})
	if v := d.Evaluate(Spawn{Exe: "/tmp/x", UID: 1000}); v.Severity != SeverityNone {
		t.Fatal("should not fire before /tmp is added")
	}
	d.Refresh([]string{"/dev/shm", "/tmp"})
	if v := d.Evaluate(Spawn{Exe: "/tmp/x", UID: 1000}); v.Severity != SeverityMedium {
		t.Fatalf("severity after refresh = %s", v.Severity)
	}
}

func TestDeduplicationAndTrim(t *testing.T) {
	d := NewDetector([]string{"/dev/shm", "/dev/shm/", "/dev/shm"})
	if len(d.Mounts()) != 1 {
		t.Fatalf("expected 1 mount, got %v", d.Mounts())
	}
}

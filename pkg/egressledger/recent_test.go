package egressledger

import (
	"testing"
	"time"
)

func TestRecentRingRetainsContainerFields(t *testing.T) {
	r := newRecentRing(8)
	r.push(ProcEvent{
		Time:           time.Now(),
		Binary:         "/usr/bin/curl",
		PID:            4242,
		DestIP:         "203.0.113.1",
		ContainerID:    "abc123",
		ContainerClass: "container",
	})
	snap := r.snapshot()
	if len(snap) != 1 {
		t.Fatalf("want 1 row, got %d", len(snap))
	}
	if snap[0].ContainerID != "abc123" {
		t.Fatalf("ContainerID not retained: got %q", snap[0].ContainerID)
	}
	if snap[0].ContainerClass != "container" {
		t.Fatalf("ContainerClass not retained: got %q", snap[0].ContainerClass)
	}
}

func TestRecentRingRetainsServiceRoleParentComm(t *testing.T) {
	r := newRecentRing(8)
	r.push(ProcEvent{
		Time:        time.Now(),
		Binary:      "/usr/bin/postgres",
		PID:         5151,
		DestIP:      "203.0.113.2",
		ServiceRole: "database",
		ParentComm:  "sshd",
	})
	snap := r.snapshot()
	if len(snap) != 1 {
		t.Fatalf("want 1 row, got %d", len(snap))
	}
	if snap[0].ServiceRole != "database" {
		t.Fatalf("ServiceRole not retained: got %q", snap[0].ServiceRole)
	}
	if snap[0].ParentComm != "sshd" {
		t.Fatalf("ParentComm not retained: got %q", snap[0].ParentComm)
	}
}

func TestRecentRingRetainsL7Protocol(t *testing.T) {
	r := newRecentRing(8)
	r.push(ProcEvent{
		Time:       time.Now(),
		Binary:     "/usr/bin/curl",
		PID:        6262,
		DestIP:     "203.0.113.3",
		L7Protocol: "http",
	})
	snap := r.snapshot()
	if len(snap) != 1 {
		t.Fatalf("want 1 row, got %d", len(snap))
	}
	if snap[0].L7Protocol != "http" {
		t.Fatalf("L7Protocol not retained: got %q", snap[0].L7Protocol)
	}
}

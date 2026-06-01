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

package source

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/lineage"
)

// seed inserts an anchor + a handful of events for graph tests.
// Returns the anchorID and the base time so the test can build windows.
func seedAnchorWithEvents(t *testing.T) (*Store, lineage.LineageID, time.Time) {
	t.Helper()
	s := openMem(t)
	ctx := context.Background()
	base := time.Date(2026, 5, 23, 14, 0, 0, 0, time.UTC)

	if err := s.Put(ctx, Anchor{
		ID: 42, Kind: KindSSH, CreatedAt: base, Actor: "alice",
		SourceIP: "1.2.3.4", Host: "test-host",
	}); err != nil {
		t.Fatalf("Put anchor: %v", err)
	}

	events := []GraphEvent{
		// bash spawns at +0s
		{SourceAnchorID: 42, Time: base, PID: 200, ParentPID: 100,
			Kind: KindSpawn, Comm: "bash", TargetImage: "/bin/bash", UID: 1000},
		// bash reads .bashrc at +1s
		{SourceAnchorID: 42, Time: base.Add(time.Second), PID: 200,
			Kind: KindFileRead, TargetPath: "/home/alice/.bashrc", Comm: "bash", UID: 1000},
		// bash reads /etc/passwd at +2s
		{SourceAnchorID: 42, Time: base.Add(2 * time.Second), PID: 200,
			Kind: KindFileRead, TargetPath: "/etc/passwd", Comm: "bash", UID: 1000},
		// bash net connect at +3s
		{SourceAnchorID: 42, Time: base.Add(3 * time.Second), PID: 200,
			Kind: KindNetConnect, TargetHost: "backend", TargetPort: 8080,
			Comm: "bash", UID: 1000},
		// sudo at +30s — high severity
		{SourceAnchorID: 42, Time: base.Add(30 * time.Second), PID: 250, ParentPID: 200,
			Kind: KindIdentity, Comm: "sudo", UID: 0, Severity: SeverityHigh},
		// child of sudo: bash as root at +31s
		{SourceAnchorID: 42, Time: base.Add(31 * time.Second), PID: 260, ParentPID: 250,
			Kind: KindSpawn, Comm: "bash", TargetImage: "/bin/bash", UID: 0},
		// root bash reads /etc/shadow at +32s — secret access, critical
		{SourceAnchorID: 42, Time: base.Add(32 * time.Second), PID: 260,
			Kind: KindSecretAccess, TargetPath: "/etc/shadow", Comm: "bash",
			UID: 0, Severity: SeverityCritical},
		// root bash writes /tmp/x at +33s
		{SourceAnchorID: 42, Time: base.Add(33 * time.Second), PID: 260,
			Kind: KindFileWrite, TargetPath: "/tmp/x", Comm: "bash", UID: 0},
		// curl spawned by root bash at +40s
		{SourceAnchorID: 42, Time: base.Add(40 * time.Second), PID: 270, ParentPID: 260,
			Kind: KindSpawn, Comm: "curl", TargetImage: "/usr/bin/curl", UID: 0},
		// curl outbound at +41s
		{SourceAnchorID: 42, Time: base.Add(41 * time.Second), PID: 270,
			Kind: KindNetConnect, TargetHost: "5.6.7.8", TargetPort: 443,
			Comm: "curl", UID: 0, Severity: SeverityWarn},
	}
	for i, ev := range events {
		if _, err := s.RecordEvent(ctx, ev); err != nil {
			t.Fatalf("RecordEvent[%d]: %v", i, err)
		}
	}
	return s, 42, base
}

func TestRecordEvent_ZeroAnchorRejected(t *testing.T) {
	s := openMem(t)
	_, err := s.RecordEvent(context.Background(), GraphEvent{Kind: KindSpawn, PID: 1})
	if err == nil {
		t.Fatal("RecordEvent must reject zero anchor")
	}
}

func TestRecordEvent_EmptyKindRejected(t *testing.T) {
	s := openMem(t)
	_, err := s.RecordEvent(context.Background(), GraphEvent{SourceAnchorID: 1, PID: 1})
	if err == nil {
		t.Fatal("RecordEvent must reject empty kind")
	}
}

func TestRecordEvent_RoundTripWithDefaults(t *testing.T) {
	s := openMem(t)
	ctx := context.Background()
	if err := s.Put(ctx, Anchor{ID: 1, Kind: KindSSH, CreatedAt: time.Now().UTC(), Actor: "u"}); err != nil {
		t.Fatalf("put anchor: %v", err)
	}
	id, err := s.RecordEvent(ctx, GraphEvent{
		SourceAnchorID: 1, PID: 100, Kind: KindFileRead, TargetPath: "/etc/passwd",
	})
	if err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero row id")
	}
}

func TestSpineFor_BasicTree(t *testing.T) {
	s, anchorID, _ := seedAnchorWithEvents(t)
	spine, err := s.SpineFor(context.Background(), anchorID, TimeWindow{})
	if err != nil {
		t.Fatalf("SpineFor: %v", err)
	}
	// Expect: source + pid 200 (bash) + 250 (sudo) + 260 (root bash) + 270 (curl) = 5 nodes.
	if len(spine) != 5 {
		t.Fatalf("spine len=%d, want 5: %+v", len(spine), spine)
	}
	if spine[0].Kind != "source" {
		t.Errorf("first node kind=%q, want source", spine[0].Kind)
	}
	pids := map[uint32]bool{}
	for _, n := range spine[1:] {
		pids[n.PID] = true
	}
	for _, want := range []uint32{200, 250, 260, 270} {
		if !pids[want] {
			t.Errorf("spine missing PID %d", want)
		}
	}
}

func TestSpineFor_ParentReparenting(t *testing.T) {
	s, anchorID, _ := seedAnchorWithEvents(t)
	spine, _ := s.SpineFor(context.Background(), anchorID, TimeWindow{})
	// PID 200's parent_pid is 100 (not in spine) → should reparent to source.
	// PID 260's parent_pid is 250 (in spine) → should keep parent.
	for _, n := range spine[1:] {
		switch n.PID {
		case 200:
			if n.ParentNodeKey != "src-42" {
				t.Errorf("PID 200 (parent 100 not in spine) should reparent to src-42, got %q", n.ParentNodeKey)
			}
		case 260:
			if n.ParentNodeKey != "p-250" {
				t.Errorf("PID 260 should keep parent p-250, got %q", n.ParentNodeKey)
			}
		case 270:
			if n.ParentNodeKey != "p-260" {
				t.Errorf("PID 270 should keep parent p-260, got %q", n.ParentNodeKey)
			}
		}
	}
}

func TestSpineFor_WindowFiltering(t *testing.T) {
	s, anchorID, base := seedAnchorWithEvents(t)
	// First 5 seconds only: should only see bash (PID 200).
	spine, err := s.SpineFor(context.Background(), anchorID, TimeWindow{
		Start: base, End: base.Add(5 * time.Second),
	})
	if err != nil {
		t.Fatalf("SpineFor: %v", err)
	}
	// source + 1 process
	if len(spine) != 2 {
		t.Fatalf("windowed spine: len=%d, want 2", len(spine))
	}
	if spine[1].PID != 200 {
		t.Errorf("windowed: expected PID 200 only, got %d", spine[1].PID)
	}
}

func TestGroupsFor_PetalsByKind(t *testing.T) {
	s, anchorID, _ := seedAnchorWithEvents(t)
	groups, err := s.GroupsFor(context.Background(), anchorID, TimeWindow{})
	if err != nil {
		t.Fatalf("GroupsFor: %v", err)
	}
	// Expected groups for PID 200 (bash):
	//   spawn x1, file_read x2, net_connect x1
	// For PID 250 (sudo): identity x1
	// For PID 260 (root bash): spawn x1, secret_access x1, file_write x1
	// For PID 270 (curl): spawn x1, net_connect x1
	wantByPidKind := map[string]int{
		"200|spawn": 1, "200|file_read": 2, "200|net_connect": 1,
		"250|identity":   1,
		"260|spawn":      1, "260|secret_access": 1, "260|file_write": 1,
		"270|spawn":      1, "270|net_connect": 1,
	}
	got := map[string]int{}
	for _, g := range groups {
		var pid uint32
		if _, err := fmt.Sscanf(g.ParentNodeKey, "p-%d", &pid); err != nil {
			t.Fatalf("bad parent key %q", g.ParentNodeKey)
		}
		got[fmt.Sprintf("%d|%s", pid, g.Kind)] = g.Count
	}
	for key, want := range wantByPidKind {
		if got[key] != want {
			t.Errorf("group %q: count=%d, want %d", key, got[key], want)
		}
	}
}

func TestGroupsFor_HighSeverityFlag(t *testing.T) {
	s, anchorID, _ := seedAnchorWithEvents(t)
	groups, _ := s.GroupsFor(context.Background(), anchorID, TimeWindow{})
	for _, g := range groups {
		// PID 260 secret_access is Critical → HighSeverity should be true.
		if g.ParentNodeKey == "p-260" && g.Kind == KindSecretAccess {
			if !g.HighSeverity {
				t.Errorf("PID 260 secret_access group should have HighSeverity=true")
			}
		}
		// PID 200 file_read is Info → HighSeverity should be false.
		if g.ParentNodeKey == "p-200" && g.Kind == KindFileRead {
			if g.HighSeverity {
				t.Errorf("PID 200 file_read group should NOT have HighSeverity")
			}
		}
	}
}

func TestGroupEvents_Pagination(t *testing.T) {
	s, anchorID, _ := seedAnchorWithEvents(t)
	// PID 200 has 2 file_read events.
	evs, err := s.GroupEvents(context.Background(), anchorID, 200, KindFileRead, TimeWindow{}, 10, 0)
	if err != nil {
		t.Fatalf("GroupEvents: %v", err)
	}
	if len(evs) != 2 {
		t.Fatalf("len=%d, want 2", len(evs))
	}
	if evs[0].TargetPath != "/home/alice/.bashrc" {
		t.Errorf("first event path=%q", evs[0].TargetPath)
	}

	// Offset 1 should skip the first.
	evs2, _ := s.GroupEvents(context.Background(), anchorID, 200, KindFileRead, TimeWindow{}, 10, 1)
	if len(evs2) != 1 || evs2[0].TargetPath != "/etc/passwd" {
		t.Errorf("offset pagination wrong: %+v", evs2)
	}
}

func TestEventCount_WithWindow(t *testing.T) {
	s, anchorID, base := seedAnchorWithEvents(t)
	all, _ := s.EventCount(context.Background(), anchorID, TimeWindow{})
	if all != 10 {
		t.Errorf("EventCount all = %d, want 10", all)
	}
	first10s, _ := s.EventCount(context.Background(), anchorID, TimeWindow{
		Start: base, End: base.Add(10 * time.Second),
	})
	// First 4 events (+0 .. +3 seconds) fall in [0,10s).
	if first10s != 4 {
		t.Errorf("EventCount first 10s = %d, want 4", first10s)
	}
}

func TestSweepEventsOlderThan(t *testing.T) {
	s, anchorID, base := seedAnchorWithEvents(t)
	cutoff := base.Add(20 * time.Second)
	removed, err := s.SweepEventsOlderThan(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("SweepEventsOlderThan: %v", err)
	}
	// Events at +0, +1s, +2s, +3s are before cutoff → 4 removed.
	if removed != 4 {
		t.Errorf("removed=%d, want 4", removed)
	}
	remain, _ := s.EventCount(context.Background(), anchorID, TimeWindow{})
	if remain != 6 {
		t.Errorf("remaining count=%d, want 6", remain)
	}
}


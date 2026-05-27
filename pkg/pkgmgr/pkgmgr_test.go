package pkgmgr

import (
	"strings"
	"testing"
	"time"
)

func TestStore_OpenIsActiveClose(t *testing.T) {
	s := New(nil)
	now := time.Now()

	if s.IsActive(now) {
		t.Fatal("empty store should not be active")
	}

	s.Open(ManagerApt, now, now.Add(10*time.Second), "apt-get install vim")
	if !s.IsActive(now.Add(time.Second)) {
		t.Error("expected active 1s after Open")
	}
	if !s.IsActive(now.Add(9 * time.Second)) {
		t.Error("expected active 9s after Open")
	}
	if s.IsActive(now.Add(20 * time.Second)) {
		t.Error("expected inactive 20s after Open (past EndsAt)")
	}

	s.Close(ManagerApt, now.Add(8*time.Second))
	// Close adds a 5s grace — so window now ends at now+13s.
	if !s.IsActive(now.Add(12 * time.Second)) {
		t.Error("expected active during grace window after Close")
	}
}

func TestStore_OpenExtendsButDoesntReset(t *testing.T) {
	s := New(nil)
	now := time.Now()
	s.Open(ManagerApt, now, now.Add(10*time.Second), "first")
	s.Open(ManagerApt, now.Add(5*time.Second), now.Add(30*time.Second), "second")
	// First Open's StartedAt should persist; EndsAt should extend.
	s.mu.RLock()
	w := s.windows[ManagerApt]
	s.mu.RUnlock()
	if !w.StartedAt.Equal(now) {
		t.Errorf("StartedAt reset on re-Open: %v want %v", w.StartedAt, now)
	}
	if !w.EndsAt.Equal(now.Add(30 * time.Second)) {
		t.Errorf("EndsAt not extended: %v want %v", w.EndsAt, now.Add(30*time.Second))
	}
}

func TestStore_MultipleManagers(t *testing.T) {
	s := New(nil)
	now := time.Now()
	s.Open(ManagerApt, now, now.Add(10*time.Second), "")
	s.Open(ManagerSnap, now.Add(time.Second), now.Add(time.Minute), "")
	if mgrs := s.ActiveManagers(now.Add(2 * time.Second)); len(mgrs) != 2 {
		t.Errorf("ActiveManagers=%d want 2", len(mgrs))
	}
	// snap window still open after apt closes.
	if mgrs := s.ActiveManagers(now.Add(15 * time.Second)); len(mgrs) != 1 || mgrs[0] != ManagerSnap {
		t.Errorf("expected only snap active; got %v", mgrs)
	}
}

func TestStore_Sweep(t *testing.T) {
	s := New(nil)
	now := time.Now()
	s.Open(ManagerApt, now.Add(-time.Hour), now.Add(-50*time.Minute), "")
	s.Open(ManagerSnap, now, now.Add(time.Minute), "")
	s.Sweep(now, 5*time.Minute) // keep last 5 min
	if s.Size() != 1 {
		t.Errorf("Sweep left %d windows want 1", s.Size())
	}
}

func TestParseAptLine_FullTransaction(t *testing.T) {
	aptState = aptLineState{} // reset
	lines := []string{
		"Start-Date: 2026-05-01  06:50:50",
		"Commandline: apt-get install -y suricata",
		"Upgrade: suricata:amd64 (1:7.0.3-1build3)",
		"End-Date: 2026-05-01  06:51:05",
	}
	var got lineEvent
	for _, l := range lines {
		ev := parseAptLine(l, time.Now())
		if ev.kind != noEvent {
			got = ev
		}
	}
	if got.kind != openClose {
		t.Fatalf("expected openClose event, got kind=%v", got.kind)
	}
	if !strings.Contains(got.command, "suricata") {
		t.Errorf("command not captured: %q", got.command)
	}
	if got.end.Sub(got.start) != 15*time.Second {
		t.Errorf("duration wrong: %v", got.end.Sub(got.start))
	}
}

func TestParseDpkgLine_Window(t *testing.T) {
	line := "2026-05-01 06:50:50 upgrade kmod:amd64 31+1 31+2"
	ev := parseDpkgLine(line, time.Now())
	if ev.kind != openOnly {
		t.Errorf("expected openOnly, got %v", ev.kind)
	}
	if ev.end.Sub(ev.start) != dpkgWindowSlide {
		t.Errorf("dpkg window wrong: %v", ev.end.Sub(ev.start))
	}
}

func TestParseDpkgLine_RejectsShortLine(t *testing.T) {
	if ev := parseDpkgLine("short", time.Now()); ev.kind != noEvent {
		t.Errorf("short line should not produce event")
	}
}

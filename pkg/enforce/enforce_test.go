package enforce

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSoakAccumulatesAndResets(t *testing.T) {
	s := NewSoak(30)
	now := time.Now()

	// First track at t=0
	s.Track("rule_x", now)
	s.Track("rule_x", now.Add(time.Hour))

	// Without an FP, after 31 days, promotable.
	ok, r := s.Promotable("rule_x", now.Add(31*24*time.Hour))
	if !ok {
		t.Errorf("expected promotable, got record %+v", r)
	}

	// Mark an FP; counter resets.
	s.MarkFP("rule_x", now.Add(31*24*time.Hour))
	ok, r = s.Promotable("rule_x", now.Add(31*24*time.Hour).Add(time.Hour))
	if ok {
		t.Errorf("expected NOT promotable after FP, got %+v", r)
	}

	// 30 more days clean; promotable again.
	ok, _ = s.Promotable("rule_x", now.Add(31*24*time.Hour).Add(31*24*time.Hour))
	if !ok {
		t.Error("expected promotable 30 days after FP")
	}
}

func TestPanicSwitchPersists(t *testing.T) {
	dir := t.TempDir()
	pin := filepath.Join(dir, "panic")

	p := NewPanicSwitch(pin)
	if p.Armed() {
		t.Error("fresh panic should not be armed")
	}
	if err := p.Arm(); err != nil {
		t.Fatal(err)
	}
	if !p.Armed() {
		t.Error("after Arm, expected armed=true")
	}

	// Restart simulation: a new switch reading the same pin file
	// should auto-detect the armed state.
	p2 := NewPanicSwitch(pin)
	if !p2.Armed() {
		t.Error("new switch should detect existing pin file")
	}

	if err := p2.Disarm(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pin); !os.IsNotExist(err) {
		t.Error("Disarm should remove pin file")
	}
}

func TestQuarantineLifecycle(t *testing.T) {
	var calls atomic.Uint64
	send := func(pid int, sig os.Signal) error {
		calls.Add(1)
		return nil
	}
	q := NewQuarantine(send)

	r, err := q.Stop(12345, "vulnsvc", "/usr/bin/vulnsvc", "mem_canary_fail")
	if err != nil {
		t.Fatal(err)
	}
	if r.State != "stopped" {
		t.Errorf("state = %q", r.State)
	}
	if r.RuleID != "mem_canary_fail" {
		t.Errorf("rule = %q", r.RuleID)
	}

	// Idempotent stop.
	_, err = q.Stop(12345, "vulnsvc", "/usr/bin/vulnsvc", "mem_canary_fail")
	if err != nil {
		t.Fatal(err)
	}

	if err := q.Resume(12345); err != nil {
		t.Fatal(err)
	}
	if err := q.Kill(12345); err != nil {
		t.Fatal(err)
	}

	// Refuse pid 1.
	if _, err := q.Stop(1, "init", "", "x"); err != errInvalidPID {
		t.Errorf("expected errInvalidPID for pid 1, got %v", err)
	}
}

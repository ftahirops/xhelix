package firerate

import (
	"testing"
	"time"
)

func TestLimiter_BelowCapPasses(t *testing.T) {
	l := NewLimiter(map[string]Policy{"r1": {MaxFires: 5, Window: time.Minute}})
	now := time.Now()
	for i := 0; i < 5; i++ {
		if !l.Allow("r1", now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("fire %d suppressed", i)
		}
	}
	if l.Allow("r1", now.Add(6*time.Second)) {
		t.Errorf("6th fire should be suppressed (cap=5)")
	}
	if l.SuppressedStats()["r1"] != 1 {
		t.Errorf("suppressed=%d want 1", l.SuppressedStats()["r1"])
	}
}

func TestLimiter_WindowSlides(t *testing.T) {
	l := NewLimiter(map[string]Policy{"r1": {MaxFires: 2, Window: 10 * time.Second}})
	now := time.Now()
	_ = l.Allow("r1", now)
	_ = l.Allow("r1", now.Add(time.Second))
	if l.Allow("r1", now.Add(2*time.Second)) {
		t.Fatal("3rd fire should be capped")
	}
	if !l.Allow("r1", now.Add(11*time.Second)) {
		t.Errorf("fire after window should pass")
	}
}

func TestLimiter_Cooldown(t *testing.T) {
	l := NewLimiter(map[string]Policy{"r1": {MaxFires: 100, Window: time.Hour, Cooldown: 5 * time.Second}})
	now := time.Now()
	_ = l.Allow("r1", now)
	if l.Allow("r1", now.Add(2*time.Second)) {
		t.Error("fire within cooldown should be suppressed")
	}
	if !l.Allow("r1", now.Add(6*time.Second)) {
		t.Error("fire after cooldown should pass")
	}
}

func TestLimiter_DefaultPolicy(t *testing.T) {
	l := NewLimiter(nil)
	now := time.Now()
	for i := 0; i < 30; i++ {
		if !l.Allow("unconfigured", now.Add(time.Duration(i)*time.Millisecond)) {
			t.Fatalf("fire %d under default cap should pass", i)
		}
	}
	if l.Allow("unconfigured", now.Add(31*time.Millisecond)) {
		t.Error("31st fire under DefaultPolicy should be suppressed")
	}
}

func TestLimiter_Nil(t *testing.T) {
	var l *Limiter
	if !l.Allow("x", time.Now()) {
		t.Error("nil limiter should be permissive")
	}
}

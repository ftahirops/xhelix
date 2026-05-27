package firerate

import (
	"sync"
	"time"
)

// Policy caps a single rule's fire rate (Phase H.3).
//
// MaxFires per Window is a sliding-window rate cap (alerts beyond it
// drop). Cooldown is a minimum gap between fires for the same rule
// (independent of rate). Either knob may be zero to disable that
// half of the check.
type Policy struct {
	MaxFires int
	Window   time.Duration
	Cooldown time.Duration
}

// DefaultPolicy applies to rules without an explicit Policy. 30
// fires per minute is generous for normal noise but catches runaway
// loops. Operators tighten per-rule via Limiter.SetPolicy.
var DefaultPolicy = Policy{MaxFires: 30, Window: time.Minute}

// Limiter enforces per-rule Policies. The Tracker type in this
// package observes rates; Limiter actively suppresses. Both can run
// against the same emit stream — Tracker reports what came in,
// Limiter decides what gets through.
type Limiter struct {
	mu            sync.Mutex
	policies      map[string]Policy
	fires         map[string][]time.Time
	suppressed    map[string]int
	cooldownUntil map[string]time.Time
}

// NewLimiter returns a Limiter with the given per-rule policies.
// nil/empty means every rule falls back to DefaultPolicy.
func NewLimiter(policies map[string]Policy) *Limiter {
	cp := map[string]Policy{}
	for k, v := range policies {
		cp[k] = v
	}
	return &Limiter{
		policies:      cp,
		fires:         map[string][]time.Time{},
		suppressed:    map[string]int{},
		cooldownUntil: map[string]time.Time{},
	}
}

// Allow reports whether a fire for ruleID at time `now` may proceed.
// On false the limiter has already counted the suppression.
func (l *Limiter) Allow(ruleID string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	pol := l.policyFor(ruleID)

	if pol.Cooldown > 0 {
		if dl, ok := l.cooldownUntil[ruleID]; ok && now.Before(dl) {
			l.suppressed[ruleID]++
			return false
		}
	}

	if pol.MaxFires > 0 && pol.Window > 0 {
		cutoff := now.Add(-pol.Window)
		fires := l.fires[ruleID]
		i := 0
		for i < len(fires) && fires[i].Before(cutoff) {
			i++
		}
		if i > 0 {
			fires = fires[i:]
		}
		if len(fires) >= pol.MaxFires {
			l.fires[ruleID] = fires
			l.suppressed[ruleID]++
			return false
		}
		l.fires[ruleID] = append(fires, now)
	}

	if pol.Cooldown > 0 {
		l.cooldownUntil[ruleID] = now.Add(pol.Cooldown)
	}
	return true
}

func (l *Limiter) policyFor(ruleID string) Policy {
	if p, ok := l.policies[ruleID]; ok {
		return p
	}
	return DefaultPolicy
}

// SetPolicy installs or replaces a per-rule policy at runtime.
func (l *Limiter) SetPolicy(ruleID string, p Policy) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.policies[ruleID] = p
}

// SuppressedStats returns a copy of per-rule suppression counts.
func (l *Limiter) SuppressedStats() map[string]int {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]int, len(l.suppressed))
	for k, v := range l.suppressed {
		out[k] = v
	}
	return out
}

// ResetLimiter clears all per-rule state. Intended for tests.
func (l *Limiter) ResetLimiter() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fires = map[string][]time.Time{}
	l.suppressed = map[string]int{}
	l.cooldownUntil = map[string]time.Time{}
}

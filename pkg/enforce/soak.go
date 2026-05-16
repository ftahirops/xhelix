// Package enforce implements xhelix's selective-enforcement plane.
//
// Phase 7 ships:
//
//   - Soak: per-rule consecutive-clean-day counter + auto-promotion
//     gate. A rule cannot move from detect to quarantine without 30
//     days of zero false positives.
//   - Quarantine: SIGSTOP a target pid with a forensic snapshot.
//   - Kill switch: a pinned BPF map flag plus an in-process bool that
//     short-circuits every action.
//   - Dry-run: simulate `block` mode for N days; log "would-block"
//     events and produce a promotion recommendation.
//
// LSM-side block actions live in the eBPF C source. This package is
// the userspace control plane.
package enforce

import (
	"sync"
	"time"
)

// Soak tracks per-rule false-positive history.
type Soak struct {
	MinCleanDays uint   // default 30

	mu      sync.RWMutex
	records map[string]*Record
}

// Record is one rule's enforcement-readiness snapshot.
type Record struct {
	RuleID               string
	EnteredDetectAt      time.Time
	FireCount            uint64
	FPCount              uint64
	LastFP               time.Time
	ZeroFPSince          time.Time
	ConsecutiveCleanDays uint
}

// NewSoak returns an initialised tracker.
func NewSoak(minCleanDays uint) *Soak {
	if minCleanDays == 0 {
		minCleanDays = 30
	}
	return &Soak{
		MinCleanDays: minCleanDays,
		records:      map[string]*Record{},
	}
}

// Track marks rule as observed at t. It increments FireCount and
// updates ConsecutiveCleanDays.
func (s *Soak) Track(ruleID string, t time.Time) *Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.records[ruleID]
	if r == nil {
		r = &Record{
			RuleID:          ruleID,
			EnteredDetectAt: t,
			ZeroFPSince:     t,
		}
		s.records[ruleID] = r
	}
	r.FireCount++
	if !r.LastFP.IsZero() {
		r.ConsecutiveCleanDays = uint(t.Sub(r.LastFP).Hours() / 24)
	} else {
		r.ConsecutiveCleanDays = uint(t.Sub(r.ZeroFPSince).Hours() / 24)
	}
	return r
}

// MarkFP records a false positive, resetting the consecutive-clean
// counter for the rule.
func (s *Soak) MarkFP(ruleID string, t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.records[ruleID]
	if r == nil {
		r = &Record{RuleID: ruleID, EnteredDetectAt: t}
		s.records[ruleID] = r
	}
	r.FPCount++
	r.LastFP = t
	r.ConsecutiveCleanDays = 0
	r.ZeroFPSince = t
}

// Promotable reports whether rule has accumulated MinCleanDays of
// zero-FP runtime and can be safely promoted from detect to
// quarantine.
//
// Returns the record so callers can show "30 days clean since X" in
// the TUI.
func (s *Soak) Promotable(ruleID string, now time.Time) (bool, *Record) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.records[ruleID]
	if r == nil {
		return false, nil
	}
	cp := *r
	if !cp.LastFP.IsZero() {
		cp.ConsecutiveCleanDays = uint(now.Sub(cp.LastFP).Hours() / 24)
	} else {
		cp.ConsecutiveCleanDays = uint(now.Sub(cp.ZeroFPSince).Hours() / 24)
	}
	return cp.ConsecutiveCleanDays >= s.MinCleanDays, &cp
}

// Snapshot returns a copy of every record. Useful for the TUI.
func (s *Soak) Snapshot() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, *r)
	}
	return out
}

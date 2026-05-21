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
	"encoding/json"
	"os"
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
	// Class is the rule's detection-class
	// (LOW_FALSE_POSITIVE_ARCHITECTURE_2026-05-21.md §3):
	//   1 = hard invariant (FP target <0.1%)
	//   2 = strong exploit signal (FP target <0.5%)
	//   3 = soft drift (FP target <5%)
	// Set on first Track; never overwritten by zero so rules
	// loaded before class_map.yaml don't lose their class.
	Class int
}

// ClassStats is the aggregate FP-rate breakout the
// low-FP architecture doc requires for operators to measure
// adherence to the per-class targets.
type ClassStats struct {
	Class       int
	Rules       int     // distinct rules with at least one fire
	TotalFires  uint64  // sum of FireCount across rules in this class
	TotalFPs    uint64  // sum of FPCount
	FPRate      float64 // TotalFPs / TotalFires (0 when TotalFires=0)
	Target      float64 // architectural target (0.001 / 0.005 / 0.05)
	WithinTarget bool   // FPRate <= Target
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
// updates ConsecutiveCleanDays. class is the rule's detection-class
// (1/2/3); zero is treated as "leave existing class unchanged".
func (s *Soak) Track(ruleID string, t time.Time, class int) *Record {
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
	if class > 0 {
		r.Class = class
	}
	r.FireCount++
	if !r.LastFP.IsZero() {
		r.ConsecutiveCleanDays = uint(t.Sub(r.LastFP).Hours() / 24)
	} else {
		r.ConsecutiveCleanDays = uint(t.Sub(r.ZeroFPSince).Hours() / 24)
	}
	return r
}

// ClassBreakdown returns per-class aggregate FP statistics for the
// LOW_FALSE_POSITIVE architecture's per-class metric model.
// Targets are pinned to the architectural document:
//   Class 1: 0.1%   Class 2: 0.5%   Class 3: 5%
func (s *Soak) ClassBreakdown() []ClassStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agg := map[int]*ClassStats{
		1: {Class: 1, Target: 0.001},
		2: {Class: 2, Target: 0.005},
		3: {Class: 3, Target: 0.05},
	}
	for _, r := range s.records {
		c := r.Class
		if c < 1 || c > 3 {
			c = 3
		}
		a := agg[c]
		a.Rules++
		a.TotalFires += r.FireCount
		a.TotalFPs += r.FPCount
	}
	out := make([]ClassStats, 0, 3)
	for _, c := range []int{1, 2, 3} {
		a := agg[c]
		if a.TotalFires > 0 {
			a.FPRate = float64(a.TotalFPs) / float64(a.TotalFires)
		}
		a.WithinTarget = a.FPRate <= a.Target
		out = append(out, *a)
	}
	return out
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

// Reclassify rewrites the Class field on every persisted Record
// using the supplied lookup function. Called at daemon startup
// after LoadFrom so records persisted before class_map.yaml was
// authoritative get correctly bucketed for the per-class metric.
//
// classOf returns the rule's class (1/2/3); 0 means "unknown,
// leave existing record's class unchanged".
func (s *Soak) Reclassify(classOf func(ruleID string) int) {
	if s == nil || classOf == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.records {
		if c := classOf(id); c > 0 {
			r.Class = c
		}
	}
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

// SaveTo persists the soak history to path as JSON. Atomic via
// temp + rename so a crashed write doesn't corrupt the file.
// Operator's view of "this rule has been clean for N days" must
// survive daemon restart.
func (s *Soak) SaveTo(path string) error {
	s.mu.RLock()
	snap := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		snap = append(snap, *r)
	}
	s.mu.RUnlock()
	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadFrom rehydrates the soak history from path. Missing file
// is not an error — fresh install starts with an empty tracker.
func (s *Soak) LoadFrom(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var snap []Record
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range snap {
		rr := r
		s.records[r.RuleID] = &rr
	}
	return nil
}

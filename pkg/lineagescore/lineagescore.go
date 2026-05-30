// Package lineagescore accumulates per-process-lineage evidence and emits
// a single incident Verdict when a lineage crosses a score threshold.
// Deterministic and single-goroutine by contract (called from the
// dispatch loop). No fleet, no ML — local chain scoring only.
//
// NOTE: distinct from pkg/verdict, which is the egress per-connection
// decision engine. This package scores process lineages for incident
// alerting.
package lineagescore

import (
	"sort"
	"sync"
	"time"
)

// Signal is one piece of evidence for a process.
type Signal struct {
	PID    uint32
	RuleID string
	Weight int
	At     time.Time
	Reason string
}

// Contributor records one signal that fed a verdict.
type Contributor struct {
	RuleID string
	Weight int
	At     time.Time
	Reason string
}

// Verdict is emitted when a lineage crosses the threshold.
type Verdict struct {
	LineageRoot  uint32
	Score        int
	Tier         string
	Contributors []Contributor
	At           time.Time
}

// Opts configures the engine.
type Opts struct {
	Threshold int
	Window    time.Duration
	Cooldown  time.Duration
	LineageOf func(pid uint32) uint32
}

type entry struct {
	rid    string
	weight int
	at     time.Time
	reason string
}

type lineageState struct {
	entries   []entry
	firedAt   time.Time
	firedTier string
	hasFired  bool
}

// tierRank orders tiers for escalation comparison.
func tierRank(t string) int {
	switch t {
	case "watch":
		return 1
	case "high":
		return 2
	case "critical":
		return 3
	}
	return 0
}

func tierHigher(a, b string) bool { return tierRank(a) > tierRank(b) }

// Engine is the per-lineage score accumulator.
//
// The bus router calls Observe from multiple goroutines (alert.Bus.Send
// is multi-goroutine), so Observe and Reset take mu. The scoring logic
// itself remains deterministic given a fixed signal order.
type Engine struct {
	mu     sync.Mutex
	opts   Opts
	states map[uint32]*lineageState
}

// New constructs an Engine with safe defaults.
func New(o Opts) *Engine {
	if o.Threshold <= 0 {
		o.Threshold = 80
	}
	if o.Window <= 0 {
		o.Window = time.Hour
	}
	if o.Cooldown <= 0 {
		o.Cooldown = o.Window
	}
	if o.LineageOf == nil {
		o.LineageOf = func(p uint32) uint32 { return p }
	}
	return &Engine{opts: o, states: map[uint32]*lineageState{}}
}

// Observe records a signal and returns a non-nil Verdict if this signal
// caused the lineage to cross the threshold (once per cooldown window).
// Zero/negative-weight signals (facts) are ignored.
func (e *Engine) Observe(s Signal) *Verdict {
	if s.Weight <= 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	root := e.opts.LineageOf(s.PID)
	st := e.states[root]
	if st == nil {
		st = &lineageState{}
		e.states[root] = st
	}
	cutoff := s.At.Add(-e.opts.Window)
	kept := st.entries[:0]
	for _, en := range st.entries {
		if en.at.After(cutoff) {
			kept = append(kept, en)
		}
	}
	st.entries = append(kept, entry{rid: s.RuleID, weight: s.Weight, at: s.At, reason: s.Reason})

	score := 0
	for _, en := range st.entries {
		score += en.weight
	}
	if score < e.opts.Threshold {
		return nil
	}

	// Suppress within the cooldown window only when the tier has NOT
	// risen above the last fired tier. A tier escalation (e.g.
	// high->critical) re-emits even within cooldown so incident response
	// sees the worse verdict instead of the first crossing masking it.
	newTier := Tier(score)
	if st.hasFired && s.At.Sub(st.firedAt) < e.opts.Cooldown && !tierHigher(newTier, st.firedTier) {
		return nil
	}

	contribs := make([]Contributor, 0, len(st.entries))
	for _, en := range st.entries {
		contribs = append(contribs, Contributor{RuleID: en.rid, Weight: en.weight, At: en.at, Reason: en.reason})
	}
	sort.SliceStable(contribs, func(i, j int) bool { return contribs[i].At.Before(contribs[j].At) })
	st.hasFired = true
	st.firedAt = s.At
	st.firedTier = newTier
	return &Verdict{LineageRoot: root, Score: score, Tier: newTier, Contributors: contribs, At: s.At}
}

// Reset clears all state.
func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.states = map[uint32]*lineageState{}
}

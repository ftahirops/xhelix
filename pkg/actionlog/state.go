// Package actionlog implements the ContainmentState machine. Every
// lineage tracked by xhelix lives in exactly one of a small set of
// states (observed → triaged → suspended → isolated → contained →
// remediated → released → terminated). State changes are recorded as
// Transitions — each carries the ActionPlan that caused it, the
// operator (if any) who authorized it, and a reason string.
//
// See REFACTOR_ROADMAP.md §2.3 for the type contract and §6 rule #5
// (transitions go through pkg/actionlog with reason + plan_id +
// operator_id) for the design motivation.
//
// Thread-safe. In-memory only; persistence (per evidence chain) is a
// follow-on in P-RF.9.
package actionlog

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ContainmentState is the per-lineage state.
type ContainmentState string

const (
	// Observed — default state for any lineage we've seen.
	StateObserved ContainmentState = "observed"
	// Triaged — soft enforce in effect (delay + step-up).
	StateTriaged ContainmentState = "triaged"
	// Suspended — Layer 2: SIGSTOP + snapshot + jail.
	StateSuspended ContainmentState = "suspended"
	// Isolated — Layer 4: capability strip + memscan + local lockout.
	StateIsolated ContainmentState = "isolated"
	// Contained — Layer 5: host isolation.
	StateContained ContainmentState = "contained"
	// Remediated — file-level restore completed.
	StateRemediated ContainmentState = "remediated"
	// Released — operator cleared the alert; lineage back to observed.
	StateReleased ContainmentState = "released"
	// Terminated — process tree SIGKILL'd; lineage is dead.
	StateTerminated ContainmentState = "terminated"
)

// AllStates returns every defined state. Used in tests and to walk
// state-transition tables for validation.
func AllStates() []ContainmentState {
	return []ContainmentState{
		StateObserved, StateTriaged, StateSuspended, StateIsolated,
		StateContained, StateRemediated, StateReleased, StateTerminated,
	}
}

// validTransitions enumerates allowed state changes. The map is
// keyed by source state; each value is the set of allowed
// destinations.
//
// Rules baked into the table:
//   - Any state can transition to itself (refresh) — handled in Validate.
//   - StateTerminated is absorbing — no outbound transitions.
//   - StateReleased can only go back to Observed (next event recreates flow).
//   - Escalation may skip levels (observed → contained for L1-tier crown-jewel).
//   - De-escalation: any state → released or remediated; remediated → released.
var validTransitions = map[ContainmentState]map[ContainmentState]bool{
	StateObserved: {
		StateTriaged: true, StateSuspended: true, StateIsolated: true,
		StateContained: true, StateTerminated: true,
	},
	StateTriaged: {
		StateObserved: true, StateSuspended: true, StateIsolated: true,
		StateContained: true, StateReleased: true, StateTerminated: true,
	},
	StateSuspended: {
		StateIsolated: true, StateContained: true,
		StateRemediated: true, StateReleased: true, StateTerminated: true,
	},
	StateIsolated: {
		StateContained: true, StateRemediated: true,
		StateReleased: true, StateTerminated: true,
	},
	StateContained: {
		StateRemediated: true, StateReleased: true, StateTerminated: true,
	},
	StateRemediated: {
		StateReleased: true, StateTerminated: true,
	},
	StateReleased: {
		StateObserved: true,
	},
	StateTerminated: {}, // absorbing
}

// CanTransition reports whether moving from→to is structurally valid.
// Self-transitions (from == to) are treated as refresh and allowed.
func CanTransition(from, to ContainmentState) bool {
	if from == to {
		return true
	}
	allowed, ok := validTransitions[from]
	if !ok {
		return false
	}
	return allowed[to]
}

// Transition is one entry in the lineage's history. Each transition
// MUST carry a reason and either a PlanID (machine-driven) or
// OperatorID (operator-driven).
type Transition struct {
	LineageID  uint64           `json:"lineage_id"`
	From       ContainmentState `json:"from"`
	To         ContainmentState `json:"to"`
	At         time.Time        `json:"at"`
	Reason     string           `json:"reason"`
	PlanID     string           `json:"plan_id,omitempty"`
	OperatorID string           `json:"operator_id,omitempty"`
}

// Validate enforces the structural invariants for one transition.
func (t Transition) Validate() error {
	if t.LineageID == 0 {
		return errors.New("actionlog: LineageID required")
	}
	if !CanTransition(t.From, t.To) {
		return fmt.Errorf("actionlog: %q → %q is not a legal transition", t.From, t.To)
	}
	if t.Reason == "" {
		return errors.New("actionlog: Reason required")
	}
	if t.PlanID == "" && t.OperatorID == "" {
		return errors.New("actionlog: either PlanID or OperatorID required")
	}
	return nil
}

// Log is the thread-safe per-host store of ContainmentStates and
// history. One Log per daemon; queried by the planner (to compose
// new plans based on current state) and by the LocalAPI (operator
// dashboards).
type Log struct {
	mu      sync.RWMutex
	state   map[uint64]ContainmentState
	history map[uint64][]Transition
}

// New returns an empty Log.
func New() *Log {
	return &Log{
		state:   map[uint64]ContainmentState{},
		history: map[uint64][]Transition{},
	}
}

// State returns the current state for a lineage. Returns
// StateObserved if the lineage has never been recorded.
func (l *Log) State(lineageID uint64) ContainmentState {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if s, ok := l.state[lineageID]; ok {
		return s
	}
	return StateObserved
}

// Record commits a transition. Returns ErrInvalidTransition if the
// transition is not legal OR if structural fields are missing.
//
// The transition's From field is automatically set from the current
// state in the log (callers may leave it zero).
func (l *Log) Record(t Transition) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	current, exists := l.state[t.LineageID]
	if !exists {
		current = StateObserved
	}
	if t.From == "" {
		t.From = current
	} else if t.From != current {
		return fmt.Errorf("actionlog: From=%q but current state is %q", t.From, current)
	}
	if t.At.IsZero() {
		t.At = time.Now().UTC()
	}
	if err := t.Validate(); err != nil {
		return err
	}

	l.state[t.LineageID] = t.To
	l.history[t.LineageID] = append(l.history[t.LineageID], t)
	return nil
}

// History returns a copy of the transitions for a lineage,
// chronologically ascending. Nil if no history.
func (l *Log) History(lineageID uint64) []Transition {
	l.mu.RLock()
	defer l.mu.RUnlock()
	src := l.history[lineageID]
	if src == nil {
		return nil
	}
	out := make([]Transition, len(src))
	copy(out, src)
	return out
}

// Snapshot returns a copy of every lineage's current state. The
// returned slice is sorted by LineageID for determinism.
func (l *Log) Snapshot() []LineageStateEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]LineageStateEntry, 0, len(l.state))
	for id, s := range l.state {
		out = append(out, LineageStateEntry{LineageID: id, State: s})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LineageID < out[j].LineageID })
	return out
}

// LineageStateEntry is one row in a Log snapshot.
type LineageStateEntry struct {
	LineageID uint64           `json:"lineage_id"`
	State     ContainmentState `json:"state"`
}

// CountByState returns how many lineages are in each state.
// Useful for operator dashboards and metrics.
func (l *Log) CountByState() map[ContainmentState]int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := map[ContainmentState]int{}
	for _, s := range l.state {
		out[s]++
	}
	return out
}

// LineagesInState returns the lineage IDs currently in the given
// state, sorted ascending.
func (l *Log) LineagesInState(s ContainmentState) []uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out []uint64
	for id, cur := range l.state {
		if cur == s {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

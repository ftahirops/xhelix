// Package correlator implements xhelix's complex-event-processing
// engine.
//
// A correlation rule is a sequence or threshold pattern over events,
// keyed by a small set of group fields. The engine is single-
// goroutine and deterministic so replayed event streams reproduce
// identical incidents.
package correlator

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/xhelix/xhelix/pkg/model"
)

// IncidentFn is invoked when a correlation completes.
type IncidentFn func(model.Alert)

// Engine evaluates a set of correlation rules against an event stream.
type Engine struct {
	mu       sync.RWMutex
	rules    []*compiledRule
	sessions map[sessionKey]*Session
	emit     IncidentFn
	env      *cel.Env
}

type sessionKey struct {
	rule  string
	group string
}

// Session is one in-flight correlation match.
type Session struct {
	Rule      *compiledRule
	GroupKey  map[string]string
	StepIndex int
	StartedAt time.Time
	LastFired time.Time
	Events    []model.Event
}

// New creates an Engine with the given incident emitter.
func New(emit IncidentFn) (*Engine, error) {
	env, err := buildEnv()
	if err != nil {
		return nil, err
	}
	return &Engine{
		sessions: map[sessionKey]*Session{},
		emit:     emit,
		env:      env,
	}, nil
}

// Load replaces the active correlation ruleset.
func (e *Engine) Load(rules []Rule) error {
	out := make([]*compiledRule, 0, len(rules))
	for i := range rules {
		c, err := e.compile(&rules[i])
		if err != nil {
			return fmt.Errorf("rule %q: %w", rules[i].ID, err)
		}
		out = append(out, c)
	}
	e.mu.Lock()
	e.rules = out
	e.mu.Unlock()
	return nil
}

// Ingest evaluates ev against every rule. Sessions advance, complete,
// or expire as appropriate.
func (e *Engine) Ingest(ctx context.Context, ev model.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := ev.Time
	if now.IsZero() {
		now = time.Now()
	}

	for _, c := range e.rules {
		// Try to advance every existing session for this rule.
		e.advanceSessions(c, ev, now)
		// Try to open a new session if the event matches step 0.
		e.tryOpen(c, ev, now)
	}
	e.expire(now)
}

// SessionCount returns the live session total.
func (e *Engine) SessionCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.sessions)
}

func (e *Engine) advanceSessions(c *compiledRule, ev model.Event, now time.Time) {
	for k, s := range e.sessions {
		if k.rule != c.Rule.ID {
			continue
		}
		if s.StepIndex >= len(c.Compiled) {
			continue
		}
		step := c.Compiled[s.StepIndex]
		if step == nil {
			continue
		}
		// Check the step's match expression with the session's group
		// already bound.
		match, _, err := step.Eval(buildVars(ev, s.GroupKey))
		if err != nil || !asBool(match) {
			continue
		}
		// Within the step's window?
		if c.Rule.Steps[s.StepIndex].Within > 0 {
			if now.Sub(s.LastFired) > c.Rule.Steps[s.StepIndex].Within {
				delete(e.sessions, k)
				continue
			}
		}
		s.Events = append(s.Events, ev)
		s.LastFired = now
		s.StepIndex++
		if s.StepIndex >= len(c.Rule.Steps) {
			e.fire(c, s, now)
			delete(e.sessions, k)
		}
	}
}

func (e *Engine) tryOpen(c *compiledRule, ev model.Event, now time.Time) {
	if len(c.Compiled) == 0 || c.Compiled[0] == nil {
		return
	}
	// Step 0 evaluates without a bound group; the group is whatever
	// keys we extract from this event for the rule's GroupBy spec.
	groupKey := extractGroup(ev, c.Rule.GroupBy)
	out, _, err := c.Compiled[0].Eval(buildVars(ev, groupKey))
	if err != nil || !asBool(out) {
		return
	}
	gKey := groupKeyString(groupKey)
	k := sessionKey{rule: c.Rule.ID, group: gKey}

	if existing, ok := e.sessions[k]; ok {
		// Step 0 is a counted threshold — bump the count instead of
		// re-creating the session. v0.2 implements simple sequence
		// rules; threshold rules layer in next.
		existing.Events = append(existing.Events, ev)
		existing.LastFired = now
		return
	}
	s := &Session{
		Rule:      c,
		GroupKey:  groupKey,
		StepIndex: 1,
		StartedAt: now,
		LastFired: now,
		Events:    []model.Event{ev},
	}
	if len(c.Rule.Steps) == 1 {
		// Single-step rule fires immediately.
		e.fire(c, s, now)
		return
	}
	e.sessions[k] = s
}

func (e *Engine) fire(c *compiledRule, s *Session, now time.Time) {
	if e.emit == nil {
		return
	}
	last := s.Events[len(s.Events)-1]
	alert := model.Alert{
		Event:  last,
		RuleID: c.Rule.ID,
		Reason: c.Rule.Desc,
		Mode:   model.ModeDetect,
	}
	for _, ev := range s.Events {
		alert.EvidenceIDs = append(alert.EvidenceIDs, ev.ID)
	}
	alert.Event.Severity = c.Rule.Severity
	e.emit(alert)
}

func (e *Engine) expire(now time.Time) {
	for k, s := range e.sessions {
		if s.Rule == nil || s.Rule.Rule == nil {
			delete(e.sessions, k)
			continue
		}
		if s.Rule.Rule.Window > 0 && now.Sub(s.StartedAt) > s.Rule.Rule.Window {
			delete(e.sessions, k)
		}
	}
}

func extractGroup(ev model.Event, fields []string) map[string]string {
	out := make(map[string]string, len(fields))
	for _, f := range fields {
		out[f] = ev.Tags[f]
	}
	return out
}

func groupKeyString(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var s string
	for _, k := range keys {
		s += k + "=" + m[k] + ";"
	}
	return s
}

func asBool(v ref.Val) bool {
	if v == nil {
		return false
	}
	b, ok := v.(types.Bool)
	if !ok {
		return false
	}
	return bool(b)
}

func buildVars(ev model.Event, group map[string]string) map[string]any {
	tags := map[string]string{}
	for k, v := range ev.Tags {
		tags[k] = v
	}
	return map[string]any{
		"event": map[string]any{
			"sensor":   ev.Sensor,
			"severity": ev.Severity.String(),
			"host":     ev.Host,
			"pid":      int64(ev.PID),
			"comm":     ev.Comm,
			"image":    ev.Image,
			"tags":     tags,
		},
		"group": group,
	}
}

// errStub is unused but reserved so the linter recognises the err
// variable name across the package.
var errStub = errors.New("correlator stub")

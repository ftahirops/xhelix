// Package rules implements xhelix's CEL-based rule engine.
//
// A rule is a YAML document with a CEL expression in its match field.
// The engine compiles every rule once at load and evaluates it
// against incoming model.Event values. Matches produce model.Alert
// values that the bus fans out to sinks.
//
// Phase 0 stubbed this package. Phase 1 wires it in for the
// kernel-eBPF sensor plane.
package rules

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/xhelix/xhelix/pkg/model"
)

// TreeFunc returns the process ancestry for a pid. Nil is allowed.
type TreeFunc func(pid uint32, depth int) []model.ProcNode

// Engine compiles and evaluates rules against events.
//
// The engine is concurrent-safe for Eval; rule reload is gated by an
// internal write-lock. Sensors call Eval on every event; the engine
// emits alerts via the supplied EmitFunc callback.
type Engine struct {
	mu       sync.RWMutex
	env      *cel.Env
	compiled []compiledRule
	limiter  *Limiter
	emit     EmitFunc
	treeFn   TreeFunc
}

// EmitFunc is invoked when a rule fires.
type EmitFunc func(model.Alert)

type compiledRule struct {
	rule    *model.Rule
	program cel.Program
}

// NewEngine builds a fresh Engine seeded with rules. emit is invoked
// for every match (after rate limiting).
func NewEngine(emit EmitFunc) (*Engine, error) {
	env, err := buildEnv()
	if err != nil {
		return nil, fmt.Errorf("build CEL env: %w", err)
	}
	return &Engine{
		env:     env,
		limiter: NewLimiter(),
		emit:    emit,
	}, nil
}

// SetTreeFunc wires a live process-tree provider for ancestry rules.
func (e *Engine) SetTreeFn(fn TreeFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.treeFn = fn
}

// Load parses and compiles the rule set, replacing the previous one.
//
// Compilation is all-or-nothing: if any rule fails to compile, the
// previous rule set remains active and the error is returned.
func (e *Engine) Load(rules []model.Rule) error {
	out := make([]compiledRule, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		ast, iss := e.env.Compile(r.Match)
		if iss != nil && iss.Err() != nil {
			return fmt.Errorf("rule %q: %w", r.ID, iss.Err())
		}
		prg, err := e.env.Program(ast,
			cel.EvalOptions(cel.OptOptimize),
		)
		if err != nil {
			return fmt.Errorf("rule %q program: %w", r.ID, err)
		}
		out = append(out, compiledRule{rule: r, program: prg})
	}
	e.mu.Lock()
	e.compiled = out
	e.mu.Unlock()
	return nil
}

// Eval runs every rule against ev and fires the EmitFunc for each
// rule whose match expression returns true (modulo rate limiting).
//
// Eval never returns an error: per-rule evaluation failures are
// counted but do not stop other rules. Errors are silently swallowed
// to keep the hot path small; debug-level logging is the next layer.
func (e *Engine) Eval(ctx context.Context, ev model.Event) {
	e.mu.RLock()
	rules := e.compiled
	treeFn := e.treeFn
	e.mu.RUnlock()

	if len(rules) == 0 {
		return
	}
	vars := buildVars(ev, treeFn)
	for _, c := range rules {
		out, _, err := c.program.Eval(vars)
		if err != nil {
			continue
		}
		b, ok := out.(types.Bool)
		if !ok || !bool(b) {
			continue
		}
		if e.limiter.Drop(c.rule, ev) {
			continue
		}
		e.emit(model.Alert{
			Event:  ev,
			RuleID: c.rule.ID,
			Reason: c.rule.Desc,
			Mode:   c.rule.Mode,
			Class:  c.rule.NormalizeClass(),
		})
	}
}

// Count returns how many rules are currently loaded.
func (e *Engine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.compiled)
}

// buildVars projects an Event into the variable map CEL expects.
//
// For Phase 1 we expose: event, parent (zero-valued when no
// ancestry is known), tree (slice of ProcNode), and convenience
// shortcut fields like path. Phase 5+ adds peer, baseline,
// threat_intel, etc.
func buildVars(ev model.Event, treeFn TreeFunc) map[string]any {
	tree := ev.ProcTree
	if len(tree) == 0 && treeFn != nil {
		tree = treeFn(ev.PID, 0)
	}
	parent := model.ProcNode{}
	if len(tree) >= 2 {
		parent = tree[1]
	}
	var path string
	if ev.Tags != nil {
		path = ev.Tags["path"]
	}
	return map[string]any{
		"event":  eventMap(ev),
		"parent": procNodeMap(parent),
		"tree":   procTreeList(tree),
		"path":   path,
		"host":   ev.Host,
	}
}

func eventMap(ev model.Event) map[string]any {
	tags := ev.Tags
	if tags == nil {
		tags = map[string]string{}
	}
	tagsRef := make(map[string]string, len(tags))
	for k, v := range tags {
		tagsRef[k] = v
	}
	return map[string]any{
		"id":         ev.ID.String(),
		"sensor":     ev.Sensor,
		"severity":   ev.Severity.String(),
		"verdict":    ev.Verdict.String(),
		"host":       ev.Host,
		"pid":        int64(ev.PID),
		"tid":        int64(ev.TID),
		"comm":       ev.Comm,
		"uid":        int64(ev.UID),
		"gid":        int64(ev.GID),
		"cgroup_id":  int64(ev.CGroupID),
		"container":  ev.Container,
		"image":      ev.Image,
		"parent_pid": int64(ev.ParentPID),
		"rule":       ev.Rule,
		"tags":       tagsRef,
	}
}

func procNodeMap(n model.ProcNode) map[string]any {
	return map[string]any{
		"pid":   int64(n.PID),
		"comm":  n.Comm,
		"uid":   int64(n.UID),
		"image": n.Image,
		"argv":  n.Argv,
	}
}

func procTreeList(tree []model.ProcNode) []ref.Val {
	out := make([]ref.Val, len(tree))
	reg := types.NewEmptyRegistry()
	for i := range tree {
		out[i] = types.NewDynamicMap(reg, procNodeMap(tree[i]))
	}
	return out
}

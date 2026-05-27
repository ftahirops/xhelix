// Package containment is the T11/T12 staged-response ladder.
//
// Existing primitives (pkg/enforce.Quarantine, pkg/netban.Banner,
// pkg/enforce.PanicSwitch) are individually wired into the alert
// pipeline for narrowly-scoped triggers. This package adds a single
// graduated ladder that maps an endpoint-level risk verdict
// (typically from pkg/endpointscore) to one of nine progressively
// stronger response actions.
//
// The ladder:
//
//	1 observe         no action; verdict logged
//	2 alert           model.Alert pushed to bus (already happening)
//	3 throttle        rate-cap the offending source's egress
//	4 block_net       kernel-level deny of source IPs / dst CIDRs
//	5 kill_proc       SIGKILL the offending process
//	6 quarantine_file move the dropped binary to /var/lib/xhelix/quarantine
//	7 quarantine_dir  freeze a directory tree (chmod 000 + bind-ro)
//	8 host_isolate    block all outbound except management plane
//	9 panic_switch    arm operator-driven kill of the whole host
//
// Steps 1-2 are always safe and ALWAYS enabled. Steps 3-9 require
// explicit per-step opt-in via the operator overlay
// (/etc/xhelix/containment.yaml). The default mode is observe —
// no action will fire on a fresh install without operator intent,
// matching the "soak before enforce" project rule.
//
// Honest non-promise: the ladder OWNS the decision of WHICH step
// to invoke, not whether the underlying primitive is safe to call
// in your environment. Calibrate severities and step caps on a
// canary before flipping any enforce-tier step on in production.
package containment

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Step is one rung of the ladder. Higher = stronger.
type Step int

const (
	StepObserve        Step = 1
	StepAlert          Step = 2
	StepThrottle       Step = 3
	StepBlockNet       Step = 4
	StepKillProc       Step = 5
	StepQuarantineFile Step = 6
	StepQuarantineDir  Step = 7
	StepHostIsolate    Step = 8
	StepPanicSwitch    Step = 9
)

// String returns the canonical step token.
func (s Step) String() string {
	switch s {
	case StepObserve:
		return "observe"
	case StepAlert:
		return "alert"
	case StepThrottle:
		return "throttle"
	case StepBlockNet:
		return "block_net"
	case StepKillProc:
		return "kill_proc"
	case StepQuarantineFile:
		return "quarantine_file"
	case StepQuarantineDir:
		return "quarantine_dir"
	case StepHostIsolate:
		return "host_isolate"
	case StepPanicSwitch:
		return "panic_switch"
	}
	return fmt.Sprintf("step_%d", int(s))
}

// ParseStep accepts the canonical tokens above (case-insensitive).
// Unknown → StepObserve, false.
func ParseStep(s string) (Step, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "observe":
		return StepObserve, true
	case "alert":
		return StepAlert, true
	case "throttle":
		return StepThrottle, true
	case "block_net", "blocknet":
		return StepBlockNet, true
	case "kill_proc", "killproc":
		return StepKillProc, true
	case "quarantine_file":
		return StepQuarantineFile, true
	case "quarantine_dir":
		return StepQuarantineDir, true
	case "host_isolate":
		return StepHostIsolate, true
	case "panic_switch":
		return StepPanicSwitch, true
	}
	return StepObserve, false
}

// Verdict is what the ladder sees on its input.
type Verdict struct {
	// Score is 0-100 (typically endpointscore.EndpointScore.Score).
	Score int
	// Chain is the named chain that produced the score (e.g.
	// "ransomware", "c2_lateral"). Used for audit, not decision.
	Chain string
	// SourceID is the per-source anchor (string) the breach is
	// attributed to. Required for targeted steps (3-7); steps 8-9
	// don't need it.
	SourceID string
	// PID is the offending process id when available; required for
	// StepKillProc. 0 = unknown.
	PID uint32
	// Image is the binary path used by StepQuarantineFile.
	Image string
	// DstIPs is the set of destination addresses used by StepBlockNet
	// to push kernel-level denies.
	DstIPs []string
	// At is the verdict timestamp. Defaults to time.Now() if zero.
	At time.Time
}

// Policy maps score bands → max permitted step. The ladder will
// never invoke a step higher than the matching band, even if a
// caller requests it. This is the "operator floor / ceiling" that
// makes hot-tuning safe: tightening a band immediately caps every
// in-flight decision.
type Policy struct {
	// MinAlert is the score at/above which StepAlert is invoked
	// (StepObserve below). Default 1.
	MinAlert int
	// MinThrottle, MinBlockNet, MinKillProc, MinQuarantineFile,
	// MinQuarantineDir, MinHostIsolate, MinPanicSwitch.
	// Set to >100 to disable a step entirely.
	MinThrottle       int
	MinBlockNet       int
	MinKillProc       int
	MinQuarantineFile int
	MinQuarantineDir  int
	MinHostIsolate    int
	MinPanicSwitch    int
	// MaxStep is a hard ceiling applied last. Set to StepAlert (2)
	// in observe mode; raises only when operator has signed off on
	// enforce. Default is StepAlert.
	MaxStep Step
}

// DefaultPolicy returns the conservative defaults: observe-only.
// Even at score 100 nothing beyond StepAlert fires. Operators MUST
// raise MaxStep + tune the Min* thresholds to enable enforce-tier
// responses.
func DefaultPolicy() Policy {
	return Policy{
		MinAlert:          1,
		MinThrottle:       60,
		MinBlockNet:       70,
		MinKillProc:       80,
		MinQuarantineFile: 80,
		MinQuarantineDir:  90,
		MinHostIsolate:    95,
		MinPanicSwitch:    100,
		MaxStep:           StepAlert, // observe + alert only
	}
}

// SelectStep returns the step the policy WOULD invoke for the
// given verdict score. Pure — does not perform the action.
func (p Policy) SelectStep(score int) Step {
	chosen := StepObserve
	switch {
	case p.MinPanicSwitch > 0 && score >= p.MinPanicSwitch:
		chosen = StepPanicSwitch
	case p.MinHostIsolate > 0 && score >= p.MinHostIsolate:
		chosen = StepHostIsolate
	case p.MinQuarantineDir > 0 && score >= p.MinQuarantineDir:
		chosen = StepQuarantineDir
	case p.MinQuarantineFile > 0 && score >= p.MinQuarantineFile:
		chosen = StepQuarantineFile
	case p.MinKillProc > 0 && score >= p.MinKillProc:
		chosen = StepKillProc
	case p.MinBlockNet > 0 && score >= p.MinBlockNet:
		chosen = StepBlockNet
	case p.MinThrottle > 0 && score >= p.MinThrottle:
		chosen = StepThrottle
	case p.MinAlert > 0 && score >= p.MinAlert:
		chosen = StepAlert
	}
	// Apply hard ceiling. MaxStep == 0 means "no ceiling" but we
	// treat 0 as Alert to match DefaultPolicy semantics.
	ceiling := p.MaxStep
	if ceiling <= 0 {
		ceiling = StepAlert
	}
	if chosen > ceiling {
		chosen = ceiling
	}
	return chosen
}

// Action is the executor injected for each enforce step. Returning
// nil = success; an error is logged but does not abort the ladder.
type Action func(v Verdict) error

// Actions is the executor set. nil entries → step is skipped with
// an audit log (so the ladder is safe to construct without every
// primitive available in tests / degraded daemons).
type Actions struct {
	Alert          Action
	Throttle       Action
	BlockNet       Action
	KillProc       Action
	QuarantineFile Action
	QuarantineDir  Action
	HostIsolate    Action
	PanicSwitch    Action
}

// Ladder is the configured runner. Goroutine-safe.
type Ladder struct {
	mu     sync.RWMutex
	policy Policy
	acts   Actions
	log    *slog.Logger
	// per-source last-step + last-time used by suppress() so a single
	// breach doesn't fire kill_proc once per evaluation tick.
	last map[string]ladderState
}

type ladderState struct {
	step Step
	at   time.Time
}

// New constructs a Ladder with the given policy + executors.
func New(p Policy, a Actions, log *slog.Logger) *Ladder {
	return &Ladder{policy: p, acts: a, log: log, last: map[string]ladderState{}}
}

// SetPolicy swaps the policy at runtime.
func (l *Ladder) SetPolicy(p Policy) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.policy = p
}

// Policy returns a copy of the current policy.
func (l *Ladder) Policy() Policy {
	if l == nil {
		return Policy{}
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.policy
}

// Handle evaluates v through the policy and invokes the selected
// action. Returns the step that was invoked (or attempted) and any
// executor error. StepObserve always returns nil error.
//
// Re-firing suppression: within RepeatCooldown (5 minutes) for the
// same SourceID, the ladder will NOT re-invoke the same step. A
// higher step CAN still fire — escalation isn't suppressed.
func (l *Ladder) Handle(v Verdict) (Step, error) {
	if l == nil {
		return StepObserve, nil
	}
	if v.At.IsZero() {
		v.At = time.Now()
	}
	l.mu.Lock()
	step := l.policy.SelectStep(v.Score)
	suppressed := l.suppress(v.SourceID, step, v.At)
	if !suppressed {
		l.last[v.SourceID] = ladderState{step: step, at: v.At}
	}
	acts := l.acts
	l.mu.Unlock()

	if l.log != nil {
		l.log.Info("containment.ladder",
			"step", step.String(), "score", v.Score, "chain", v.Chain,
			"source", v.SourceID, "pid", v.PID, "suppressed", suppressed)
	}
	if suppressed || step == StepObserve {
		return step, nil
	}
	act := pickAction(acts, step)
	if act == nil {
		if l.log != nil {
			l.log.Warn("containment.ladder: step has no executor (skipped)",
				"step", step.String())
		}
		return step, nil
	}
	return step, act(v)
}

// RepeatCooldown is the per-(source, step) cooldown after a fire.
var RepeatCooldown = 5 * time.Minute

func (l *Ladder) suppress(source string, step Step, now time.Time) bool {
	if source == "" {
		return false
	}
	prev, ok := l.last[source]
	if !ok {
		return false
	}
	// Only suppress identical step within cooldown. Escalation
	// (higher step than previous) is always allowed.
	if step > prev.step {
		return false
	}
	if step == prev.step && now.Sub(prev.at) < RepeatCooldown {
		return true
	}
	return false
}

func pickAction(a Actions, s Step) Action {
	switch s {
	case StepAlert:
		return a.Alert
	case StepThrottle:
		return a.Throttle
	case StepBlockNet:
		return a.BlockNet
	case StepKillProc:
		return a.KillProc
	case StepQuarantineFile:
		return a.QuarantineFile
	case StepQuarantineDir:
		return a.QuarantineDir
	case StepHostIsolate:
		return a.HostIsolate
	case StepPanicSwitch:
		return a.PanicSwitch
	}
	return nil
}

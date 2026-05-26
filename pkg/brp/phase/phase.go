// Package phase tracks per-PID lifecycle phase for BRP evaluation.
//
// The v2 BRP architecture distinguishes four phases per process so the
// runtime can apply phase-specific envelope rules:
//
//	bootstrap — first window after spawn; broader writes are normal
//	            (config templating, socket setup, temp-file warm-up)
//	steady    — long-running operation; the tightest envelope applies
//	reload    — operator-driven reload (SIGHUP / config write detected);
//	            transient widened envelope for config re-read
//	degraded  — recent crash / OOM / panic; envelope tightens further
//	            since attackers often exploit restart races
//
// v1 implements bootstrap → steady automatically (time-based) and exposes
// hooks (Reload, Degrade) for higher layers to flip into the other two
// phases when they detect the trigger. No state is persisted across
// daemon restarts — phase is a hot in-memory property, not durable.
package phase

import (
	"sync"
	"time"
)

// Phase is the canonical lifecycle state.
type Phase uint8

const (
	PhaseUnknown   Phase = iota
	PhaseBootstrap       // first BootstrapWindow after first-seen
	PhaseSteady          // default after bootstrap window elapses
	PhaseReload          // explicitly flipped by Reload(pid)
	PhaseDegraded        // explicitly flipped by Degrade(pid)
)

// String returns the canonical short token used in event tags + logs.
func (p Phase) String() string {
	switch p {
	case PhaseBootstrap:
		return "bootstrap"
	case PhaseSteady:
		return "steady"
	case PhaseReload:
		return "reload"
	case PhaseDegraded:
		return "degraded"
	}
	return "unknown"
}

// DefaultBootstrap is the window during which a freshly-spawned process
// is treated as bootstrapping. Chosen at 60s because typical web/db
// servers complete socket setup + worker-fork well inside that window;
// operators with slower startups can tune via NewTracker(window).
const DefaultBootstrap = 60 * time.Second

// DefaultReloadWindow is how long a process stays in PhaseReload after
// Reload() is called before falling back to PhaseSteady.
const DefaultReloadWindow = 10 * time.Second

// DefaultDegradedWindow is how long PhaseDegraded persists after Degrade().
const DefaultDegradedWindow = 5 * time.Minute

// Tracker is the per-PID phase state machine. Safe for concurrent use.
//
// State is kept in-memory only. Forget(pid) reclaims when a process exits.
// A bounded sweep also drops entries whose firstSeen is older than 24h —
// PIDs do recycle and a stale entry could misclassify a new process.
type Tracker struct {
	mu sync.RWMutex

	bootstrapWindow time.Duration
	reloadWindow    time.Duration
	degradedWindow  time.Duration

	entries map[uint32]*entry
}

type entry struct {
	firstSeen      time.Time
	manual         Phase     // PhaseUnknown = no manual override
	manualUntil    time.Time // when the manual override expires
}

// NewTracker constructs a Tracker with default windows. Pass zero values
// to inherit DefaultBootstrap / DefaultReloadWindow / DefaultDegradedWindow.
func NewTracker(bootstrapWindow, reloadWindow, degradedWindow time.Duration) *Tracker {
	if bootstrapWindow <= 0 {
		bootstrapWindow = DefaultBootstrap
	}
	if reloadWindow <= 0 {
		reloadWindow = DefaultReloadWindow
	}
	if degradedWindow <= 0 {
		degradedWindow = DefaultDegradedWindow
	}
	return &Tracker{
		bootstrapWindow: bootstrapWindow,
		reloadWindow:    reloadWindow,
		degradedWindow:  degradedWindow,
		entries:         map[uint32]*entry{},
	}
}

// ObserveSignal updates the phase tracker from a signal event. Used by
// the pipeline to convert syscall / configfile-write / restart-loop
// indicators into phase transitions WITHOUT requiring manual operator
// hooks.
//
// Recognized triggers:
//
//	signal=SIGHUP                  → Reload
//	signal=SIGSEGV | OOM kill      → Degrade
//	exec_within_N_seconds_of_exit  → Degrade (restart loop)
//
// The signal name is the lowercase Unix mnemonic ("hup", "term", "segv",
// "kill") — what the eBPF signal sensor stamps as ev.Tags["signal"].
func (t *Tracker) ObserveSignal(pid uint32, signal string, now time.Time) Phase {
	if pid == 0 {
		return PhaseUnknown
	}
	switch signal {
	case "hup":
		t.Reload(pid, now)
	case "segv", "abrt", "bus":
		t.Degrade(pid, now)
	}
	return t.Get(pid, now)
}

// ObserveRestart marks a PID as Degraded when a new process replaces a
// recently-exited one with the same image — the classic restart-loop
// indicator that often coincides with attacker exploitation of a service
// crash recovery window.
//
// Caller passes the time of the previous exit and the new spawn; if they
// occur within restartLoopWindow, Degraded fires.
func (t *Tracker) ObserveRestart(pid uint32, prevExit, newSpawn time.Time) {
	const restartLoopWindow = 30 * time.Second
	if newSpawn.Sub(prevExit) <= restartLoopWindow {
		t.Degrade(pid, newSpawn)
	}
}

// Observe records that PID has been seen. First-touch starts the
// bootstrap window. Returns the current Phase for the PID.
func (t *Tracker) Observe(pid uint32, now time.Time) Phase {
	if pid == 0 {
		return PhaseUnknown
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[pid]
	if !ok {
		e = &entry{firstSeen: now}
		t.entries[pid] = e
	}
	return t.phaseFor(e, now)
}

// Get returns the current Phase for pid without recording observation.
// Returns PhaseUnknown if pid was never Observed.
func (t *Tracker) Get(pid uint32, now time.Time) Phase {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.entries[pid]
	if !ok {
		return PhaseUnknown
	}
	return t.phaseFor(e, now)
}

// Reload flips pid into PhaseReload for the configured reload window.
// If pid is unknown, Reload creates an entry with firstSeen=now-bootstrap
// (so its natural bootstrap window has already elapsed).
func (t *Tracker) Reload(pid uint32, now time.Time) {
	t.setManual(pid, PhaseReload, now.Add(t.reloadWindow), now)
}

// Degrade flips pid into PhaseDegraded for the configured degraded window.
func (t *Tracker) Degrade(pid uint32, now time.Time) {
	t.setManual(pid, PhaseDegraded, now.Add(t.degradedWindow), now)
}

func (t *Tracker) setManual(pid uint32, ph Phase, until, now time.Time) {
	if pid == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[pid]
	if !ok {
		e = &entry{firstSeen: now.Add(-t.bootstrapWindow - time.Second)}
		t.entries[pid] = e
	}
	e.manual = ph
	e.manualUntil = until
}

// Forget drops the entry for pid (typically called on process exit).
func (t *Tracker) Forget(pid uint32) {
	t.mu.Lock()
	delete(t.entries, pid)
	t.mu.Unlock()
}

// Sweep drops entries whose firstSeen is older than maxAge. Returns the
// number of entries reclaimed. Call from a long-running ticker.
func (t *Tracker) Sweep(now time.Time, maxAge time.Duration) int {
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	cutoff := now.Add(-maxAge)
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for pid, e := range t.entries {
		if e.firstSeen.Before(cutoff) {
			delete(t.entries, pid)
			n++
		}
	}
	return n
}

// Size returns the number of tracked PIDs (test helper).
func (t *Tracker) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}

func (t *Tracker) phaseFor(e *entry, now time.Time) Phase {
	if e.manual != PhaseUnknown && now.Before(e.manualUntil) {
		return e.manual
	}
	if now.Sub(e.firstSeen) < t.bootstrapWindow {
		return PhaseBootstrap
	}
	return PhaseSteady
}

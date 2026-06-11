// Package contracthealth provides the safety layer for the behavioral
// compiler's enforcement: a deny-storm circuit breaker (alert-only) and a
// reconciler that converges on-disk armed state with declared intent.
//
// Design decision (deliberate, security-driven): the breaker NEVER
// auto-disables enforcement on deny volume. Deny rate is attacker-
// controllable — letting a flood of denies auto-downgrade a locked app
// would hand an attacker an off-switch for the EDR. The breaker therefore
// only ALERTS on a deny storm and surfaces an operator-driven downgrade.
// The one thing that DOES auto-revert is an unambiguous availability
// failure (a service that won't restart after arming), handled in
// pkg/contractarm.RestartAndVerify — not here.
package contracthealth

import (
	"sync"
	"time"
)

// Breaker tracks per-app policy-deny rate over a rolling window and
// latches a "tripped" alert state when the rate crosses a threshold.
// Alert-only: it takes no enforcement action itself.
type Breaker struct {
	window    time.Duration
	threshold int
	onTrip    func(app string, count int)

	mu      sync.Mutex
	events  map[string][]time.Time // recent deny timestamps per app
	tripped map[string]time.Time   // app → first trip time (latched until Reset)
}

// NewBreaker returns a breaker that trips when an app accumulates
// >= threshold denies within window. onTrip is called once per latch
// (typically to publish an alert); it may be nil.
func NewBreaker(window time.Duration, threshold int, onTrip func(app string, count int)) *Breaker {
	if window <= 0 {
		window = time.Minute
	}
	if threshold <= 0 {
		threshold = 25
	}
	return &Breaker{
		window:    window,
		threshold: threshold,
		onTrip:    onTrip,
		events:    make(map[string][]time.Time),
		tripped:   make(map[string]time.Time),
	}
}

// RecordDeny registers one policy deny for app at time at. If the rolling
// count reaches the threshold and the app is not already tripped, the
// breaker latches and fires onTrip exactly once.
func (b *Breaker) RecordDeny(app string, at time.Time) {
	if app == "" {
		return
	}
	b.mu.Lock()
	ev := append(b.events[app], at)
	ev = pruneOlder(ev, at.Add(-b.window))
	b.events[app] = ev
	count := len(ev)
	_, already := b.tripped[app]
	shouldFire := count >= b.threshold && !already
	if shouldFire {
		b.tripped[app] = at
	}
	cb := b.onTrip
	b.mu.Unlock()

	if shouldFire && cb != nil {
		cb(app, count)
	}
}

// SetOnTrip sets (or replaces) the trip callback after construction —
// used to attach the alert bus once it exists.
func (b *Breaker) SetOnTrip(fn func(app string, count int)) {
	b.mu.Lock()
	b.onTrip = fn
	b.mu.Unlock()
}

// Tripped reports whether the app's breaker is latched.
func (b *Breaker) Tripped(app string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.tripped[app]
	return ok
}

// RecentDenies returns the current rolling-window deny count for app.
func (b *Breaker) RecentDenies(app string, now time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(pruneOlder(b.events[app], now.Add(-b.window)))
}

// Reset clears the latched trip state for an app (operator acknowledged /
// handled). Does not clear the rolling event window.
func (b *Breaker) Reset(app string) {
	b.mu.Lock()
	delete(b.tripped, app)
	b.mu.Unlock()
}

// Threshold / Window expose the configured limits (for the UI).
func (b *Breaker) Threshold() int          { return b.threshold }
func (b *Breaker) Window() time.Duration   { return b.window }

// Sweep prunes rolling event windows older than `now-window` to bound
// memory. Trip latches are intentionally sticky (operator must Reset).
func (b *Breaker) Sweep(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cut := now.Add(-b.window)
	for app, ev := range b.events {
		ev = pruneOlder(ev, cut)
		if len(ev) == 0 {
			delete(b.events, app)
		} else {
			b.events[app] = ev
		}
	}
}

// pruneOlder returns the suffix of ts with all entries strictly after cut.
// ts is assumed roughly ascending (append order); we scan from the front.
func pruneOlder(ts []time.Time, cut time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cut) {
		i++
	}
	if i == 0 {
		return ts
	}
	// Compact to avoid unbounded backing-array growth.
	out := make([]time.Time, len(ts)-i)
	copy(out, ts[i:])
	return out
}

// Package sshbrute detects SSH brute-force attempts from a single
// source IP. Phase J.1.
//
// Input: identity.sshd events with outcome=failure (Failed password,
// Invalid user). Sensor sensors/identity/sshd.go already produces
// these — see ParseSSHDLine.
//
// Detection: sliding-window counter keyed by src_ip. When N or more
// failures from the same source IP land within window M, emit one
// alert and enter cooldown to suppress repeat alerts on the same
// attack.
//
// Defaults: N=20, M=60s, cooldown=5min. These match the conservative
// posture in docs/BRP_IMPLEMENTATION_PLAN_2026-05-24.md §7quater.
//
// FP considerations:
//   - Legitimate password-typing-mistake bursts rarely exceed 5
//     failures in 60s for one user. N=20 leaves headroom.
//   - Fail2ban / cracker-style attacks easily exceed N=20 in seconds.
//   - Distributed brute-force (one fail per source) is NOT caught
//     here — that's a different detector against the aggregate
//     /var/log/auth.log rate, deferred.
package sshbrute

import (
	"log/slog"
	"sync"
	"time"
)

// Detector is the sliding-window brute-force counter.
//
// Safe for concurrent use. One Detector per daemon.
type Detector struct {
	mu sync.Mutex

	// thresholds
	threshold int           // N — failures needed
	window    time.Duration // M — observation window
	cooldown  time.Duration // suppress repeat alerts on same source IP

	// per-source state
	bySource map[string]*sourceState
}

// sourceState tracks failure timestamps + cooldown for one src_ip.
// Ring buffer of last `threshold` timestamps gives O(1) per event.
type sourceState struct {
	stamps      []time.Time // ring of last threshold events
	idx         int
	count       int       // count in the ring (caps at threshold)
	cooldownEnd time.Time // when the next alert can fire
	users       map[string]int
}

// Defaults returns the recommended detector thresholds.
func Defaults() (threshold int, window, cooldown time.Duration) {
	return 20, 60 * time.Second, 5 * time.Minute
}

// NewDetector constructs a detector with the given thresholds.
// Use Defaults() for the recommended values.
func NewDetector(threshold int, window, cooldown time.Duration) *Detector {
	return &Detector{
		threshold: threshold,
		window:    window,
		cooldown:  cooldown,
		bySource:  make(map[string]*sourceState),
	}
}

// Observation is what the detector returns when a fresh alert
// should fire. Fired==false means the event was recorded but did
// not (yet) cross the threshold + cooldown gate.
type Observation struct {
	Fired       bool
	SourceIP    string
	Failures    int
	Window      time.Duration
	UserAttempts map[string]int // user → count of attempts seen in window
}

// Observe records one auth failure from sourceIP for user at ts.
// Returns Fired=true exactly once per (sourceIP, attack-burst), gated
// by cooldown.
func (d *Detector) Observe(sourceIP, user string, ts time.Time) Observation {
	if sourceIP == "" {
		return Observation{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.bySource[sourceIP]
	if !ok {
		st = &sourceState{
			stamps: make([]time.Time, d.threshold),
			users:  make(map[string]int),
		}
		d.bySource[sourceIP] = st
	}
	st.stamps[st.idx] = ts
	st.idx = (st.idx + 1) % d.threshold
	if st.count < d.threshold {
		st.count++
	}
	if user != "" {
		st.users[user]++
	}

	// Count how many ring entries fall within [ts-window, ts].
	failuresInWindow := 0
	for _, t := range st.stamps {
		if !t.IsZero() && !t.Before(ts.Add(-d.window)) {
			failuresInWindow++
		}
	}
	if failuresInWindow < d.threshold {
		return Observation{}
	}
	if ts.Before(st.cooldownEnd) {
		return Observation{}
	}
	st.cooldownEnd = ts.Add(d.cooldown)
	users := make(map[string]int, len(st.users))
	for u, n := range st.users {
		users[u] = n
	}
	// Clear the user accumulator so the next alert reports fresh
	// users only.
	st.users = make(map[string]int)
	return Observation{
		Fired:       true,
		SourceIP:    sourceIP,
		Failures:    failuresInWindow,
		Window:      d.window,
		UserAttempts: users,
	}
}

// Sweep clears entries whose most-recent stamp is older than 2×window.
// Called periodically by the daemon to bound memory.
func (d *Detector) Sweep(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := now.Add(-2 * d.window)
	for ip, st := range d.bySource {
		newest := time.Time{}
		for _, t := range st.stamps {
			if t.After(newest) {
				newest = t
			}
		}
		if newest.Before(cutoff) && now.After(st.cooldownEnd) {
			delete(d.bySource, ip)
		}
	}
}

// Size returns the number of tracked source IPs (metrics).
func (d *Detector) Size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.bySource)
}

// LogAlert is a convenience helper for callers that want a structured
// slog line for a fired observation. The caller still has to emit the
// model.Alert through their bus — this just logs the fact.
func LogAlert(log *slog.Logger, obs Observation) {
	if !obs.Fired {
		return
	}
	users := make([]string, 0, len(obs.UserAttempts))
	for u := range obs.UserAttempts {
		users = append(users, u)
	}
	log.Warn("ssh brute-force detected",
		"src_ip", obs.SourceIP,
		"failures", obs.Failures,
		"window", obs.Window.String(),
		"users", users)
}

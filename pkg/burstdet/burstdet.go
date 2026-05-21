// Package burstdet detects "burst" patterns from a single PID:
//   - file_read_burst:    one PID opening >N files in <T seconds
//   - process_spawn_burst: one PID spawning >N children in <T seconds
//
// Both are the steady-state signature of credential-harvesting
// stages of modern malware. Megalodon (ox.security 2026) scans
// the CI/CD workspace for AWS/Slack/GitHub keys via grep+regex —
// hundreds of opens per second. TeamTNT chains `aws configure
// list-profiles` to many `cat` reads. Outlaw's cron pattern
// spawns ~20 children in a 5s window.
//
// Honest scope:
//   - we observe events that flow through pkg/pipeline.Handle.
//     If the event channel drops due to backpressure we under-count.
//   - JIT runtimes (Java, Node, .NET) legitimately open hundreds
//     of class files at startup. The pipeline already exempts
//     these via the jit_allowlisted tag — the burstdet wiring
//     skips events whose Image matches runtimeallow.
//   - per-PID counter is dropped on proc_exit so PID reuse
//     doesn't carry false history. A periodic Sweep handles the
//     case where exit events are lost.
package burstdet

import (
	"sync"
	"time"
)

// Threshold defines one detector's window + count.
type Threshold struct {
	Window   time.Duration // sliding window (typical: 10s)
	Count    int           // burst threshold (typical: 50)
	CoolDown time.Duration // suppress repeat alerts for the same PID
}

// Defaults returns sensible thresholds for files / spawns.
//
// File reads: 80 reads in 10s = "scan the workspace for secrets"
// territory. Normal compile / dev workloads stay below this.
//
// Process spawns: 20 spawns in 10s = "shell loop or process-
// scanning malware". cron / systemd at peak rotation stay below.
func Defaults() (file, spawn Threshold) {
	return Threshold{Window: 10 * time.Second, Count: 80, CoolDown: 60 * time.Second},
		Threshold{Window: 10 * time.Second, Count: 20, CoolDown: 60 * time.Second}
}

// Counter is one threshold's per-PID sliding-window tracker.
// Safe for concurrent use.
type Counter struct {
	t      Threshold
	mu     sync.Mutex
	events map[uint32]*pidWindow
}

type pidWindow struct {
	timestamps []time.Time // each event time (trimmed to window)
	lastAlert  time.Time   // for cool-down
}

// NewCounter constructs a Counter with the given threshold.
func NewCounter(t Threshold) *Counter {
	if t.Window <= 0 {
		t.Window = 10 * time.Second
	}
	if t.Count <= 0 {
		t.Count = 50
	}
	if t.CoolDown <= 0 {
		t.CoolDown = 60 * time.Second
	}
	return &Counter{t: t, events: map[uint32]*pidWindow{}}
}

// Observe records one event for pid at time now. Returns cross=true
// the FIRST time the PID's count in the sliding window crosses the
// threshold; subsequent calls within CoolDown return false even if
// the count stays high. count is the events-in-window at this moment.
func (c *Counter) Observe(pid uint32, now time.Time) (cross bool, count int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.events[pid]
	if w == nil {
		w = &pidWindow{}
		c.events[pid] = w
	}
	cutoff := now.Add(-c.t.Window)
	i := 0
	for ; i < len(w.timestamps); i++ {
		if w.timestamps[i].After(cutoff) {
			break
		}
	}
	if i > 0 {
		w.timestamps = w.timestamps[i:]
	}
	w.timestamps = append(w.timestamps, now)
	count = len(w.timestamps)
	if count >= c.t.Count {
		if now.Sub(w.lastAlert) >= c.t.CoolDown {
			w.lastAlert = now
			cross = true
		}
	}
	return cross, count
}

// Forget drops a PID's history. Call on proc_exit so PID reuse
// doesn't carry stale state.
func (c *Counter) Forget(pid uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.events, pid)
}

// Sweep removes PIDs with no events in the last ageOut interval.
// Call periodically (every 5 min is fine) so dead-PID entries
// don't accumulate when proc_exit events are lost.
func (c *Counter) Sweep(now time.Time, ageOut time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-ageOut)
	dropped := 0
	for pid, w := range c.events {
		if len(w.timestamps) == 0 ||
			w.timestamps[len(w.timestamps)-1].Before(cutoff) {
			delete(c.events, pid)
			dropped++
		}
	}
	return dropped
}

// Size returns the count of currently-tracked PIDs (for /status).
func (c *Counter) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// Threshold returns the configured window/count/cooldown.
func (c *Counter) Threshold() Threshold { return c.t }

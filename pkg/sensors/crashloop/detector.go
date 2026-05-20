// Package crashloop is the Ring 2 crash-loop trap. When a protected
// service crashes ≥ Threshold times within Window seconds, the
// detector emits a SignalCrashLoop (Tier-1, weight 80 by default)
// into the planner — score crosses 75 → SuspendProcess fires on the
// lineage. The service is also Halted via the configured callback
// so systemd doesn't auto-restart it back into the exploit.
//
// See PROTECTED_SERVICES_TRAP.md §6 "Crash-Loop Trap (cheap, high-
// signal)".
//
// Pure Go. CGO_ENABLED=0. Source-agnostic: any goroutine can call
// Detector.Observe() with a CrashEvent. The Linux source built into
// this package polls systemd via systemctl; tests use a synthetic
// source.
package crashloop

import (
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/takeover"
)

// CrashEvent is one observed crash. Producers populate as much as
// they have; ServiceName is the only required field for the
// detector to track windows.
type CrashEvent struct {
	At          time.Time
	ServiceName string // matches protectedsvc.ProtectedService.Name
	UnitName    string // optional — e.g. "nginx.service"
	PID         uint32 // crashed PID if known
	LineageID   uint64 // for the takeover signal
	ExitCode    int    // when process exited normally
	Signal      string // when process was terminated by signal ("SIGSEGV", "SIGABRT", ...)
	Source      string // who saw it: "systemd", "ebpf", etc.
}

// Decision is what the detector wants the caller to do when a crash
// loop fires. Caller wires this to:
//   - takeover.Planner.OnSignal(Signal) for the score bump
//   - a "halt" callback (systemctl stop + mask) so systemd doesn't
//     auto-restart the service back into the exploit
type Decision struct {
	ServiceName string
	UnitName    string
	LineageID   uint64
	Signal      takeover.Signal
	CrashCount  int           // how many crashes in window
	Window      time.Duration // window covered
	LastEvents  []CrashEvent  // copy of the crashes that triggered (newest last)
}

// Config tunes the detector.
type Config struct {
	// Window — sliding time window. Default 60s.
	Window time.Duration
	// Threshold — crash count within Window that triggers a fire.
	// Default 3.
	Threshold int
	// SignalWeight — weight attached to the emitted takeover.Signal.
	// Default 80 (Tier-1).
	SignalWeight int
	// FireCooldown — once a service fires, the detector won't fire
	// again for this duration even if more crashes arrive. Prevents
	// re-emission storms; the planner already has the Suspended
	// state. Default 5min.
	FireCooldown time.Duration

	// Now / Sleep test hooks.
	Now func() time.Time
}

func (c Config) defaulted() Config {
	d := c
	if d.Window <= 0 {
		d.Window = 60 * time.Second
	}
	if d.Threshold <= 0 {
		d.Threshold = 3
	}
	if d.SignalWeight <= 0 {
		d.SignalWeight = 80
	}
	if d.FireCooldown <= 0 {
		d.FireCooldown = 5 * time.Minute
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return d
}

// Detector is the per-service sliding-window crash counter.
// Thread-safe.
type Detector struct {
	cfg Config

	mu       sync.Mutex
	windows  map[string]*window // by ServiceName
	lastFire map[string]time.Time
}

type window struct {
	events []CrashEvent // chronologically ordered (oldest first)
}

// New returns a Detector with the given Config.
func New(cfg Config) *Detector {
	return &Detector{
		cfg:      cfg.defaulted(),
		windows:  map[string]*window{},
		lastFire: map[string]time.Time{},
	}
}

// Observe records a crash. Returns a non-nil Decision if this
// observation pushed the service across the threshold (and the
// FireCooldown has expired); nil otherwise.
func (d *Detector) Observe(ev CrashEvent) *Decision {
	if ev.At.IsZero() {
		ev.At = d.cfg.Now()
	}
	if ev.ServiceName == "" {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	w, ok := d.windows[ev.ServiceName]
	if !ok {
		w = &window{}
		d.windows[ev.ServiceName] = w
	}

	cutoff := ev.At.Add(-d.cfg.Window)
	w.events = pruneOlder(w.events, cutoff)
	w.events = append(w.events, ev)

	if len(w.events) < d.cfg.Threshold {
		return nil
	}

	// Cooldown check.
	if last, ok := d.lastFire[ev.ServiceName]; ok {
		if ev.At.Sub(last) < d.cfg.FireCooldown {
			return nil
		}
	}
	d.lastFire[ev.ServiceName] = ev.At

	// Build decision.
	last := w.events
	cp := make([]CrashEvent, len(last))
	copy(cp, last)

	sig := takeover.Signal{
		LineageID:  ev.LineageID,
		Kind:       takeover.SignalCrashLoop,
		At:         ev.At,
		Source:     "crashloop:" + ev.ServiceName,
		Detail:     buildDetail(ev, len(cp)),
		Confidence: "deterministic",
		Weight:     d.cfg.SignalWeight,
	}
	return &Decision{
		ServiceName: ev.ServiceName,
		UnitName:    ev.UnitName,
		LineageID:   ev.LineageID,
		Signal:      sig,
		CrashCount:  len(cp),
		Window:      d.cfg.Window,
		LastEvents:  cp,
	}
}

// Forget drops all state for a service. Call after a Released or
// Terminated transition so the next start-fresh doesn't carry
// stale crashes forward.
func (d *Detector) Forget(serviceName string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.windows, serviceName)
	delete(d.lastFire, serviceName)
}

// CrashCount returns the number of crashes for the service within
// the current window. Useful for dashboards.
func (d *Detector) CrashCount(serviceName string, now time.Time) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	w, ok := d.windows[serviceName]
	if !ok {
		return 0
	}
	cutoff := now.Add(-d.cfg.Window)
	w.events = pruneOlder(w.events, cutoff)
	return len(w.events)
}

// pruneOlder drops events older than cutoff. Events are roughly
// time-ordered (we always append at observation), so we can walk
// from the front until we find an event ≥ cutoff.
func pruneOlder(events []CrashEvent, cutoff time.Time) []CrashEvent {
	i := 0
	for ; i < len(events); i++ {
		if !events[i].At.Before(cutoff) {
			break
		}
	}
	if i == 0 {
		return events
	}
	rem := events[i:]
	out := make([]CrashEvent, len(rem))
	copy(out, rem)
	return out
}

func buildDetail(ev CrashEvent, count int) string {
	if ev.Signal != "" {
		return ev.ServiceName + " crashed " + itoa(count) + "x (last " + ev.Signal + ")"
	}
	if ev.ExitCode != 0 {
		return ev.ServiceName + " crashed " + itoa(count) + "x (last exit " + itoa(ev.ExitCode) + ")"
	}
	return ev.ServiceName + " crashed " + itoa(count) + "x"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

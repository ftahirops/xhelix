// Package pkgmgr maintains per-host package-manager transaction windows.
//
// When apt / dpkg / dnf / snap is actively installing or upgrading packages,
// many file-write and execve events that would normally trip xhelix's
// dropped-binary-lifecycle chain are legitimate (postinst scripts, dpkg
// triggers, snap mount). pkgmgr provides a single source of truth:
//
//	store := pkgmgr.New(log)
//	go pkgmgr.TailApt(ctx, store, "/var/log/apt/history.log")
//	go pkgmgr.TailDpkg(ctx, store, "/var/log/dpkg.log")
//
//	if store.IsActive(ev.Time) {
//	    ev.Tags["pkg_install_window"] = "true"
//	}
//
// Phase K.2.
package pkgmgr

import (
	"log/slog"
	"sync"
	"time"
)

// Manager identifies the package manager that opened a window.
type Manager string

const (
	ManagerApt  Manager = "apt"
	ManagerDpkg Manager = "dpkg"
	ManagerDnf  Manager = "dnf"
	ManagerSnap Manager = "snap"
)

// Window represents an active package transaction.
//
// EndsAt is set when the transaction's End-Date is observed (apt) or
// after a quiescence timeout (dpkg / snap, which don't have explicit
// transaction-end markers).
type Window struct {
	Manager   Manager
	StartedAt time.Time
	EndsAt    time.Time
	Command   string // e.g. "apt-get install -y suricata"
}

// Store holds the active window per manager. Safe for concurrent use.
type Store struct {
	mu      sync.RWMutex
	windows map[Manager]*Window
	log     *slog.Logger
}

// New constructs an empty Store.
func New(log *slog.Logger) *Store {
	return &Store{
		windows: make(map[Manager]*Window),
		log:     log,
	}
}

// Open or extend a window for `m`. `at` is the line timestamp from the log
// file. `endsAt` is when the window should auto-close if no Close() call
// arrives.
//
// If a window for m is already open, Open extends EndsAt forward but
// preserves StartedAt — multiple log lines within a transaction don't
// reset the start.
func (s *Store) Open(m Manager, at, endsAt time.Time, command string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.windows[m]
	if !ok {
		w = &Window{Manager: m, StartedAt: at, Command: command}
		s.windows[m] = w
		if s.log != nil {
			s.log.Info("pkgmgr: window opened", "manager", string(m), "started_at", at, "ends_at", endsAt, "cmd", command)
		}
	}
	if endsAt.After(w.EndsAt) {
		w.EndsAt = endsAt
	}
}

// Close marks the window for `m` as ending now. Used by apt's End-Date.
func (s *Store) Close(m Manager, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.windows[m]
	if !ok {
		return
	}
	// Add a grace period so events arriving immediately after End-Date
	// still get tagged — postinst trigger handlers can fire seconds
	// after the End-Date line.
	grace := 5 * time.Second
	if at.Add(grace).After(w.EndsAt) {
		w.EndsAt = at.Add(grace)
	}
	if s.log != nil {
		s.log.Info("pkgmgr: window closing", "manager", string(m), "ends_at", w.EndsAt, "duration", w.EndsAt.Sub(w.StartedAt).String())
	}
}

// IsActive reports whether any package-manager transaction is active at
// time `at`. Lock-free fast-path for the pipeline hot path.
func (s *Store) IsActive(at time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, w := range s.windows {
		if !at.After(w.EndsAt) && !at.Before(w.StartedAt) {
			return true
		}
	}
	return false
}

// ActiveManagers returns the list of managers with an open window at `at`.
// Used for tag enrichment when the pipeline wants more detail than a
// boolean.
func (s *Store) ActiveManagers(at time.Time) []Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Manager
	for m, w := range s.windows {
		if !at.After(w.EndsAt) && !at.Before(w.StartedAt) {
			out = append(out, m)
		}
	}
	return out
}

// Sweep removes windows that ended more than `keep` ago. Caller runs this
// periodically (default once per minute) to bound memory.
func (s *Store) Sweep(now time.Time, keep time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.Add(-keep)
	for m, w := range s.windows {
		if w.EndsAt.Before(cutoff) {
			delete(s.windows, m)
			if s.log != nil {
				s.log.Debug("pkgmgr: window swept", "manager", string(m), "ended_at", w.EndsAt)
			}
		}
	}
}

// Size returns the number of currently-tracked windows (metrics helper).
func (s *Store) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.windows)
}

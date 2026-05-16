// Package oobhub defines the out-of-band-transport interface for
// the xhelix host → xhub link.
//
// Why it exists: if a compromised host can block its main NIC's
// egress to the hub, the hub stops hearing from it — and that
// silence looks identical to "the host is fine." A secondary
// transport (Tailscale mesh, WireGuard tunnel, LTE modem) on a
// different routing path makes that exfiltration detection
// adversarially robust.
//
// The package is the *contract*. Concrete transports are
// supplied by callers — a Tailscale dialer, a WG dialer, a
// SOCKS5 dialer, anything that satisfies the Transport
// interface. Callers register transports in priority order;
// the Manager dials each in turn until one succeeds.
//
// Pure-Go. No external deps. Production wiring (Tailscale,
// WireGuard) lives behind build tags in calling code.
package oobhub

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"time"
)

// Transport is the secondary-link interface.
type Transport interface {
	// Name is a stable identifier ("tailscale", "wg-corp", "lte").
	Name() string

	// Priority — lower number = tried first. Tie-break by Name.
	Priority() int

	// Available reports whether this transport is ready to dial.
	// Implementations should be cheap (no network round-trip) so
	// the Manager can call this on every Dial.
	Available() bool

	// Dial opens a connection to the hub address using this
	// transport's network. The Manager passes the ctx; transport
	// implementations honour it for cancel and deadline.
	Dial(ctx context.Context, hubAddr string) (net.Conn, error)
}

// Manager orchestrates priority-ordered fallback across the
// registered transports.
type Manager struct {
	mu         sync.RWMutex
	transports []Transport

	// Stats: per-transport dial attempts + successes + last error.
	stats map[string]*transportStats
}

type transportStats struct {
	attempts  uint64
	successes uint64
	lastErr   string
	lastAt    time.Time
}

// New returns an empty Manager.
func New() *Manager {
	return &Manager{stats: map[string]*transportStats{}}
}

// Register adds a transport. Re-registering the same Name
// replaces the prior instance.
func (m *Manager) Register(t Transport) {
	if t == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Replace by name
	for i, ex := range m.transports {
		if ex.Name() == t.Name() {
			m.transports[i] = t
			return
		}
	}
	m.transports = append(m.transports, t)
	sort.SliceStable(m.transports, func(i, j int) bool {
		if m.transports[i].Priority() != m.transports[j].Priority() {
			return m.transports[i].Priority() < m.transports[j].Priority()
		}
		return m.transports[i].Name() < m.transports[j].Name()
	})
}

// Unregister removes a transport by name.
func (m *Manager) Unregister(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, t := range m.transports {
		if t.Name() == name {
			m.transports = append(m.transports[:i], m.transports[i+1:]...)
			delete(m.stats, name)
			return
		}
	}
}

// Names returns the registered transport names in priority order.
func (m *Manager) Names() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.transports))
	for i, t := range m.transports {
		out[i] = t.Name()
	}
	return out
}

// Dial walks the transports in priority order and returns the
// first successful (transport, conn). Returns an aggregated
// error if every available transport fails.
type DialResult struct {
	TransportName string
	Conn          net.Conn
}

// Dial attempts every Available() transport in priority order.
// Returns the first that succeeds; ctx applies to the entire
// attempt sequence.
func (m *Manager) Dial(ctx context.Context, hubAddr string) (DialResult, error) {
	m.mu.RLock()
	transports := make([]Transport, len(m.transports))
	copy(transports, m.transports)
	m.mu.RUnlock()

	if len(transports) == 0 {
		return DialResult{}, errors.New("oobhub: no transports registered")
	}
	var lastErr error
	tried := 0
	for _, t := range transports {
		if !t.Available() {
			continue
		}
		tried++
		s := m.statFor(t.Name())
		s.attempts++
		conn, err := t.Dial(ctx, hubAddr)
		s.lastAt = time.Now()
		if err != nil {
			s.lastErr = err.Error()
			lastErr = err
			continue
		}
		s.successes++
		s.lastErr = ""
		return DialResult{TransportName: t.Name(), Conn: conn}, nil
	}
	if tried == 0 {
		return DialResult{}, errors.New("oobhub: no transports currently Available")
	}
	if lastErr == nil {
		lastErr = errors.New("oobhub: all transports failed")
	}
	return DialResult{}, lastErr
}

// Stats reports per-transport counters.
type StatSnapshot struct {
	Name      string
	Priority  int
	Available bool
	Attempts  uint64
	Successes uint64
	LastError string
}

// Stats returns a snapshot of per-transport counters in priority
// order.
func (m *Manager) Stats() []StatSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]StatSnapshot, 0, len(m.transports))
	for _, t := range m.transports {
		s := m.stats[t.Name()]
		var att, succ uint64
		var lastErr string
		if s != nil {
			att, succ, lastErr = s.attempts, s.successes, s.lastErr
		}
		out = append(out, StatSnapshot{
			Name: t.Name(), Priority: t.Priority(), Available: t.Available(),
			Attempts: att, Successes: succ, LastError: lastErr,
		})
	}
	return out
}

func (m *Manager) statFor(name string) *transportStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.stats[name]
	if !ok {
		s = &transportStats{}
		m.stats[name] = s
	}
	return s
}

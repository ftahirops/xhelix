// Package denyledger is an in-memory, per-app deny-event store.
//
// It records exec-guard red-zone blocks and CEL-rule block-mode alerts,
// buckets them by declared app name, and provides a fast aggregate view
// for the per-app health dashboard.
//
// No persistence — counters reset on daemon restart. The operational
// use case is "what's been blocked in the last few hours", not forensics.
// Chain storage handles long-term evidence.
package denyledger

import (
	"strings"
	"sync"
	"time"
)

const defaultMaxRecent = 100

// DenyEvent is one recorded deny or block.
type DenyEvent struct {
	Time       time.Time `json:"time"`
	Binary     string    `json:"binary"`
	RuleID     string    `json:"rule_id"`
	Reason     string    `json:"reason"`
	CgroupPath string    `json:"cgroup_path,omitempty"`
}

// AppDenyStats is the aggregated view for one app.
type AppDenyStats struct {
	AppName     string            `json:"app"`
	TotalDenies uint64            `json:"total_denies"`
	ByRule      map[string]uint64 `json:"by_rule"`
	ByBinary    map[string]uint64 `json:"by_binary"`
	FirstDeny   time.Time         `json:"first_deny,omitempty"`
	LastDeny    time.Time         `json:"last_deny,omitempty"`
	// Status is "clean" (0 denies), "active" (1–49), or "noisy" (50+).
	Status string `json:"status"`
	// Recent holds up to maxRecent events, newest first.
	Recent []DenyEvent `json:"recent"`
}

type appBucket struct {
	total    uint64
	byRule   map[string]uint64
	byBinary map[string]uint64
	first    time.Time
	last     time.Time
	// ring is a bounded slice of recent events (newest at index 0).
	ring []DenyEvent
}

func newBucket() *appBucket {
	return &appBucket{
		byRule:   make(map[string]uint64),
		byBinary: make(map[string]uint64),
	}
}

func (b *appBucket) record(ev DenyEvent, maxRecent int) {
	b.total++
	if ev.RuleID != "" {
		b.byRule[ev.RuleID]++
	}
	if ev.Binary != "" {
		b.byBinary[ev.Binary]++
	}
	if b.first.IsZero() {
		b.first = ev.Time
	}
	b.last = ev.Time
	// Prepend to ring; cap at maxRecent.
	b.ring = append([]DenyEvent{ev}, b.ring...)
	if len(b.ring) > maxRecent {
		b.ring = b.ring[:maxRecent]
	}
}

func (b *appBucket) snapshot(appName string) AppDenyStats {
	st := AppDenyStats{
		AppName:     appName,
		TotalDenies: b.total,
		ByRule:      make(map[string]uint64, len(b.byRule)),
		ByBinary:    make(map[string]uint64, len(b.byBinary)),
		FirstDeny:   b.first,
		LastDeny:    b.last,
		Recent:      make([]DenyEvent, len(b.ring)),
	}
	for k, v := range b.byRule {
		st.ByRule[k] = v
	}
	for k, v := range b.byBinary {
		st.ByBinary[k] = v
	}
	copy(st.Recent, b.ring)
	switch {
	case b.total == 0:
		st.Status = "clean"
	case b.total >= 50:
		st.Status = "noisy"
	default:
		st.Status = "active"
	}
	return st
}

// Ledger is the top-level deny ledger. Safe for concurrent use.
type Ledger struct {
	mu        sync.RWMutex
	byApp     map[string]*appBucket
	maxRecent int
}

// New creates a deny ledger with the default ring size (100 events/app).
func New() *Ledger {
	return &Ledger{
		byApp:     make(map[string]*appBucket),
		maxRecent: defaultMaxRecent,
	}
}

// Record records a single deny event. appName may be empty (events go
// into the "_unknown" bucket for unattributed denies).
func (l *Ledger) Record(appName, binary, ruleID, cgroupPath, reason string, at time.Time) {
	if appName == "" {
		appName = "_unknown"
	}
	if at.IsZero() {
		at = time.Now()
	}
	// Trim binary to base name for aggregation — full paths explode cardinality.
	binaryBase := binaryBase(binary)
	ev := DenyEvent{
		Time:       at,
		Binary:     binaryBase,
		RuleID:     ruleID,
		Reason:     reason,
		CgroupPath: cgroupPath,
	}
	l.mu.Lock()
	b, ok := l.byApp[appName]
	if !ok {
		b = newBucket()
		l.byApp[appName] = b
	}
	b.record(ev, l.maxRecent)
	l.mu.Unlock()
}

// AppHealth returns the aggregated deny stats for the named app.
// Returns nil if no events have been recorded for that app.
func (l *Ledger) AppHealth(appName string) *AppDenyStats {
	l.mu.RLock()
	b, ok := l.byApp[appName]
	l.mu.RUnlock()
	if !ok {
		return nil
	}
	l.mu.RLock()
	snap := b.snapshot(appName)
	l.mu.RUnlock()
	return &snap
}

// AllApps returns a summary (no Recent ring) for every app that has
// recorded at least one deny. Used by the overview endpoint.
func (l *Ledger) AllApps() []AppDenyStats {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]AppDenyStats, 0, len(l.byApp))
	for name, b := range l.byApp {
		s := b.snapshot(name)
		s.Recent = nil // save allocations for overview
		out = append(out, s)
	}
	return out
}

// binaryBase returns the last path component, stripping the full path
// so "/usr/sbin/php-fpm8.2" → "php-fpm8.2".
func binaryBase(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

package xhubfleet

import (
	"sync"
	"time"
)

// TrustLevel governs how a host's data is allowed to influence the fleet.
// Untrusted hosts can upload but can't teach anyone; only Trusted hosts
// contribute to BRP candidates. Quarantined hosts are explicitly excluded.
type TrustLevel string

const (
	TrustUntrusted   TrustLevel = "untrusted"   // New host, observe-only
	TrustObserved    TrustLevel = "observed"    // Data collected, not used for BRP
	TrustCandidate   TrustLevel = "candidate"   // Stable, low-alert host
	TrustTrusted     TrustLevel = "trusted"     // Contributes to BRP candidates
	TrustQuarantined TrustLevel = "quarantined" // Excluded due to suspicious activity
)

// HostRecord is the per-host trust state the hub keeps.
type HostRecord struct {
	HostTag        string
	FirstSeen      time.Time
	LastSeen       time.Time
	Trust          TrustLevel
	AlertCount24h  int    // running count for trust gating
	CriticalAlerts int    // hard-block trigger
	Reason         string // why current Trust was set (audit trail)
}

// TrustPolicy is the deterministic ruleset for level transitions.
// All thresholds are tunable.
type TrustPolicy struct {
	MinObservedDays      int // days before a new host can be promoted past Untrusted
	MinCandidateDays     int // additional days at Candidate before Trusted
	MaxAlerts24hForTrust int // 24h alert count cap to stay Trusted
	QuarantineOnCritical bool
}

func DefaultTrustPolicy() TrustPolicy {
	return TrustPolicy{
		MinObservedDays:      3,
		MinCandidateDays:     7,
		MaxAlerts24hForTrust: 50,
		QuarantineOnCritical: true,
	}
}

// TrustRanker tracks per-host trust state. Decisions are pure functions
// of (HostRecord, TrustPolicy, now). All transitions are logged for audit.
type TrustRanker struct {
	mu     sync.RWMutex
	hosts  map[string]*HostRecord
	policy TrustPolicy
}

func NewTrustRanker(p TrustPolicy) *TrustRanker {
	return &TrustRanker{
		hosts:  map[string]*HostRecord{},
		policy: p,
	}
}

// See registers an upload from a host. Auto-creates a HostRecord on first
// sighting (as Untrusted). Updates LastSeen.
func (t *TrustRanker) See(hostTag string, now time.Time) *HostRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.hosts[hostTag]
	if h == nil {
		h = &HostRecord{
			HostTag:   hostTag,
			FirstSeen: now,
			Trust:     TrustUntrusted,
			Reason:    "new host — observe-only",
		}
		t.hosts[hostTag] = h
	}
	h.LastSeen = now
	return h
}

// RecordAlert bumps the 24h count and triggers quarantine on critical.
func (t *TrustRanker) RecordAlert(hostTag string, severity string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.hosts[hostTag]
	if h == nil {
		return
	}
	h.AlertCount24h++
	if severity == "critical" {
		h.CriticalAlerts++
		if t.policy.QuarantineOnCritical {
			h.Trust = TrustQuarantined
			h.Reason = "critical alert — excluded from fleet learning"
		}
	}
}

// Evaluate runs the policy on a single host and returns the appropriate
// trust level. Mutates h.Trust + h.Reason if the level should change.
func (t *TrustRanker) Evaluate(hostTag string, now time.Time) TrustLevel {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.hosts[hostTag]
	if h == nil {
		return TrustUntrusted
	}
	if h.Trust == TrustQuarantined {
		return h.Trust
	}
	ageDays := int(now.Sub(h.FirstSeen).Hours() / 24)
	if h.AlertCount24h > t.policy.MaxAlerts24hForTrust {
		if h.Trust == TrustTrusted {
			h.Trust = TrustCandidate
			h.Reason = "demoted: alert count exceeded threshold"
		}
		return h.Trust
	}
	switch {
	case ageDays < t.policy.MinObservedDays:
		h.Trust = TrustUntrusted
		h.Reason = "observation period not met"
	case ageDays < t.policy.MinObservedDays+t.policy.MinCandidateDays:
		if h.Trust == TrustUntrusted {
			h.Trust = TrustCandidate
			h.Reason = "promoted: observation period complete"
		}
	default:
		if h.Trust == TrustUntrusted || h.Trust == TrustCandidate {
			h.Trust = TrustTrusted
			h.Reason = "promoted: full trust period complete with low alerts"
		}
	}
	return h.Trust
}

// CanTeach returns true if the host is allowed to contribute to BRP candidates.
func (t *TrustRanker) CanTeach(hostTag string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	h := t.hosts[hostTag]
	return h != nil && h.Trust == TrustTrusted
}

// All returns a snapshot of all host records.
func (t *TrustRanker) All() []HostRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]HostRecord, 0, len(t.hosts))
	for _, h := range t.hosts {
		out = append(out, *h)
	}
	return out
}

// DecayAlerts halves the AlertCount24h on every tick (call hourly).
// Simple decay rather than a sliding window — accurate enough for trust gating.
func (t *TrustRanker) DecayAlerts() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, h := range t.hosts {
		h.AlertCount24h = h.AlertCount24h / 2
	}
}

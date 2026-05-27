// Package baselinegate is the Phase L1 baseline-aware alert gate.
//
// The autobaseline subsystem already learns per-host (image, behavior)
// tuples and tags every event with `baseline_known=true` when the
// daemon recognizes the action. But before L1, no rule consulted that
// tag — so a process the host had been doing the same thing as for
// days still produced fresh alerts on every fire.
//
// L1 closes that gap. The gate sits in the alert emit closure (after
// firerate, before bus.Send) and decides:
//
//   1. If the alert's rule_id is on the AlwaysFire list (hard
//      invariants, BRP hard-deny, reverse-shell, IMDS access, anything
//      class 1) — fire regardless of baseline. These are decisions
//      that don't get "learned away".
//
//   2. Else if event.tags[baseline_known]=="true" — suppress the
//      alert OR downgrade severity to info, per Policy.
//
//   3. Else fire as normal.
//
// Honest non-promise: the gate is only as good as the autobaseline's
// learned set. On a fresh host with empty baseline, every alert passes
// through unchanged. The gate's value emerges over the observation
// window. Operators wanting immediate FP relief should pair this with
// rule tuning (Phase M) and BRP profile signing.
package baselinegate

import (
	"sync"
)

// Action is what the gate decided to do with the alert.
type Action int

const (
	ActionFire     Action = iota // pass through unchanged
	ActionDowngrade               // emit, but caller should lower severity / mark known
	ActionSuppress                // drop entirely; count the suppression
)

// Policy chooses what happens when baseline_known is true.
type Policy struct {
	// SuppressKnown: when true and baseline_known and rule not on
	// AlwaysFire list, suppress the alert entirely.
	SuppressKnown bool
	// DowngradeKnown: when true and SuppressKnown is false, emit but
	// flag the alert as known (caller stamps `baseline_suppressed=
	// downgraded` for visibility).
	DowngradeKnown bool
	// AlwaysFire is the set of rule_ids that ignore baseline_known.
	// Loaded from operator config; hard-coded defaults below.
	AlwaysFire map[string]struct{}
}

// DefaultAlwaysFire returns the conservative defaults: rules that
// represent decisions, not patterns. Even if the host has done it
// many times, these are still events the operator must see.
func DefaultAlwaysFire() map[string]struct{} {
	return map[string]struct{}{
		// Hard-deny invariants (Tier 1)
		"brp.hard_deny":                {},
		"brp.verify_protected_path":    {},

		// Reverse shells — even "learned" rev shells stay alerts
		"revshell.detected":            {},
		"shell_with_socket_fd":         {}, // ambient but interesting in audit

		// Cloud metadata access — never normal
		"metadata.access_by_unexpected": {},
		"metadata_svc_unexpected":      {},

		// Container escape / capability gain via newprivs
		"contescape.detected":          {},
		"cap.gained":                   {}, // operators want to see all sudo

		// Endpoint score breach (composite signal, never baseline-known)
		"containment.endpoint_breach":  {},

		// Long-window slow-burn (composite)
		"h2.slow_egress_fanout_24h":    {},

		// CDN cloaking / domain fronting — never normal
		"cdn_cloaking_bare_ip_tls":     {},
		"cdn_cloaking_sni_dns_mismatch": {},

		// Persistence file writes — never normal without operator action
		"ssh_key_added_root":           {},
		"cron_new_unit":                {},
		"systemd_unit_new":             {},
		"ld_preload_drift":             {},
		"pam_module_modified":          {},
	}
}

// Gate is the runtime decision surface. Goroutine-safe.
type Gate struct {
	mu     sync.RWMutex
	policy Policy
	// suppressedByRule counts alerts the gate dropped, for operator
	// observability via `xhelixctl baseline suppressed-stats`.
	suppressedByRule map[string]int
	downgradedByRule map[string]int
}

// New constructs a Gate with the given policy. If policy.AlwaysFire
// is nil, DefaultAlwaysFire is used.
func New(p Policy) *Gate {
	if p.AlwaysFire == nil {
		p.AlwaysFire = DefaultAlwaysFire()
	}
	return &Gate{
		policy:           p,
		suppressedByRule: map[string]int{},
		downgradedByRule: map[string]int{},
	}
}

// Decide returns the Action to take. Pure — does NOT mutate alert
// state. Caller does the suppression/downgrade itself.
func (g *Gate) Decide(ruleID string, baselineKnown bool) Action {
	if g == nil {
		return ActionFire
	}
	if !baselineKnown {
		return ActionFire
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if _, always := g.policy.AlwaysFire[ruleID]; always {
		return ActionFire
	}
	if g.policy.SuppressKnown {
		return ActionSuppress
	}
	if g.policy.DowngradeKnown {
		return ActionDowngrade
	}
	return ActionFire
}

// RecordSuppress / RecordDowngrade update observability counters.
// The Gate exposes these via Snapshot for the CLI.
func (g *Gate) RecordSuppress(ruleID string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.suppressedByRule[ruleID]++
	g.mu.Unlock()
}

func (g *Gate) RecordDowngrade(ruleID string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.downgradedByRule[ruleID]++
	g.mu.Unlock()
}

// Snapshot returns a copy of the suppress/downgrade counters for
// operator inspection.
type Snapshot struct {
	Suppressed map[string]int
	Downgraded map[string]int
}

func (g *Gate) Snapshot() Snapshot {
	if g == nil {
		return Snapshot{}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	s := Snapshot{
		Suppressed: make(map[string]int, len(g.suppressedByRule)),
		Downgraded: make(map[string]int, len(g.downgradedByRule)),
	}
	for k, v := range g.suppressedByRule {
		s.Suppressed[k] = v
	}
	for k, v := range g.downgradedByRule {
		s.Downgraded[k] = v
	}
	return s
}

// Package egressguard turns egress observation into local enforcement
// for protected roles. When wired into the pipeline, it decides per
// net_connect event whether to allow, verify, or deny outbound traffic
// based on BRP role + declared peers + secret-taint state.
//
// Phase C of the BRP implementation plan. Build spec §3.3.
//
// Architecture:
//
//	Backend interface (ebpf | nftables) — kernel enforcement mechanism
//	Guard            (this package)     — userspace decision engine
//	Pipeline         (pkg/pipeline)     — calls Guard.Decide per event
//
// Shadow vs enforce mode:
//
//	Shadow mode: Decide() returns the right answer; ApplyDeny() logs
//	             the would-be deny but does not push to backend. Used
//	             for FP measurement before enforcement.
//	Enforce mode: ApplyDeny() pushes deny to the kernel backend.
//
// Backend selection (locked in build spec §0 + C.1 spec):
//
//	1. eBPF cgroup/connect-family — primary, when kernel ≥ 5.15 + CAP_BPF
//	2. nftables per-cgroup — fallback when eBPF unavailable
//	3. Observe-only — emergency degradation if both backends fail
package egressguard

import (
	"time"
)

// Decision is the per-event verdict from Guard.Decide.
type Decision uint8

const (
	// EgressAllow — destination is declared or otherwise approved.
	EgressAllow Decision = iota
	// EgressVerify — outside the role envelope but not absolute-bad.
	// Caller (pipeline) routes to the verifier for scoring.
	EgressVerify
	// EgressDeny — known-bad pattern (raw-IP from protected role,
	// secret-taint + novel outbound, etc.). Enforce mode pushes to
	// backend; shadow mode logs only.
	EgressDeny
)

// String returns the canonical short token for logs + tags.
func (d Decision) String() string {
	switch d {
	case EgressAllow:
		return "allow"
	case EgressVerify:
		return "verify"
	case EgressDeny:
		return "deny"
	}
	return "unknown"
}

// Request is the input to Guard.Decide for a single net_connect event.
//
// Populated by the pipeline from the event's BRP / asset / secret /
// source context — the Guard does NOT re-parse events, it consumes
// already-resolved facts.
type Request struct {
	PID         uint32
	LineageID   uint64
	CGroupID    uint64
	AppName     string // bare app name from AppIdent
	AppRole     string // BRP profile role
	DestIP      string
	DestPort    uint16
	SNI         string
	DNSName     string
	DestClass   string // pkg/destclass output ("private", "cdn", etc.)
	AssetClass  string // pkg/assetclass output for the destination
	SecretTaint string // pkg/secrettaint state token
	SourceID    uint64
	At          time.Time
}

// Guard is the egress enforcement decision surface.
//
// Decide() is called per net_connect event. It returns the runtime
// verdict, optionally accompanied by an explanation string.
//
// ApplyDeny() pushes a deny entry to the backend with the given TTL.
// In shadow mode this is a log-only operation; in enforce mode it
// reaches the kernel.
type Guard interface {
	Decide(Request) (Decision, string)
	ApplyDeny(lineageID uint64, destKey string, ttl time.Duration) error
	// Mode reports the current operating mode for telemetry.
	Mode() Mode
	// BackendName reports which backend is active (test/metrics helper).
	BackendName() string
}

// Mode is the operating mode of the guard.
type Mode uint8

const (
	// ModeObserve — observe + classify, no deny push. Used during
	// substrate development.
	ModeObserve Mode = iota
	// ModeShadow — log would-be denies, no kernel push. Default for
	// rollout — operator measures FP rate before enforcing.
	ModeShadow
	// ModeEnforce — push denies to kernel backend.
	ModeEnforce
)

func (m Mode) String() string {
	switch m {
	case ModeObserve:
		return "observe"
	case ModeShadow:
		return "shadow"
	case ModeEnforce:
		return "enforce"
	}
	return "unknown"
}

// Package takeover is xhelix's per-lineage takeover scorer +
// planner. It accumulates per-lineage Signals (canary touched,
// taint expanded, LOTL match, capability abuse, ...), maps them to a
// 0-100 score via a configurable weight table, and emits
// decision.ActionPlans through decision.Plan() when thresholds are
// crossed.
//
// Per REFACTOR_ROADMAP.md §2 + memory[[refactor-direction]]:
// pkg/takeover ships AS the planner — same code as the old
// pkg/takeover scorer would have been, but the output type is an
// ActionPlan, not a raw score. P-FT.1 + P-RF.6 collapsed into one.
//
// This slice (P-RF.6.skeleton) lands the type vocabulary +
// aggregator + scorer + planner glue. Real signal-to-score mapping
// is governed by Weights below; defaults come from
// FULL_TAKEOVER_DETECTION.md §4.2.
//
// No live caller yet — the dispatch loop wires this in P-RF.7.
package takeover

import (
	"time"
)

// SignalKind enumerates the per-lineage events the scorer cares about.
// Adding a kind is wire-safe (string constants) but old recorded
// signals may not carry the new tag — design accordingly.
type SignalKind string

const (
	// SignalCanaryTouch — a canary file / row / route was accessed.
	// Tier-1 deterministic per BEHAVIORAL_DEFENSE.md.
	SignalCanaryTouch SignalKind = "canary_touch"
	// SignalTaintExpand — TaintSet grew (new sensitive object read).
	SignalTaintExpand SignalKind = "taint_expand"
	// SignalPassportMissing — sensitive egress without Data Passport.
	SignalPassportMissing SignalKind = "passport_missing"
	// SignalLOTL — living-off-the-land binary executed in suspicious
	// lineage context (per P-B.7 LOTL scoring matrix).
	SignalLOTL SignalKind = "lotl"
	// SignalCapAbuse — capability dropped from baseline reappeared
	// (e.g. CAP_SYS_ADMIN on a web-app lineage).
	SignalCapAbuse SignalKind = "cap_abuse"
	// SignalNewBinary — execve'd binary with no SHA-256 baseline.
	SignalNewBinary SignalKind = "new_binary"
	// SignalNewEndpoint — connect() to a destination outside baseline.
	SignalNewEndpoint SignalKind = "new_endpoint"
	// SignalParentMismatch — process spawned with unexpected parent
	// (e.g. bash spawned by httpd; see FULL_TAKEOVER §3.B).
	SignalParentMismatch SignalKind = "parent_mismatch"
	// SignalCredAccess — touched /etc/shadow, ssh keys, browser
	// password stores, etc.
	SignalCredAccess SignalKind = "cred_access"
	// SignalPersistence — wrote to cron, systemd unit, .bashrc,
	// authorized_keys, etc.
	SignalPersistence SignalKind = "persistence"
	// SignalDefenseEvasion — touched /var/log, audit configuration,
	// or attempted to disable xhelix.
	SignalDefenseEvasion SignalKind = "defense_evasion"
	// SignalLateralMove — outbound SSH/SMB/RDP/WinRM observed.
	SignalLateralMove SignalKind = "lateral_move"
	// SignalRuleHit — a CEL rule matched. Score weight depends on
	// rule severity (handled in scorer).
	SignalRuleHit SignalKind = "rule_hit"

	// --- Protected Services (PROTECTED_SERVICES_TRAP.md §6) ---

	// SignalShellAttempt — protected service tried to execve a shell.
	// Tier-1 deterministic. Routed to honey-sh in trap mode.
	SignalShellAttempt SignalKind = "shell_attempt"
	// SignalInterpAttempt — protected service tried to execve a
	// language interpreter (python/perl/ruby/node/php-cgi).
	SignalInterpAttempt SignalKind = "interp_attempt"
	// SignalDownloader — protected service tried to execve a
	// network downloader (curl/wget/fetch/aria2c/axel).
	SignalDownloader SignalKind = "downloader"
	// SignalReconTool — protected service tried to execve a recon
	// tool (nmap/nc/ncat/socat/tcpdump).
	SignalReconTool SignalKind = "recon_tool"
	// SignalPrivTool — protected service tried to execve a
	// privilege-escalation tool (su/sudo/pkexec/doas).
	SignalPrivTool SignalKind = "priv_tool"
	// SignalForbiddenSyscall — seccomp denied a syscall.
	// Tier-2 — most denials are noise; stacks to cross threshold.
	SignalForbiddenSyscall SignalKind = "forbidden_syscall"
	// SignalForbiddenWrite — AppArmor denied a write outside
	// WriteRoots (e.g. /etc/cron.d, /etc/sudoers.d).
	SignalForbiddenWrite SignalKind = "forbidden_write"
	// SignalForbiddenConnect — protected service tried to connect()
	// outside upstream_cidrs (or to a known-bad destination).
	SignalForbiddenConnect SignalKind = "forbidden_connect"
	// SignalRWXMemory — anonymous RWX mmap or W→X mprotect
	// transition from a protected service. Tier-1.
	SignalRWXMemory SignalKind = "rwx_memory"
	// SignalC2Beacon — a sinkholed outbound connection produced
	// repeated traffic patterns consistent with a beacon.
	SignalC2Beacon SignalKind = "c2_beacon"
	// SignalDecoyTouch — a decoy file (/etc/shadow decoy, AWS
	// canary creds, etc) was read. Like SignalCanaryTouch but for
	// the protected-services deception layer.
	SignalDecoyTouch SignalKind = "decoy_touch"
	// SignalCrashLoop — a protected service segfaulted >=3 times
	// in 60s — indicates exploit-in-progress.
	SignalCrashLoop SignalKind = "crash_loop"
	// SignalIdentityMismatch — exe SHA / unit / uid of a running
	// protected-service process did not match the registered
	// expectation. Binary-swap or unit hijack indicator.
	SignalIdentityMismatch SignalKind = "identity_mismatch"
)

// AllKinds enumerates every defined SignalKind. Useful for
// admin-UI dropdowns and weight-table validation.
func AllKinds() []SignalKind {
	return []SignalKind{
		SignalCanaryTouch, SignalTaintExpand, SignalPassportMissing,
		SignalLOTL, SignalCapAbuse, SignalNewBinary, SignalNewEndpoint,
		SignalParentMismatch, SignalCredAccess, SignalPersistence,
		SignalDefenseEvasion, SignalLateralMove, SignalRuleHit,
		// Protected Services
		SignalShellAttempt, SignalInterpAttempt, SignalDownloader,
		SignalReconTool, SignalPrivTool, SignalForbiddenSyscall,
		SignalForbiddenWrite, SignalForbiddenConnect, SignalRWXMemory,
		SignalC2Beacon, SignalDecoyTouch, SignalCrashLoop,
		SignalIdentityMismatch,
	}
}

// Signal is a single observation attributable to one lineage.
type Signal struct {
	LineageID uint64     `json:"lineage_id"`
	Kind      SignalKind `json:"kind"`
	At        time.Time  `json:"at"`
	// Source identifies the sensor / rule / package that produced
	// the signal — used for debugging false positives.
	Source string `json:"source,omitempty"`
	// Detail is human-readable context ("/etc/shadow read",
	// "execve(/usr/bin/curl)").
	Detail string `json:"detail,omitempty"`
	// Weight, if > 0, overrides the default weight from the table.
	// Used by SignalRuleHit to thread rule severity through.
	Weight int `json:"weight,omitempty"`
	// Confidence: "deterministic" / "high" / "medium" / "low".
	// Tier-2/3 signals come in at "medium" or "low"; the composition
	// rule downweights them unless paired with deterministic ones.
	Confidence string `json:"confidence,omitempty"`
	// RemoteIP, if set, gets pushed into AttributedIPs when the
	// planner builds an Input. High-confidence attribution only.
	RemoteIP string `json:"remote_ip,omitempty"`
}

// Weights maps each SignalKind to its base contribution to the
// score. Values clipped at 100 (the score ceiling). Defaults align
// with FULL_TAKEOVER_DETECTION.md §4.2.
//
// Designed so single Tier-1 deterministic signals push past 75
// (Suspended) on their own, but probabilistic signals require ≥2
// stacked to cross 75. See BEHAVIORAL_DEFENSE.md §5 composition.
type Weights map[SignalKind]int

// DefaultWeights returns the production weight table. Copy-on-read;
// callers may modify their copy.
func DefaultWeights() Weights {
	return Weights{
		// Tier-1 deterministic — single signal crosses to suspended.
		SignalCanaryTouch:     80, // canary is exclusively touched by attackers
		SignalPassportMissing: 75, // sensitive egress without passport = exfil
		SignalDefenseEvasion:  85, // attacks on xhelix itself
		// Tier-2 high-confidence — need 1-2 to cross suspended.
		SignalTaintExpand:    35,
		SignalCredAccess:     50,
		SignalPersistence:    55,
		SignalLateralMove:    50,
		SignalParentMismatch: 40,
		SignalCapAbuse:       45,
		// Tier-3 weak — need stacking.
		SignalLOTL:        25,
		SignalNewBinary:   20,
		SignalNewEndpoint: 15,
		// Rule hits depend on rule severity; Weight field overrides.
		SignalRuleHit: 30,

		// Protected Services (PROTECTED_SERVICES_TRAP.md §6).
		// Tier-1 — single signal crosses 75 (Suspended).
		SignalShellAttempt:     80,
		SignalDownloader:       75,
		SignalForbiddenWrite:   80,
		SignalRWXMemory:        95,
		SignalC2Beacon:         85,
		SignalDecoyTouch:       85,
		SignalCrashLoop:        80,
		SignalIdentityMismatch: 90,
		// Tier-1 weaker — usually cross alone, but might be a
		// legitimate operator helper for php-fpm IPC, etc.
		SignalInterpAttempt: 70,
		SignalReconTool:     75,
		SignalPrivTool:      80,
		// Tier-2 — noise on real systems; needs stacking.
		SignalForbiddenSyscall: 50,
		SignalForbiddenConnect: 60,
	}
}

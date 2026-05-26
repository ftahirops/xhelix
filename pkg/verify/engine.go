// Package verify is the Tier-2 verification engine (T07).
//
// Architectural role:
//
//	BRP runtime classifies a single event as Allow / Verify / HardDeny.
//	Verify decisions are NOT final — they declare "this event deviates
//	from the profile envelope and needs corroborating analysis." This
//	package is where that analysis happens.
//
//	The verifier runs an event through N independent scoring domains
//	(path classification, source lineage, integrity verdict, behavior
//	history, network novelty, hash baseline, phase, cross-app) and
//	combines them into a calibrated likelihood-ratio (LLR) score. The
//	final outcome is one of:
//
//	  Benign     — score below the low threshold; suppress alert
//	  Suspicious — score in the middle band; surface at Class=3
//	  Promote    — score above the high threshold; re-promote to HardDeny
//
// Status — first cut (2026-05-23):
//
//	Domains shipped:
//	  ✅ PathClassifier — protected-path tier weighting
//
//	Domains stubbed (planned T07 follow-ons):
//	  ⏳ SourceLineage — actor anchor / IP source weighting
//	  ⏳ IntegrityHash — pkg/integrity verdict comparison
//	  ⏳ BehaviorHistory — baseline aggregator deviation
//	  ⏳ NetworkNovelty — egressmon novelty score
//	  ⏳ PhaseScore — phase tracker correlation
//	  ⏳ CrossApp — multi-process call-chain
//	  ⏳ HashBaseline — integrity baseline DB lookup
//
//	One domain is enough to demonstrate the wiring + provide measurable
//	additional protection beyond raw BRP. Subsequent domains plug in
//	without changing the Engine surface.
package verify

import (
	"strings"

	"github.com/xhelix/xhelix/pkg/brp"
)

// Outcome is the verifier's final say on a Verify-decision event.
type Outcome uint8

const (
	OutcomeUnknown    Outcome = iota
	OutcomeBenign             // score < lowThreshold → suppress
	OutcomeSuspicious         // lowThreshold ≤ score < highThreshold → surface
	OutcomePromote            // score ≥ highThreshold → re-promote to HardDeny
)

func (o Outcome) String() string {
	switch o {
	case OutcomeBenign:
		return "benign"
	case OutcomeSuspicious:
		return "suspicious"
	case OutcomePromote:
		return "promote"
	}
	return "unknown"
}

// Result carries the verifier's verdict plus per-domain breakdown for
// audit. The Score is the summed LLR contribution from all enabled
// domains; reasons explain how it was reached.
type Result struct {
	Outcome     Outcome
	Score       float64
	Domains     map[string]float64 // per-domain contribution
	Reason      string
}

// Engine is the verifier substrate. Domains are evaluated in sequence
// against an Input; each domain returns an LLR contribution and a
// human reason. The engine sums contributions and bucketizes via
// LowThreshold / HighThreshold.
//
// Safe for concurrent use — Engine is stateless modulo configuration.
type Engine struct {
	LowThreshold  float64
	HighThreshold float64
	domains       []Domain
}

// Input is what each Domain sees. It carries the original BRP facts
// plus auxiliary context the verifier resolves on its own. Domains
// MUST NOT mutate Input.
type Input struct {
	Facts     brp.EventFacts
	Decision  brp.Decision // BRP's tentative decision (always Verify when called)
	BRPReason string       // BRP's reason for the Verify

	// Auxiliary scoring context — populated by the pipeline when
	// available, zero-value means "domain has no input from this signal".

	// Phase is the actor's current lifecycle phase: "bootstrap", "steady",
	// "reload", "degraded", or "" (unknown).
	Phase string
	// SourceAnchorID, when non-zero, identifies the originating
	// SourceAnchor — used by SourceLineage domain to weight anchored
	// vs un-anchored activity.
	SourceAnchorID uint64
	// AnchorKind reports the anchor type (ssh / pam / sudo / cron /
	// systemd / host). Operator-initiated anchors (pam,sudo,ssh) are
	// far less suspicious than host-anchored writes to protected paths.
	AnchorKind string
	// BaselineKnown signals whether the autobaseline aggregator has
	// previously observed this (image, behavior) pair from the host.
	BaselineKnown bool
	// IntegrityAuthentic mirrors brp.TrustSignals.IntegrityAuthentic —
	// duplicated here so the IntegrityHash domain can read without
	// reaching into Facts.Trust.
	IntegrityAuthentic bool
	// DestClass is the egress-observer classification for net_connect
	// events: "known_upstream" / "novel_external" / "rare_endpoint" / "".
	DestClass string
	// JITAllowlisted: actor matched a JIT runtime allowlist (node, java,
	// python, etc.) — broader behavior is expected, attenuate score.
	JITAllowlisted bool

	// ActorApp is the bare app name of the actor process (e.g. "nginx",
	// "php-fpm", "mysql"). Populated from ev.Tags["app_name"].
	ActorApp string
	// TargetApp is the bare app name of the destination — for net_connect
	// it is resolved from the destination host/port via the egress observer
	// or vhost correlator; for spawn it is the target image's basename.
	// Empty when no destination context is available.
	TargetApp string
	// EdgeAllowed is true when the (ActorApp, TargetApp, action, dest)
	// tuple matches an explicitly-signed Edge in the daemon's EdgeSet.
	// When true the CrossApp domain attenuates the score by an additional
	// -2.0 — operator-signed edges are the strongest cross-app trust
	// signal we have.
	EdgeAllowed bool

	// AssetClass is the canonical asset taxonomy class for the event's
	// target (pkg/assetclass). Populated by the pipeline from
	// ev.Tags["asset_class"]. Empty for events without classifiable
	// target context. Read by the AssetContext domain.
	AssetClass string

	// SecretTaint is the current taint state for the actor's lineage
	// (pkg/secrettaint), as a string token: "secret_touched" /
	// "outbound_restricted" / "containment_required" / "" for clean.
	// Populated by the pipeline from ev.Tags["secret_taint"]. Read by
	// the SecretContext domain.
	SecretTaint string

	// SecretClasses is the set of secret classes the actor's lineage
	// has touched. Populated from secrettaint.Store.ClassesForLineage.
	// Read by the SecretContext domain for class-weighted scoring.
	SecretClasses []string
}

// Domain is one scoring axis. Returns:
//   - score: LLR contribution (positive = more suspicious, negative = less)
//   - reason: short human explanation, included in audit
type Domain interface {
	Name() string
	Score(in Input) (score float64, reason string)
}

// NewEngine returns an Engine with default thresholds calibrated for the
// shipped domains. Operators can tune via configuration.
//
// Shipped domains (2026-05-24):
//
//	PathClassifier     — protected-path tier weighting (+1..+5)
//	PhaseCorrelation   — bootstrap = -1.5 (lenient), degraded = +2 (strict)
//	SourceLineage      — operator-anchored = -2.0 (lenient), host-anchored = +1
//	IntegrityHash      — Authentic upgrade verdict = -3 (lenient)
//	BehaviorHistory    — baseline_known = -2 (lenient)
//	NetworkNovelty     — known_upstream = -1, novel_external = +2
//	JITAttenuation     — JIT runtime allowlisted = -1 (lenient)
//
// With LowThreshold=1.0 and HighThreshold=4.0 this means:
//   - /etc/cron.d/ write from unattributed actor → 3.0 → suspicious
//   - /etc/shadow write from unattributed actor → 5.0 → promote
//   - /etc/shadow write by authenticated dpkg upgrade → 5 - 3 = 2.0 → suspicious
//   - /etc/shadow write by dpkg with baseline_known → 5 - 3 - 2 = 0.0 → benign
func NewEngine() *Engine {
	return &Engine{
		LowThreshold:  1.0,
		HighThreshold: 4.0,
		domains: []Domain{
			PathClassifier{},
			PhaseCorrelation{},
			SourceLineage{},
			IntegrityHash{},
			BehaviorHistory{},
			NetworkNovelty{},
			JITAttenuation{},
			CrossApp{},
			SecretContext{}, // Phase B.3 — taint-aware scoring
			AssetContext{},  // Phase B.3 — asset-class-aware scoring
		},
	}
}

// AddDomain registers an additional scoring domain. Domains are evaluated
// in registration order; ordering does not affect final score.
func (e *Engine) AddDomain(d Domain) {
	e.domains = append(e.domains, d)
}

// Evaluate runs all domains and returns the consolidated Result.
func (e *Engine) Evaluate(in Input) Result {
	r := Result{Domains: map[string]float64{}}
	var reasons []string
	for _, d := range e.domains {
		s, why := d.Score(in)
		r.Score += s
		r.Domains[d.Name()] = s
		if why != "" {
			reasons = append(reasons, d.Name()+": "+why)
		}
	}
	switch {
	case r.Score >= e.HighThreshold:
		r.Outcome = OutcomePromote
	case r.Score >= e.LowThreshold:
		r.Outcome = OutcomeSuspicious
	default:
		r.Outcome = OutcomeBenign
	}
	r.Reason = strings.Join(reasons, "; ")
	return r
}

// PathClassifier is the first verifier domain. It weights protected-path
// writes by how critical the path is to host security. The list mirrors
// pkg/brp.ProtectedSystemPaths but applies graduated weights instead of
// a single boolean.
//
// Weight rationale:
//
//	5.0 — credential / authorization backbone (corrupting these = total
//	      host compromise: /etc/shadow, /etc/sudoers, /root/.ssh)
//	3.0 — service / boot / persistence (custom systemd unit, cron entry,
//	      kernel module)
//	2.0 — package manager state (corruption breaks updates but doesn't
//	      immediately compromise auth)
//	1.0 — network/mount config (resolv.conf, hosts, fstab)
type PathClassifier struct{}

func (PathClassifier) Name() string { return "path_classifier" }

func (PathClassifier) Score(in Input) (float64, string) {
	if in.Facts.Path == "" {
		return 0, ""
	}
	path := in.Facts.Path

	// Tier 5 — credential backbone (most critical)
	tier5 := []string{
		"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/",
		"/etc/pam.d/", "/etc/security/", "/root/.ssh/", "/etc/ssh/sshd_config",
		"/etc/ssh/sshd_config.d/", "/etc/ssh/ssh_host_",
	}
	for _, p := range tier5 {
		if strings.HasPrefix(path, p) {
			return 5.0, "credential backbone (" + p + ")"
		}
	}

	// Tier 3 — service / persistence / boot
	tier3 := []string{
		"/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
		"/etc/cron.weekly/", "/etc/cron.monthly/", "/etc/crontab",
		"/var/spool/cron/", "/boot/", "/lib/modules/", "/usr/lib/modules/",
		"/etc/systemd/network/",
	}
	for _, p := range tier3 {
		if strings.HasPrefix(path, p) {
			return 3.0, "service/persistence (" + p + ")"
		}
	}

	// Tier 2 — database storage + package manager
	tier2 := []string{
		"/var/lib/mysql/", "/var/lib/postgresql/", "/var/lib/mariadb/",
		"/var/lib/mongodb/", "/var/lib/redis/",
		"/var/lib/dpkg/", "/var/lib/rpm/", "/var/lib/apt/lists/",
		"/var/cache/apt/archives/",
		"/etc/psa/", "/usr/local/psa/", "/var/lib/psa/", "/opt/psa/",
	}
	for _, p := range tier2 {
		if strings.HasPrefix(path, p) {
			return 2.0, "database/pkg-state (" + p + ")"
		}
	}

	// Tier 1 — network / mount config
	tier1 := []string{
		"/etc/passwd", "/etc/fstab", "/etc/hosts", "/etc/hostname",
		"/etc/resolv.conf", "/etc/network/", "/etc/netplan/",
		"/etc/NetworkManager/",
	}
	for _, p := range tier1 {
		if strings.HasPrefix(path, p) {
			return 1.0, "network/mount config (" + p + ")"
		}
	}
	return 0, ""
}

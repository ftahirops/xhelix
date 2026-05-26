package brp

import (
	"encoding/json"
	"fmt"
	"time"

	parser "github.com/xhelix/xhelix/pkg/brp/parser"
)

// SchemaVersion is the current BRP file format version. Bumped any time
// the wire-format Profile struct changes in a way that requires the
// matcher to read it differently. Old profiles with a strictly-lower
// SchemaVersion are still loadable; newer profiles are rejected by
// older xhelix binaries to prevent silent misinterpretation.
const SchemaVersion = 1

// ConfidenceClass classifies how much the runtime should trust a
// resolved profile. From the v2 BRP architecture doc:
//
//   - Strict: exact (app, version, OS, role, features) match against a
//     curated, signed, fleet-consensus profile. Verifier treats the
//     profile as authoritative for the L1 envelope.
//
//   - StableFallback: nearest compatible version family matched. The
//     verifier still uses the profile but applies a confidence penalty
//     to its assertions (an out-of-envelope event scores lower than it
//     would under Strict).
//
//   - ConstrainedAdaptation: local config has changed since the profile
//     was published (config-fingerprint mismatch). A bounded overlay is
//     learned locally; hard-deny invariants stay in force.
//
//   - Unprofiled: no matching profile at all. The verifier handles the
//     binary conservatively — log-only / shadow-mode, no enforcement
//     decisions derived from the (non-existent) envelope.
type ConfidenceClass uint8

const (
	ConfidenceUnknown ConfidenceClass = iota
	ConfidenceStrict
	ConfidenceStableFallback
	ConfidenceConstrainedAdaptation
	ConfidenceUnprofiled
)

// String returns the canonical short token for logs and JSON output.
func (c ConfidenceClass) String() string {
	switch c {
	case ConfidenceStrict:
		return "strict"
	case ConfidenceStableFallback:
		return "stable_fallback"
	case ConfidenceConstrainedAdaptation:
		return "constrained_adaptation"
	case ConfidenceUnprofiled:
		return "unprofiled"
	}
	return "unknown"
}

// MarshalJSON renders as the short token (not the int).
func (c ConfidenceClass) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// UnmarshalJSON accepts the short tokens above.
func (c *ConfidenceClass) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch s {
	case "strict":
		*c = ConfidenceStrict
	case "stable_fallback":
		*c = ConfidenceStableFallback
	case "constrained_adaptation":
		*c = ConfidenceConstrainedAdaptation
	case "unprofiled":
		*c = ConfidenceUnprofiled
	case "unknown", "":
		*c = ConfidenceUnknown
	default:
		return fmt.Errorf("unknown confidence class %q", s)
	}
	return nil
}

// Profile is the wire-format BRP record. It carries (a) the
// identification key bucketing fleet samples and (b) the
// ConfigDerivedBehavior envelope describing what the app may legitimately
// do at runtime. Profiles are produced by the curator (hub-side
// aggregation reviewed by humans, signed by HSM) or by an operator's
// local key for custom-app overlays.
type Profile struct {
	SchemaVersion int                              `json:"schema_version"`
	ProfileID     string                           `json:"profile_id"`     // e.g. "brp-nginx-1.24.0-debian12-reverse-proxy-v3"
	Confidence    ConfidenceClass                  `json:"confidence"`
	SampleCount   int                              `json:"sample_count"`   // hosts contributing to the consensus
	FleetCount    int                              `json:"fleet_count"`    // total hosts in the bucket
	SigningEpoch  int64                            `json:"signing_epoch"`  // unix nanos when this profile was signed
	VersionRange  string                           `json:"version_range"`  // "1.24.0" (Strict) / "1.24.x" (StableFallback)
	Key           parser.ProfileKey                `json:"key"`
	Behavior      parser.ConfigDerivedBehavior     `json:"behavior"`
	SourceFiles   []string                         `json:"source_files,omitempty"` // origin config paths
}

// SignedProfile wraps Profile with a detached-payload signature so the
// canonical Profile bytes can be re-derived for verification. The
// signature covers a fixed JSON serialization (sorted keys; no
// indentation; UTF-8) so two implementations produce identical bytes
// for the same Profile value.
type SignedProfile struct {
	Profile   Profile `json:"profile"`
	Signer    string  `json:"signer"`    // "xhelix-project" or operator key id
	Algorithm string  `json:"algorithm"` // "ed25519" — fixed for v1
	Signature string  `json:"signature"` // base64-std signature bytes
}

// CanonicalBytes returns the deterministic byte sequence over which the
// signature is computed. Two semantically-identical Profile values
// must produce byte-identical output regardless of map iteration order
// or struct field order. The current implementation relies on:
//
//   - encoding/json's struct-field-order being source-order (Go spec)
//   - parser.ConfigDerivedBehavior's slices being normalised (sorted+deduped)
//     by the parser before signing — which they are
//
// If future fields use map[string]X, this function MUST be revised
// to walk maps in sorted-key order.
func (p Profile) CanonicalBytes() ([]byte, error) {
	return json.Marshal(p)
}

// Validate runs structural checks on a Profile. Returns the first
// problem found, or nil. Called by LoadProfile before signature
// verification (no point verifying a structurally-broken profile).
//
// In particular: a profile whose declared WriteRoots or ExecAllowed
// intersect ProtectedSystemPaths is REJECTED, regardless of who
// signed it. The "protect-our-own" backstop runs ahead of trust.
func (p Profile) Validate() error {
	if p.SchemaVersion == 0 {
		return fmt.Errorf("schema_version is required")
	}
	if p.SchemaVersion > SchemaVersion {
		return fmt.Errorf("schema_version %d newer than supported %d", p.SchemaVersion, SchemaVersion)
	}
	if p.ProfileID == "" {
		return fmt.Errorf("profile_id is required")
	}
	if p.Confidence == ConfidenceUnknown {
		return fmt.Errorf("confidence class is required")
	}
	if p.Key.App == "" {
		return fmt.Errorf("key.app is required")
	}
	if p.SigningEpoch == 0 {
		return fmt.Errorf("signing_epoch is required")
	}
	if p.SigningEpoch < 0 {
		return fmt.Errorf("signing_epoch must be positive")
	}
	if t := time.Unix(0, p.SigningEpoch); t.After(time.Now().Add(24 * time.Hour)) {
		return fmt.Errorf("signing_epoch %s is more than 24h in the future", t)
	}

	// PROTECT-OUR-OWN backstop. A signed profile is NOT trusted to
	// override the immutable protected-paths list.
	if hit := IntersectsProtected(p.Behavior.WriteRoots); hit != "" {
		return fmt.Errorf("profile WriteRoots intersect protected path %q", hit)
	}
	if hit := IntersectsProtected(p.Behavior.ExecAllowed); hit != "" {
		return fmt.Errorf("profile ExecAllowed intersect protected path %q", hit)
	}
	return nil
}

// QualityWarnings returns non-fatal warnings about profile shape that
// suggest the profile is wider than typical or missing common fields.
// Operators see these at generate-time so they can tighten the profile
// before it ships; the daemon does NOT reject profiles for these.
//
// Warnings:
//
//	- excessive WriteRoots (> 10 entries) suggests the envelope is too broad
//	- empty UpstreamHosts for nginx/apache/php-fpm suggests no egress is declared
//	  (means the role can talk to ANY destination — Phase C egressguard
//	  will treat this as undeclared and deny everything)
//	- ExecAllowed contains shells/interpreters for web/db roles
//	- empty ListenPorts for nginx/apache suggests the server has no
//	  declared listening surface
func (p Profile) QualityWarnings() []string {
	var ws []string

	if n := len(p.Behavior.WriteRoots); n > 10 {
		ws = append(ws, fmt.Sprintf(
			"WriteRoots has %d entries; envelope is likely too broad — review and tighten",
			n))
	}

	// Empty UpstreamHosts on a role that typically has upstreams.
	switch p.Key.App {
	case "nginx", "apache", "php-fpm":
		if len(p.Behavior.UpstreamHosts) == 0 && len(p.Behavior.UpstreamSockets) == 0 {
			ws = append(ws, fmt.Sprintf(
				"%s profile has no declared UpstreamHosts/UpstreamSockets — Phase C egressguard will deny all outbound for this role",
				p.Key.App))
		}
	}

	// Shells/interpreters in ExecAllowed for web/db roles.
	dangerousExecs := []string{
		"/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/sh", "/usr/bin/bash",
		"/usr/bin/python", "/usr/bin/python3", "/usr/bin/perl",
		"/usr/bin/ruby", "/usr/bin/nc",
	}
	webOrDB := map[string]bool{
		"nginx-static": true, "nginx-reverse-proxy": true, "nginx-fastcgi": true,
		"nginx-lua": true, "nginx-njs": true, "nginx-grpc-proxy": true,
		"apache-static": true, "apache-reverse-proxy": true, "apache-cgi": true,
		"apache-fastcgi": true, "apache-wsgi": true,
		"mysql-default": true, "mysql-primary": true, "mysql-replica": true,
		"mysql-galera": true,
	}
	if webOrDB[p.Key.Role] {
		for _, allowed := range p.Behavior.ExecAllowed {
			for _, d := range dangerousExecs {
				if allowed == d {
					ws = append(ws, fmt.Sprintf(
						"role %q ExecAllowed contains %q — this contradicts the role invariant and the runtime will hard_deny it",
						p.Key.Role, d))
				}
			}
		}
	}

	// Web servers with no listen ports.
	switch p.Key.App {
	case "nginx", "apache":
		if len(p.Behavior.ListenPorts) == 0 && len(p.Behavior.ListenSockets) == 0 {
			ws = append(ws, fmt.Sprintf(
				"%s profile has no declared ListenPorts/ListenSockets — verify config parsed correctly",
				p.Key.App))
		}
	}

	return ws
}

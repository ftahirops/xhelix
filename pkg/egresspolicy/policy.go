// Package egresspolicy is the per-binary outbound network policy
// engine. Each binary can have a signed Policy YAML at
// /etc/xhelix/policies/<binary-sanitized>.yaml. The engine evaluates
// every net_connect event against the matching policy and returns
// one of: ALLOW | OBSERVE | VERIFY | DENY.
//
// Default mode is OBSERVE for any binary without a signed policy —
// the engine records what would have happened but takes no action.
//
// Week 3 scope: schema + storage + runtime evaluation. The Sign /
// Verify path uses an operator-local Ed25519 key (loaded from
// /etc/xhelix/policies/operator.pub). HSM-backed signing is a
// future iteration. The observe→sign workflow CLI ships in Week 4;
// this package's CLI surface is read+keygen only.
package egresspolicy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the current Policy file format. Bump when wire format
// changes incompatibly.
const SchemaVersion = 1

// AlgorithmEd25519 is the only signature algorithm supported in v1.
const AlgorithmEd25519 = "ed25519"

// Mode is the per-binary enforcement posture.
type Mode string

const (
	// ModeObserve: every connect is recorded; no action taken. Default
	// for binaries without a signed policy.
	ModeObserve Mode = "observe"
	// ModeAllowAny: explicitly allowed to do anything (e.g. apt, dpkg).
	ModeAllowAny Mode = "allow_any"
	// ModeDenyDefault: deny everything except listed allow rules.
	// The portmaster-strict mode.
	ModeDenyDefault Mode = "deny_default"
	// ModeTorOnly: allowed only when connecting to a tor SOCKS proxy
	// (127.0.0.1:9050 by default). Anything else denies.
	ModeTorOnly Mode = "tor_only"
)

// torLoopback is the canonical local Tor SOCKS endpoint. ModeTorOnly
// permits exactly this destination and denies everything else.
var (
	torLoopback4 = net.ParseIP("127.0.0.1").To4()
	torLoopback6 = net.ParseIP("::1")
	torPort      = uint16(9050)
)

// Policy is the per-binary rule set the operator signs.
type Policy struct {
	SchemaVersion int       `yaml:"schema_version" json:"schema_version"`
	Binary        string    `yaml:"binary"         json:"binary"`
	Mode          Mode      `yaml:"mode"           json:"mode"`
	SignedAt      time.Time `yaml:"signed_at"      json:"signed_at"`
	Signer        string    `yaml:"signer"         json:"signer"`
	Comment       string    `yaml:"comment,omitempty" json:"comment,omitempty"`

	// Allow rules. Evaluated in declaration order; first match wins
	// for ALLOW. Empty for ModeAllowAny / ModeObserve.
	Allow []Rule `yaml:"allow,omitempty" json:"allow,omitempty"`

	// Deny rules. Same evaluation order. Matches override Allow.
	Deny []Rule `yaml:"deny,omitempty" json:"deny,omitempty"`

	// Optional scope: applies the policy only when the subject's
	// uid / cgroup_class matches. Empty = applies to all subjects
	// that exec this binary.
	OnlyUIDs      []uint32 `yaml:"only_uids,omitempty"      json:"only_uids,omitempty"`
	OnlyCgroups   []string `yaml:"only_cgroups,omitempty"   json:"only_cgroups,omitempty"`
	ExceptUIDs    []uint32 `yaml:"except_uids,omitempty"    json:"except_uids,omitempty"`
	ExceptCgroups []string `yaml:"except_cgroups,omitempty" json:"except_cgroups,omitempty"`
}

// Rule is one matching condition. All non-empty fields must match
// for the rule to fire (AND semantics).
type Rule struct {
	DestCIDR  string   `yaml:"dest_cidr,omitempty"  json:"dest_cidr,omitempty"`
	DestClass string   `yaml:"dest_class,omitempty" json:"dest_class,omitempty"`
	Country   string   `yaml:"country,omitempty"    json:"country,omitempty"`
	ASN       string   `yaml:"asn,omitempty"        json:"asn,omitempty"`
	Ports     []uint16 `yaml:"ports,omitempty"      json:"ports,omitempty"`
	Protocols []string `yaml:"protocols,omitempty"  json:"protocols,omitempty"`
	SNI       string   `yaml:"sni,omitempty"        json:"sni,omitempty"`
	DNSName   string   `yaml:"dns_name,omitempty"   json:"dns_name,omitempty"`
	Comment   string   `yaml:"comment,omitempty"    json:"comment,omitempty"`
}

// Decision is the engine's output for one connect event.
type Decision struct {
	Action    Action
	Mode      Mode
	PolicyID  string // binary name that produced this decision
	MatchedBy string // human-readable rule pointer ("allow[2]: dest_class=cloudflare")
	Reason    string
}

// Action is the runtime verdict.
type Action uint8

const (
	ActionAllow   Action = iota // pass through
	ActionObserve               // record but pass (no policy or observe mode)
	ActionVerify                // route to verifier (BRP scoring)
	ActionDeny                  // egressguard installs deny
)

// String returns the lowercase wire form of an Action ("allow",
// "observe", "verify", "deny"). Used for event tag stamping.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionObserve:
		return "observe"
	case ActionVerify:
		return "verify"
	case ActionDeny:
		return "deny"
	default:
		return "observe"
	}
}

// Request is the input the pipeline passes to Decide.
type Request struct {
	Binary    string
	UID       uint32
	Cgroup    string
	DestIP    net.IP
	DestPort  uint16
	Protocol  string
	SNI       string
	DNSName   string
	DestClass string
	Country   string
	ASN       string
}

// SignedPolicy wraps a Policy with detached signature.
type SignedPolicy struct {
	Policy    Policy `yaml:"policy"    json:"policy"`
	Signer    string `yaml:"signer"    json:"signer"`
	Algorithm string `yaml:"algorithm" json:"algorithm"`
	Signature string `yaml:"signature" json:"signature"`
}

// Validate sanity-checks a Policy independent of any signature.
// Returns an error explaining the first structural problem found.
func (p Policy) Validate() error {
	if p.SchemaVersion == 0 {
		return errors.New("schema_version is required")
	}
	if p.SchemaVersion > SchemaVersion {
		return fmt.Errorf("schema_version %d newer than this binary supports (max %d)", p.SchemaVersion, SchemaVersion)
	}
	if p.Binary == "" {
		return errors.New("binary is required")
	}
	switch p.Mode {
	case ModeObserve, ModeAllowAny, ModeDenyDefault, ModeTorOnly:
	default:
		return fmt.Errorf("unknown mode %q", p.Mode)
	}
	if p.Signer == "" {
		return errors.New("signer is required")
	}
	for i, r := range p.Allow {
		if err := r.validate(); err != nil {
			return fmt.Errorf("allow[%d]: %w", i, err)
		}
	}
	for i, r := range p.Deny {
		if err := r.validate(); err != nil {
			return fmt.Errorf("deny[%d]: %w", i, err)
		}
	}
	return nil
}

func (r Rule) validate() error {
	if r.DestCIDR != "" {
		if _, _, err := net.ParseCIDR(r.DestCIDR); err != nil {
			return fmt.Errorf("invalid dest_cidr %q: %w", r.DestCIDR, err)
		}
	}
	for _, p := range r.Protocols {
		switch p {
		case "tcp", "udp", "icmp", "":
		default:
			return fmt.Errorf("unknown protocol %q", p)
		}
	}
	return nil
}

// canonicalBytes returns the deterministic byte form used for signing.
// YAML emitted with sorted keys (Go struct field order is fixed; ports
// + uid lists are sorted ascending), no leading "---", LF line endings.
//
// Determinism matters because Sign and Verify both compute these bytes;
// any nondeterminism (e.g. map iteration order) breaks the round-trip
// across processes / language implementations.
func canonicalBytes(p Policy) ([]byte, error) {
	// Defensive copy + sort variadic-length lists. Allow/Deny order is
	// significant (first match wins) so it is NOT sorted; only the
	// commutative scope lists are.
	cp := p
	cp.OnlyUIDs = append([]uint32(nil), p.OnlyUIDs...)
	cp.OnlyCgroups = append([]string(nil), p.OnlyCgroups...)
	cp.ExceptUIDs = append([]uint32(nil), p.ExceptUIDs...)
	cp.ExceptCgroups = append([]string(nil), p.ExceptCgroups...)
	sort.Slice(cp.OnlyUIDs, func(i, j int) bool { return cp.OnlyUIDs[i] < cp.OnlyUIDs[j] })
	sort.Strings(cp.OnlyCgroups)
	sort.Slice(cp.ExceptUIDs, func(i, j int) bool { return cp.ExceptUIDs[i] < cp.ExceptUIDs[j] })
	sort.Strings(cp.ExceptCgroups)
	for i := range cp.Allow {
		cp.Allow[i] = sortRuleLists(cp.Allow[i])
	}
	for i := range cp.Deny {
		cp.Deny[i] = sortRuleLists(cp.Deny[i])
	}
	// Normalise time to UTC, no monotonic component, microsecond precision.
	// Truncate to seconds for cross-process determinism — YAML's time
	// marshaling preserves sub-second precision which can drift through
	// the parse/emit cycle.
	cp.SignedAt = cp.SignedAt.UTC().Truncate(time.Second)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cp); err != nil {
		return nil, fmt.Errorf("yaml encode: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("yaml close: %w", err)
	}
	return buf.Bytes(), nil
}

func sortRuleLists(r Rule) Rule {
	r.Ports = append([]uint16(nil), r.Ports...)
	r.Protocols = append([]string(nil), r.Protocols...)
	sort.Slice(r.Ports, func(i, j int) bool { return r.Ports[i] < r.Ports[j] })
	sort.Strings(r.Protocols)
	return r
}

// Sign signs a Policy with priv and returns SignedPolicy. The signed
// payload is the canonical YAML bytes of Policy.
func Sign(p Policy, signerID string, priv ed25519.PrivateKey) (SignedPolicy, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SignedPolicy{}, fmt.Errorf("invalid private key size %d (want %d)", len(priv), ed25519.PrivateKeySize)
	}
	if signerID == "" {
		return SignedPolicy{}, errors.New("signer is required")
	}
	if p.SchemaVersion == 0 {
		p.SchemaVersion = SchemaVersion
	}
	if p.Signer == "" {
		p.Signer = signerID
	}
	if p.SignedAt.IsZero() {
		p.SignedAt = time.Now().UTC().Truncate(time.Second)
	}
	if err := p.Validate(); err != nil {
		return SignedPolicy{}, fmt.Errorf("validate: %w", err)
	}
	canonical, err := canonicalBytes(p)
	if err != nil {
		return SignedPolicy{}, err
	}
	sig := ed25519.Sign(priv, canonical)
	return SignedPolicy{
		Policy:    p,
		Signer:    signerID,
		Algorithm: AlgorithmEd25519,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify checks the signature on sp using pub. Returns nil on success.
func Verify(sp SignedPolicy, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	if sp.Algorithm != AlgorithmEd25519 {
		return fmt.Errorf("unsupported algorithm %q (only %q supported)", sp.Algorithm, AlgorithmEd25519)
	}
	if sp.Signer == "" {
		return errors.New("signer is empty")
	}
	if err := sp.Policy.Validate(); err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sp.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	canonical, err := canonicalBytes(sp.Policy)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return errors.New("ed25519 signature does not verify")
	}
	return nil
}

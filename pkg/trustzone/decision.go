package trustzone

import (
	"fmt"
	"net"
)

// ZoneAction is the trust-zone decision for a single connect.
type ZoneAction uint8

const (
	ZoneAllow      ZoneAction = iota // pass through
	ZoneObserve                      // record only (no rule fire)
	ZoneVerify                       // route to verifier
	ZoneDeny                         // egressguard installs deny
	ZoneTorRequire                   // must go through Tor SOCKS (caller decides redirect vs deny)
)

// String renders the action as a stable lowercase token for tag
// stamping and operator-facing logs.
func (a ZoneAction) String() string {
	switch a {
	case ZoneAllow:
		return "allow"
	case ZoneObserve:
		return "observe"
	case ZoneVerify:
		return "verify"
	case ZoneDeny:
		return "deny"
	case ZoneTorRequire:
		return "tor_require"
	default:
		return "unknown"
	}
}

// DecisionInput is what the engine needs to decide.
type DecisionInput struct {
	Subject   Subject
	DestIP    net.IP
	DestPort  uint16
	Protocol  string
	SNI       string
	DestClass string
	Country   string
}

// Matrix is operator-tunable. v1 ships a sensible default; future
// versions accept a Matrix override in the YAML.
type Matrix map[Label]map[string]ZoneAction

// defaultRestrictedAllow is the set of dest_class values that a
// restricted subject can reach without verification. Operators
// typically want these because they're the boring corporate-internet
// background — package mirrors, dev registries, cloud control planes.
var defaultRestrictedAllow = map[string]struct{}{
	"cloudflare":   {},
	"google":       {},
	"aws":          {},
	"azure":        {},
	"akamai":       {},
	"fastly":       {},
	"cdn":          {},
	"private":      {},
	"os_update":    {},
	"dev_registry": {},
	"loopback":     {},
}

// torLocalPorts are the loopback ports that LabelTorOnly subjects are
// permitted to reach (the Tor SOCKS / control listeners). 9050 is the
// tor daemon default; 9150 is Tor Browser bundle's port.
var torLocalPorts = map[uint16]struct{}{
	9050: {},
	9051: {}, // tor control
	9150: {}, // tor browser
	9151: {}, // tor browser control
}

// DefaultMatrix returns the baked-in policy matrix. It is informed
// by Qubes' colour zones (red/yellow/green/blue) but mapped to the
// per-host egress decision points xhelix actually has.
func DefaultMatrix() Matrix {
	return Matrix{
		// Trusted: never gated. The whole point of this label is
		// "operator told us this subject is fine".
		LabelTrusted: nil,
		// Restricted: a known-safe set passes; everything else goes
		// to the verifier (Week 4 will route this through brp.verify).
		LabelRestricted: nil, // handled inline (set-membership)
		// Untrusted: only private/loopback passes; everything else
		// is denied. This is the "hard sandbox" zone.
		LabelUntrusted: nil, // handled inline
		// TorOnly: only loopback Tor ports pass; everything else
		// must be redirected through Tor (or denied if no proxy).
		LabelTorOnly: nil, // handled inline
	}
}

// Decide is the policy matrix: label × destination → action. Pure
// function; safe to call from the hot path. Returns (action, label,
// human-readable reason). When the subject's label is unknown or the
// destination doesn't match any rule, returns ZoneAllow with a reason
// of "default-allow" — fail-open, since this layer is opt-in.
func (m *Manager) Decide(in DecisionInput) (ZoneAction, Label, string) {
	if m == nil {
		return ZoneAllow, LabelTrusted, "trustzone disabled"
	}
	lbl := m.Lookup(in.Subject)
	switch lbl {
	case LabelTrusted, "":
		return ZoneAllow, LabelTrusted, "trusted zone"

	case LabelRestricted:
		if _, ok := defaultRestrictedAllow[in.DestClass]; ok {
			return ZoneAllow, lbl, fmt.Sprintf("restricted: dest_class=%s allowed", in.DestClass)
		}
		if isPrivateOrLoopback(in.DestIP) {
			return ZoneAllow, lbl, "restricted: private/loopback"
		}
		return ZoneVerify, lbl, fmt.Sprintf("restricted: dest_class=%s not in allow-list", in.DestClass)

	case LabelUntrusted:
		if isPrivateOrLoopback(in.DestIP) {
			return ZoneAllow, lbl, "untrusted: private/loopback"
		}
		if in.DestClass == "private" || in.DestClass == "loopback" {
			return ZoneAllow, lbl, "untrusted: private dest_class"
		}
		return ZoneDeny, lbl, "untrusted: external destination denied"

	case LabelTorOnly:
		if isTorLocal(in.DestIP, in.DestPort) {
			return ZoneAllow, lbl, "tor_only: loopback tor port"
		}
		return ZoneTorRequire, lbl, "tor_only: must route through Tor SOCKS"

	default:
		// Unknown custom label — fail open with a tag so the operator
		// can see it in event logs and fix their YAML.
		return ZoneAllow, lbl, fmt.Sprintf("unknown label %q: fail-open", lbl)
	}
}

// isPrivateOrLoopback returns true for RFC1918 + loopback + link-local +
// ULAv6 + loopback v6.
func isPrivateOrLoopback(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return true
	}
	return false
}

// isTorLocal returns true when the destination is a loopback address
// AND the port matches a known Tor proxy listener.
func isTorLocal(ip net.IP, port uint16) bool {
	if ip == nil {
		return false
	}
	if !ip.IsLoopback() {
		return false
	}
	_, ok := torLocalPorts[port]
	return ok
}

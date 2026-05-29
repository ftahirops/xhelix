package egresspolicy

import (
	"fmt"
	"net"
	"strings"
)

// Engine evaluates Requests against the Store. It is the hot-path
// consultee in pkg/pipeline.Handle for net_connect events. nil-safe:
// a nil engine always returns ActionObserve.
type Engine struct {
	store       *Store
	defaultMode Mode
}

// New constructs an Engine over the given store. defaultMode is the
// posture returned when no per-binary policy is loaded. ModeObserve is
// the safe default — no behavior change until the operator signs a
// stricter policy.
func New(store *Store, defaultMode Mode) *Engine {
	if defaultMode == "" {
		defaultMode = ModeObserve
	}
	return &Engine{store: store, defaultMode: defaultMode}
}

// DefaultMode returns the engine's posture for unmatched binaries.
func (e *Engine) DefaultMode() Mode {
	if e == nil {
		return ModeObserve
	}
	return e.defaultMode
}

// Store returns the underlying Store. Used by CLI / web for listing
// loaded policies. nil-safe.
func (e *Engine) Store() *Store {
	if e == nil {
		return nil
	}
	return e.store
}

// Decide is the hot-path entry. It looks up the matching policy,
// applies scope filters, and walks Allow / Deny rules according to
// mode. Lock-cheap: a single RLock on the store and a linear scan of
// (typically very few) rules.
func (e *Engine) Decide(req Request) Decision {
	if e == nil {
		return Decision{Action: ActionObserve, Mode: ModeObserve, Reason: "engine nil"}
	}
	if e.store == nil {
		return Decision{Action: ActionObserve, Mode: e.defaultMode, Reason: "store nil"}
	}
	sp := e.store.Get(req.Binary)
	if sp == nil {
		return Decision{Action: ActionObserve, Mode: e.defaultMode, Reason: "no policy"}
	}
	p := sp.Policy

	// Scope filters — Only* lists, when non-empty, mean "this policy
	// applies ONLY to subjects in the list". Except* lists exclude
	// subjects from the policy. Excluded subjects fall back to
	// defaultMode (Observe). This matches the principle that an
	// operator's narrowed policy should never accidentally widen.
	if !subjectInScope(p, req) {
		return Decision{
			Action:   ActionObserve,
			Mode:     e.defaultMode,
			PolicyID: p.Binary,
			Reason:   "subject out of policy scope",
		}
	}

	switch p.Mode {
	case ModeAllowAny:
		return Decision{
			Action:    ActionAllow,
			Mode:      ModeAllowAny,
			PolicyID:  p.Binary,
			MatchedBy: "allow_any",
			Reason:    "mode=allow_any",
		}

	case ModeObserve:
		return Decision{
			Action:   ActionObserve,
			Mode:     ModeObserve,
			PolicyID: p.Binary,
			Reason:   "mode=observe",
		}

	case ModeTorOnly:
		if isTorEndpoint(req) {
			return Decision{
				Action:    ActionAllow,
				Mode:      ModeTorOnly,
				PolicyID:  p.Binary,
				MatchedBy: "tor_loopback",
				Reason:    "tor SOCKS endpoint",
			}
		}
		return Decision{
			Action:   ActionDeny,
			Mode:     ModeTorOnly,
			PolicyID: p.Binary,
			Reason:   "mode=tor_only and dest is not 127.0.0.1:9050",
		}

	case ModeDenyDefault:
		// Deny rules first — explicit deny beats explicit allow.
		for i, r := range p.Deny {
			if matchRule(r, req) {
				return Decision{
					Action:    ActionDeny,
					Mode:      ModeDenyDefault,
					PolicyID:  p.Binary,
					MatchedBy: fmt.Sprintf("deny[%d]: %s", i, describeRule(r)),
					Reason:    r.Comment,
				}
			}
		}
		for i, r := range p.Allow {
			if matchRule(r, req) {
				return Decision{
					Action:    ActionAllow,
					Mode:      ModeDenyDefault,
					PolicyID:  p.Binary,
					MatchedBy: fmt.Sprintf("allow[%d]: %s", i, describeRule(r)),
					Reason:    r.Comment,
				}
			}
		}
		return Decision{
			Action:   ActionDeny,
			Mode:     ModeDenyDefault,
			PolicyID: p.Binary,
			Reason:   "no allow rule matched (deny_default)",
		}

	default:
		// Unknown mode in a signed policy should not happen because
		// Validate rejects it, but guard anyway.
		return Decision{
			Action:   ActionObserve,
			Mode:     e.defaultMode,
			PolicyID: p.Binary,
			Reason:   fmt.Sprintf("unknown mode %q in signed policy", p.Mode),
		}
	}
}

// subjectInScope applies the Only*/Except* filters in p to req. Empty
// Only* lists mean "any subject"; populated Except* lists override.
func subjectInScope(p Policy, req Request) bool {
	if len(p.OnlyUIDs) > 0 && !containsUID(p.OnlyUIDs, req.UID) {
		return false
	}
	if len(p.OnlyCgroups) > 0 && !containsStringCI(p.OnlyCgroups, req.Cgroup) {
		return false
	}
	if containsUID(p.ExceptUIDs, req.UID) {
		return false
	}
	if containsStringCI(p.ExceptCgroups, req.Cgroup) {
		return false
	}
	return true
}

// matchRule returns true if req matches all non-empty fields in r
// (AND semantics). Empty fields are wildcards.
func matchRule(r Rule, req Request) bool {
	if r.DestCIDR != "" {
		_, ipnet, err := net.ParseCIDR(r.DestCIDR)
		if err != nil || ipnet == nil || req.DestIP == nil {
			return false
		}
		if !ipnet.Contains(req.DestIP) {
			return false
		}
	}
	if r.DestClass != "" && !strings.EqualFold(r.DestClass, req.DestClass) {
		return false
	}
	if r.Country != "" && !strings.EqualFold(r.Country, req.Country) {
		return false
	}
	if r.ASN != "" && !strings.EqualFold(r.ASN, req.ASN) {
		return false
	}
	if len(r.Ports) > 0 && !containsPort(r.Ports, req.DestPort) {
		return false
	}
	if len(r.Protocols) > 0 && !containsStringCI(r.Protocols, req.Protocol) {
		return false
	}
	if r.SNI != "" && !matchHostname(r.SNI, req.SNI) {
		return false
	}
	if r.DNSName != "" && !matchHostname(r.DNSName, req.DNSName) {
		return false
	}
	return true
}

// matchHostname implements "exact OR wildcard suffix" matching. A
// pattern starting with "*." matches any subdomain of the rest; a
// pattern starting with "." matches anything ending in that suffix.
// Comparison is case-insensitive.
func matchHostname(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == "" || host == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".cloudflare.com"
		return strings.HasSuffix(host, suffix) || host == suffix[1:]
	}
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(host, pattern) || host == pattern[1:]
	}
	return pattern == host
}

// isTorEndpoint returns true if req points at the canonical local Tor
// SOCKS port. v1 hardcodes 127.0.0.1:9050 + ::1:9050; future versions
// may make this configurable per-policy.
func isTorEndpoint(req Request) bool {
	if req.DestPort != torPort {
		return false
	}
	if req.DestIP == nil {
		return false
	}
	if v4 := req.DestIP.To4(); v4 != nil {
		return v4.Equal(torLoopback4)
	}
	return req.DestIP.Equal(torLoopback6)
}

func containsUID(xs []uint32, x uint32) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsPort(xs []uint16, x uint16) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsStringCI(xs []string, x string) bool {
	for _, v := range xs {
		if strings.EqualFold(v, x) {
			return true
		}
	}
	return false
}

// describeRule produces a short human-readable description of r for
// inclusion in Decision.MatchedBy. Picks the most specific non-empty
// field; falls back to "*".
func describeRule(r Rule) string {
	switch {
	case r.DestCIDR != "":
		return "dest_cidr=" + r.DestCIDR
	case r.SNI != "":
		return "sni=" + r.SNI
	case r.DNSName != "":
		return "dns_name=" + r.DNSName
	case r.DestClass != "":
		return "dest_class=" + r.DestClass
	case r.Country != "":
		return "country=" + r.Country
	case r.ASN != "":
		return "asn=" + r.ASN
	case len(r.Ports) > 0:
		return fmt.Sprintf("ports=%v", r.Ports)
	case len(r.Protocols) > 0:
		return fmt.Sprintf("protocols=%v", r.Protocols)
	default:
		return "*"
	}
}

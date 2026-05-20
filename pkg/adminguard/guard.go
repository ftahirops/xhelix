// Package adminguard enforces operator-declared IP/ASN allow-lists
// on sensitive routes. Per BEHAVIORAL_DEFENSE.md §3.12-b — Tier 1
// deterministic detection: either the source matches the operator's
// policy or it doesn't, no statistical inference.
//
// Decision semantics:
//
//   1. The guard is route-scoped: a request whose route doesn't
//      match ANY rule is not "an admin route" and is allowed
//      unconditionally (this package is not the system's default
//      policy — it is opt-in per route).
//
//   2. For requests whose route DOES match one or more rules, ALL
//      matching rules' restrictions apply. The source must satisfy
//      every matching rule. Fail-closed: a single rule deny denies
//      the whole request.
//
//   3. Inside a rule, satisfying ANY of the listed CIDRs / IPs / ASNs
//      is enough. They are alternatives.
//
// This composes with the layered defenses in the doc: WebAuthn
// (3.12-a) handles credential strength; this package handles source
// reachability; Data Passport (P7.1.7) handles authorisation per
// action. None replaces another.
package adminguard

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"

	"github.com/xhelix/xhelix/pkg/geoip"
)

// Decision is the verdict returned by Check.
type Decision uint8

const (
	DecisionAllow Decision = iota
	DecisionDeny
)

func (d Decision) String() string {
	if d == DecisionAllow {
		return "allow"
	}
	return "deny"
}

// Verdict carries the full decision context.
type Verdict struct {
	Decision     Decision `json:"decision"`
	Reason       string   `json:"reason"`
	Route        string   `json:"route"`
	SourceIP     string   `json:"source_ip"`
	ResolvedASN  string   `json:"resolved_asn,omitempty"`
	MatchedRule  string   `json:"matched_rule,omitempty"`
	DenyingRule  string   `json:"denying_rule,omitempty"`
}

// rule represents one allow-list entry, post-parsing.
type rule struct {
	Name         string
	RoutePrefixes []string   // route_patterns from YAML, stored as path prefixes
	RouteExact    []string   // exact route matches (no trailing slash)
	AllowedCIDRs  []*net.IPNet
	AllowedIPs    map[string]struct{}
	AllowedASNs   map[string]struct{}
}

// fileSchema mirrors admin_allowlist.yaml on disk.
type fileSchema struct {
	Version int `yaml:"version"`
	Rules   []struct {
		Name          string   `yaml:"name"`
		RoutePatterns []string `yaml:"route_patterns"`
		AllowedCIDRs  []string `yaml:"allowed_cidrs"`
		AllowedIPs    []string `yaml:"allowed_ips"`
		AllowedASNs   []string `yaml:"allowed_asns"`
	} `yaml:"rules"`
}

// Guard is the loaded, validated policy. Safe for concurrent reads;
// Reload() atomically swaps state.
type Guard struct {
	mu       sync.RWMutex
	rules    []rule
	source   string
	geoip    geoip.Provider // optional; if nil, ASN-only rules are skipped

	checks  atomic.Uint64
	allowed atomic.Uint64
	denied  atomic.Uint64
}

// New constructs an empty Guard. The geoip provider is optional —
// if nil, rules that rely on ASN matching will silently fail to
// match (their CIDR/IP entries still work). Pass a real provider
// in production.
func New(provider geoip.Provider) *Guard {
	return &Guard{geoip: provider}
}

// Load reads YAML policy from path. Missing file is not an error —
// the Guard simply has no rules and allows everything. A malformed
// file IS an error and leaves the guard untouched.
func (g *Guard) Load(path string) error {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("adminguard load: %w", err)
	}
	rules, err := parse(raw)
	if err != nil {
		return fmt.Errorf("adminguard parse: %w", err)
	}
	g.mu.Lock()
	g.rules = rules
	g.source = path
	g.mu.Unlock()
	return nil
}

// Reload re-reads the source file. Failed reload leaves the live
// policy intact.
func (g *Guard) Reload() error {
	g.mu.RLock()
	src := g.source
	g.mu.RUnlock()
	if src == "" {
		return fmt.Errorf("adminguard: no source path set")
	}
	return g.Load(src)
}

func parse(raw []byte) ([]rule, error) {
	var f fileSchema
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d (want 1)", f.Version)
	}
	out := make([]rule, 0, len(f.Rules))
	for i, r := range f.Rules {
		if r.Name == "" {
			r.Name = fmt.Sprintf("rule-%d", i+1)
		}
		if len(r.RoutePatterns) == 0 {
			return nil, fmt.Errorf("rule %q: route_patterns is required", r.Name)
		}
		if len(r.AllowedCIDRs)+len(r.AllowedIPs)+len(r.AllowedASNs) == 0 {
			return nil, fmt.Errorf("rule %q: at least one of allowed_cidrs/ips/asns is required (an empty rule would deny every request)", r.Name)
		}
		built := rule{
			Name:        r.Name,
			AllowedIPs:  make(map[string]struct{}, len(r.AllowedIPs)),
			AllowedASNs: make(map[string]struct{}, len(r.AllowedASNs)),
		}
		for _, p := range r.RoutePatterns {
			// Trailing slash → prefix match; no trailing slash → exact match.
			if strings.HasSuffix(p, "/") {
				built.RoutePrefixes = append(built.RoutePrefixes, p)
			} else {
				built.RouteExact = append(built.RouteExact, p)
			}
		}
		for _, c := range r.AllowedCIDRs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				return nil, fmt.Errorf("rule %q: bad CIDR %q: %w", r.Name, c, err)
			}
			built.AllowedCIDRs = append(built.AllowedCIDRs, n)
		}
		for _, ip := range r.AllowedIPs {
			if net.ParseIP(ip) == nil {
				return nil, fmt.Errorf("rule %q: bad IP %q", r.Name, ip)
			}
			built.AllowedIPs[ip] = struct{}{}
		}
		for _, asn := range r.AllowedASNs {
			built.AllowedASNs[strings.ToUpper(asn)] = struct{}{}
		}
		out = append(out, built)
	}
	return out, nil
}

// matchesRoute reports whether the rule's route patterns cover route.
func (r rule) matchesRoute(route string) bool {
	for _, exact := range r.RouteExact {
		if route == exact {
			return true
		}
	}
	for _, p := range r.RoutePrefixes {
		if strings.HasPrefix(route, p) {
			return true
		}
	}
	return false
}

// satisfiedBy reports whether the source satisfies any of the rule's
// allowed sources. Caller already verified the rule matches the route.
func (r rule) satisfiedBy(ip net.IP, ipStr, asn string) bool {
	if _, ok := r.AllowedIPs[ipStr]; ok {
		return true
	}
	for _, n := range r.AllowedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	if asn != "" {
		if _, ok := r.AllowedASNs[strings.ToUpper(asn)]; ok {
			return true
		}
	}
	return false
}

// Check evaluates whether the request from sourceIP to route is
// permitted. Returns the verdict; the caller decides what to do
// with it (refuse, alert, both).
func (g *Guard) Check(route, sourceIP string) Verdict {
	g.checks.Add(1)
	v := Verdict{Route: route, SourceIP: sourceIP}

	ip := net.ParseIP(sourceIP)
	if ip == nil {
		g.denied.Add(1)
		v.Decision = DecisionDeny
		v.Reason = "source IP failed to parse"
		return v
	}

	var asn string
	if g.geoip != nil {
		if res, ok := g.geoip.Lookup(sourceIP); ok {
			asn = res.ASN
			v.ResolvedASN = asn
		}
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	// Find every rule whose route patterns match this request.
	var matched []rule
	for _, r := range g.rules {
		if r.matchesRoute(route) {
			matched = append(matched, r)
		}
	}

	// No matching rule → not a sensitive route → allow.
	if len(matched) == 0 {
		g.allowed.Add(1)
		v.Decision = DecisionAllow
		v.Reason = "route is not under admin allow-list policy"
		return v
	}

	// Every matching rule's restrictions apply. Deny on first failure.
	for _, r := range matched {
		if !r.satisfiedBy(ip, sourceIP, asn) {
			g.denied.Add(1)
			v.Decision = DecisionDeny
			v.DenyingRule = r.Name
			v.Reason = fmt.Sprintf("source %s (asn=%q) not in allow-list for rule %q",
				sourceIP, asn, r.Name)
			return v
		}
		// Track the first matching rule as informational.
		if v.MatchedRule == "" {
			v.MatchedRule = r.Name
		}
	}

	g.allowed.Add(1)
	v.Decision = DecisionAllow
	v.Reason = "source satisfies all matching admin rules"
	return v
}

// Stats is the snapshot returned to LocalAPI / health.snapshot.
type Stats struct {
	RuleCount int    `json:"rule_count"`
	Checks    uint64 `json:"checks"`
	Allowed   uint64 `json:"allowed"`
	Denied    uint64 `json:"denied"`
	Source    string `json:"source,omitempty"`
}

// Stats returns counter snapshot.
func (g *Guard) Stats() Stats {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return Stats{
		RuleCount: len(g.rules),
		Checks:    g.checks.Load(),
		Allowed:   g.allowed.Load(),
		Denied:    g.denied.Load(),
		Source:    g.source,
	}
}

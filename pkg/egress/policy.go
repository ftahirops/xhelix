// Package egress implements the taint-aware destination policy
// described in DATA_LEAK_FABRIC.md §6. It answers a single question:
//
//	"Given a lineage's accumulated TaintSet and a candidate outbound
//	 destination, is this connection permitted?"
//
// The decision is pure: no network I/O, no state mutation. Enforcement
// (calling netban.Ban, terminating the socket, etc.) is the caller's
// responsibility.
//
// Two policy sources feed the decision:
//
//  1. Static rules loaded from ruleset/dlcf/egress.yaml — per-class
//     allowed destination CIDRs and hostnames. Maintained by operators.
//
//  2. Live Data Passports (P7.1.7, future) — short-TTL signed tokens
//     that add temporary destinations for a specific class set. The
//     PassportSource interface is the integration point.
//
// Default deny: a tainted lineage with no matching rule and no live
// passport is denied. An *untainted* lineage is allowed by default
// (this package's job is data-leak prevention, not general
// connectivity policy).
package egress

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"

	"github.com/xhelix/xhelix/pkg/lineage"
)

// Decision is the verdict returned by Policy.Allow.
type Decision uint8

const (
	// DecisionAllow — destination matches a rule for every class
	// in the lineage's taint set (or the lineage is untainted).
	DecisionAllow Decision = iota

	// DecisionDeny — at least one tainted class has no destination
	// rule covering this connection.
	DecisionDeny
)

func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionDeny:
		return "deny"
	}
	return "unknown"
}

// Verdict carries the full decision context, useful for logging and
// for the LocalAPI surface.
type Verdict struct {
	Decision    Decision        `json:"decision"`
	Reason      string          `json:"reason"`
	TaintBits   uint64          `json:"taint_bits"`
	Classes     []string        `json:"classes,omitempty"`
	DestIP      string          `json:"dest_ip"`
	DestPort    uint16          `json:"dest_port,omitempty"`
	MatchedRule string          `json:"matched_rule,omitempty"`
	Passport    string          `json:"passport,omitempty"`
}

// classRule is one entry from egress.yaml — destinations a tainted
// lineage carrying this class is permitted to talk to.
type classRule struct {
	Class      string
	Name       string // operator-facing label, optional
	CIDRs      []*net.IPNet
	IPs        map[string]struct{}
	HostSuffix []string // ".s3.amazonaws.com" matches "x.s3.amazonaws.com"
}

// fileSchema mirrors egress.yaml on disk.
type fileSchema struct {
	Version int `yaml:"version"`
	Rules   []struct {
		Class       string   `yaml:"class"`
		Name        string   `yaml:"name"`
		CIDRs       []string `yaml:"cidrs"`
		IPs         []string `yaml:"ips"`
		HostSuffixes []string `yaml:"host_suffixes"`
	} `yaml:"rules"`
}

// PassportSource is the integration point for P7.1.7. The Policy will
// consult it on every Allow() call; nil is fine (means no passports).
type PassportSource interface {
	// ActiveDestinations returns the destinations currently
	// authorised by valid passports for the given class. Implementations
	// must be cheap to call (Allow is on the hot path).
	ActiveDestinations(class string) (cidrs []*net.IPNet, hostSuffixes []string, passportID string)
}

// Policy is the loaded, validated rule set. Safe for concurrent reads;
// Reload() atomically swaps state under a write lock.
type Policy struct {
	mu            sync.RWMutex
	rulesByClass  map[string][]classRule
	source        string
	passportSrc   PassportSource
	classRegistry *lineage.ClassRegistry

	allowed atomic.Uint64
	denied  atomic.Uint64
	checks  atomic.Uint64
}

// New constructs an empty Policy. Call Load() to populate from YAML.
func New(reg *lineage.ClassRegistry) *Policy {
	return &Policy{
		rulesByClass:  make(map[string][]classRule),
		classRegistry: reg,
	}
}

// AttachPassportSource wires the dynamic passport layer. Called once
// at startup after pkg/passport is constructed (P7.1.7).
func (p *Policy) AttachPassportSource(s PassportSource) {
	p.mu.Lock()
	p.passportSrc = s
	p.mu.Unlock()
}

// Load reads a YAML policy file. Missing file is not an error; the
// policy starts empty and every tainted lineage will be denied
// outbound. That's the safe default — operators must opt in to
// destinations explicitly.
func (p *Policy) Load(path string) error {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("egress load: %w", err)
	}
	rules, err := parse(raw)
	if err != nil {
		return fmt.Errorf("egress parse: %w", err)
	}
	p.mu.Lock()
	p.rulesByClass = rules
	p.source = path
	p.mu.Unlock()
	return nil
}

// Reload re-reads the source file. Failed reload leaves the live
// policy intact (consistent with pkg/catalog behaviour).
func (p *Policy) Reload() error {
	p.mu.RLock()
	src := p.source
	p.mu.RUnlock()
	if src == "" {
		return fmt.Errorf("egress: no source path set")
	}
	return p.Load(src)
}

func parse(body []byte) (map[string][]classRule, error) {
	var f fileSchema
	if err := yaml.Unmarshal(body, &f); err != nil {
		return nil, err
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version: %d (want 1)", f.Version)
	}
	out := make(map[string][]classRule, len(f.Rules))
	for _, r := range f.Rules {
		if r.Class == "" {
			return nil, fmt.Errorf("rule with empty class")
		}
		cr := classRule{Class: r.Class, Name: r.Name, IPs: make(map[string]struct{})}
		for _, c := range r.CIDRs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				return nil, fmt.Errorf("rule %q: bad CIDR %q: %w", r.Name, c, err)
			}
			cr.CIDRs = append(cr.CIDRs, n)
		}
		for _, ip := range r.IPs {
			if net.ParseIP(ip) == nil {
				return nil, fmt.Errorf("rule %q: bad IP %q", r.Name, ip)
			}
			cr.IPs[ip] = struct{}{}
		}
		for _, h := range r.HostSuffixes {
			if !strings.HasPrefix(h, ".") {
				h = "." + h
			}
			cr.HostSuffix = append(cr.HostSuffix, strings.ToLower(h))
		}
		out[r.Class] = append(out[r.Class], cr)
	}
	return out, nil
}

// Allow evaluates whether the outbound connection is permitted.
//
// taint:    the lineage's accumulated TaintSet
// destIP:   the destination IP address (must be valid)
// destHost: optional destination hostname (e.g. from DNS resolution),
//           lowercased before comparison; pass "" if unknown
// destPort: optional, recorded in the verdict but not used by v1
//           policy matching (port-level scoping is a v2 feature)
func (p *Policy) Allow(taint lineage.TaintSet, destIP net.IP, destHost string, destPort uint16) Verdict {
	p.checks.Add(1)

	v := Verdict{
		TaintBits: uint64(taint),
		DestIP:    destIP.String(),
		DestPort:  destPort,
	}

	// Untainted lineages: not our problem. Other plumbing
	// (netban blocklist, country gates, etc.) decides those.
	if taint.IsEmpty() {
		p.allowed.Add(1)
		v.Decision = DecisionAllow
		v.Reason = "untainted lineage — no DLCF policy applies"
		return v
	}

	if p.classRegistry != nil {
		v.Classes = p.classRegistry.NamesOf(taint)
	}

	if destIP == nil {
		p.denied.Add(1)
		v.Decision = DecisionDeny
		v.Reason = "destination IP is nil"
		return v
	}

	destHost = strings.ToLower(destHost)

	p.mu.RLock()
	defer p.mu.RUnlock()

	// Every class in the taint set must be satisfied — either by a
	// static rule OR by an active passport.
	for _, className := range v.Classes {
		if p.satisfiesClass(className, destIP, destHost, &v) {
			continue
		}
		// First unsatisfied class fails the whole check.
		p.denied.Add(1)
		v.Decision = DecisionDeny
		if v.Reason == "" {
			v.Reason = fmt.Sprintf("class %q has no rule or passport covering %s",
				className, destIP)
		}
		return v
	}

	p.allowed.Add(1)
	v.Decision = DecisionAllow
	if v.Reason == "" {
		v.Reason = "all tainted classes have matching destination rule"
	}
	return v
}

// satisfiesClass reports whether the destination is allowed for the
// named class via either a static rule or an active passport. Updates
// verdict.MatchedRule / verdict.Passport on success. Caller holds the
// read lock.
func (p *Policy) satisfiesClass(class string, destIP net.IP, destHost string, v *Verdict) bool {
	// Static rules first (cheaper).
	for _, r := range p.rulesByClass[class] {
		if r.matches(destIP, destHost) {
			v.MatchedRule = r.label()
			return true
		}
	}
	// Then passports.
	if p.passportSrc != nil {
		cidrs, suffixes, id := p.passportSrc.ActiveDestinations(class)
		if matchesNet(cidrs, destIP) || matchesHostSuffix(suffixes, destHost) {
			v.Passport = id
			return true
		}
	}
	return false
}

func (r classRule) matches(destIP net.IP, destHost string) bool {
	if _, ok := r.IPs[destIP.String()]; ok {
		return true
	}
	if matchesNet(r.CIDRs, destIP) {
		return true
	}
	if destHost != "" && matchesHostSuffix(r.HostSuffix, destHost) {
		return true
	}
	return false
}

func (r classRule) label() string {
	if r.Name != "" {
		return r.Name
	}
	return r.Class
}

func matchesNet(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func matchesHostSuffix(suffixes []string, host string) bool {
	if host == "" {
		return false
	}
	for _, s := range suffixes {
		// "." + suffix" was prepended at load; equality covers exact
		// match too (".example.com" matches "example.com" via the
		// HasSuffix path below).
		if strings.HasSuffix(host, s) || strings.HasSuffix("."+host, s) {
			return true
		}
	}
	return false
}

// Stats returns counters useful for health.snapshot and operator
// dashboards.
type Stats struct {
	RuleCount  int    `json:"rule_count"`
	ClassCount int    `json:"class_count"`
	Checks     uint64 `json:"checks"`
	Allowed    uint64 `json:"allowed"`
	Denied     uint64 `json:"denied"`
	Source     string `json:"source,omitempty"`
}

// Stats returns a snapshot of the policy's counters.
func (p *Policy) Stats() Stats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	rules := 0
	for _, rs := range p.rulesByClass {
		rules += len(rs)
	}
	return Stats{
		RuleCount:  rules,
		ClassCount: len(p.rulesByClass),
		Checks:     p.checks.Load(),
		Allowed:    p.allowed.Load(),
		Denied:     p.denied.Load(),
		Source:     p.source,
	}
}

// Package policy implements xhelix's declarative egress policy. The
// operator authors deny/allow rules per-app and globally; this
// package evaluates them as the highest-priority verdict layer.
//
// Policy is hot-reloadable: callers create a Policy, then call
// Load() with a fresh source whenever the file changes. Decide()
// uses a copy-on-write atomic so reloads are lock-free for readers.
package policy

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xhelix/xhelix/pkg/verdict"
)

// AppKey identifies which app a per-app rule applies to. Any one of
// the fields is sufficient; the matcher uses the most specific
// available identifier.
type AppKey struct {
	ExeSHA string // hex SHA-256 of the binary
	Exe    string // absolute path; matched by exact suffix or full string
	Comm   string // /proc/PID/comm; useful when SHA isn't available
	Unit   string // systemd unit name
}

// AppRules holds per-app constraints.
type AppRules struct {
	Match AppKey

	// AllowOnlyDomains, if non-empty, means *only* these domains may
	// be contacted by this app. Anything else is denied.
	AllowOnlyDomains []string

	// AllowCountries / AllowASNs, if non-empty, similarly restrict
	// the destination to listed countries / ASNs.
	AllowCountries []string
	AllowASNs      []uint32

	// Deny* override the allow lists. Highest precedence within a
	// per-app rule.
	DenyDomains   []string
	DenyCountries []string
	DenyASNs      []uint32
	DenyPorts     []uint16
}

// Global holds rules that apply to every flow regardless of app.
type Global struct {
	DenyDomains   []string
	DenyCountries []string
	DenyASNs      []uint32
	DenyIPCIDRs   []string // textual CIDR; matched by ParseCIDR at load time

	denyIPNets []*net.IPNet
}

// Document is the marshalled shape — a single file's contents.
type Document struct {
	Global Global     `yaml:"global"  json:"global"`
	Apps   []AppRules `yaml:"apps"    json:"apps"`
}

// Policy is the runtime evaluator.
type Policy struct {
	doc atomic.Pointer[Document]
	mu  sync.Mutex
}

// New returns an empty policy. Load to install rules.
func New() *Policy {
	p := &Policy{}
	empty := &Document{}
	p.doc.Store(empty)
	return p
}

// Load atomically replaces the active policy.
func (p *Policy) Load(d *Document) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if d == nil {
		d = &Document{}
	}
	d.Global.denyIPNets = compileCIDRs(d.Global.DenyIPCIDRs)
	p.doc.Store(d)
}

// Current returns a pointer to the active document. Callers must not
// mutate it.
func (p *Policy) Current() *Document { return p.doc.Load() }

// Layer adapts a Policy to a verdict.Layer (priority 0 — runs first).
type Layer struct {
	P *Policy
}

func (Layer) Name() string { return "policy" }

func (l Layer) Eval(c verdict.Conn) (bool, verdict.Action, verdict.Confidence, []verdict.Reason) {
	doc := l.P.Current()
	if doc == nil {
		return false, "", 0, nil
	}

	host := c.SNI
	if host == "" {
		host = c.DNSName
	}

	// 1) Global denies (apply to every app).
	if r := matchGlobal(doc.Global, host, c); r != "" {
		return true, verdict.ActionDeny, 95, []verdict.Reason{{
			Layer:  "policy",
			RuleID: "policy.global.deny",
			Note:   r,
		}}
	}

	// 2) Per-app rules. Find the most specific matching app rule.
	app := matchApp(doc.Apps, c)
	if app == nil {
		return false, "", 0, nil // no per-app rule → continue chain
	}

	// 2a) Explicit per-app denies.
	if r := matchAppDeny(app, host, c); r != "" {
		return true, verdict.ActionDeny, 95, []verdict.Reason{{
			Layer:  "policy",
			RuleID: "policy.app.deny",
			Note:   r,
		}}
	}

	// 2b) Allow-only / allow-country / allow-ASN — if specified,
	// anything not on these lists is denied.
	if len(app.AllowOnlyDomains) > 0 {
		matched := false
		for _, p := range app.AllowOnlyDomains {
			if verdict.MatchHost(p, host) {
				matched = true
				break
			}
		}
		if !matched {
			return true, verdict.ActionDeny, 90, []verdict.Reason{{
				Layer:  "policy",
				RuleID: "policy.app.allow-only-domains",
				Note:   "host not in app's allow-only-domains list",
			}}
		}
	}
	if len(app.AllowCountries) > 0 && c.Country != "" {
		matched := false
		for _, cc := range app.AllowCountries {
			if cc == c.Country {
				matched = true
				break
			}
		}
		if !matched {
			return true, verdict.ActionDeny, 90, []verdict.Reason{{
				Layer:  "policy",
				RuleID: "policy.app.country-restricted",
				Note:   "country " + c.Country + " not in app's allow-countries list",
			}}
		}
	}
	if len(app.AllowASNs) > 0 && c.ASN != 0 {
		matched := false
		for _, asn := range app.AllowASNs {
			if asn == c.ASN {
				matched = true
				break
			}
		}
		if !matched {
			return true, verdict.ActionDeny, 90, []verdict.Reason{{
				Layer:  "policy",
				RuleID: "policy.app.asn-restricted",
				Note:   "ASN not in app's allow-asns list",
			}}
		}
	}
	return false, "", 0, nil
}

// ─── helpers ────────────────────────────────────────────────────

func matchGlobal(g Global, host string, c verdict.Conn) string {
	for _, p := range g.DenyDomains {
		if verdict.MatchHost(p, host) {
			return "global deny: domain " + p
		}
	}
	for _, cc := range g.DenyCountries {
		if cc == c.Country && c.Country != "" {
			return "global deny: country " + cc
		}
	}
	for _, asn := range g.DenyASNs {
		if asn == c.ASN && asn != 0 {
			return "global deny: ASN"
		}
	}
	if ip := net.ParseIP(c.DstIP); ip != nil {
		for _, n := range g.denyIPNets {
			if n.Contains(ip) {
				return "global deny: dst_ip " + c.DstIP
			}
		}
	}
	return ""
}

func compileCIDRs(raws []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(raws))
	for _, raw := range raws {
		raw = normalizeCIDR(raw)
		if raw == "" {
			continue
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

func normalizeCIDR(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "/") {
		return raw
	}
	if strings.Contains(raw, ":") {
		return raw + "/128"
	}
	return raw + "/32"
}

func matchApp(rules []AppRules, c verdict.Conn) *AppRules {
	// Specificity order: ExeSHA > Exe (exact) > Unit > Comm.
	var best *AppRules
	bestScore := 0
	for i := range rules {
		score := 0
		k := rules[i].Match
		if k.ExeSHA != "" && k.ExeSHA == c.ExeSHA {
			score = 100
		} else if k.Exe != "" && k.Exe == c.Exe {
			score = 80
		} else if k.Unit != "" && k.Unit == c.Comm {
			// We don't have systemd unit threaded through yet; fall
			// back to comm match here.
			score = 50
		} else if k.Comm != "" && k.Comm == c.Comm {
			score = 30
		}
		if score > bestScore {
			best = &rules[i]
			bestScore = score
		}
	}
	return best
}

func matchAppDeny(a *AppRules, host string, c verdict.Conn) string {
	for _, p := range a.DenyDomains {
		if verdict.MatchHost(p, host) {
			return "app deny: domain " + p
		}
	}
	for _, cc := range a.DenyCountries {
		if cc == c.Country && c.Country != "" {
			return "app deny: country " + cc
		}
	}
	for _, asn := range a.DenyASNs {
		if asn == c.ASN && asn != 0 {
			return "app deny: ASN"
		}
	}
	for _, port := range a.DenyPorts {
		if port == c.DstPort && port != 0 {
			return "app deny: port"
		}
	}
	return ""
}

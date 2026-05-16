// Package static is a Provider that answers from in-memory
// allow/deny lists. It's the bridge between xhelix's existing
// pkg/intel feed-fetcher (Spamhaus, FireHOL, Tor) and the new
// pluggable providers interface.
//
// The provider holds two maps (denied domains, denied IPs) plus
// an optional allowlist. Lookups are O(1). Refresh() swaps the
// snapshot atomically.
package static

import (
	"context"
	"strings"
	"sync"

	"github.com/xhelix/xhelix/pkg/intel/providers"
)

// Source is a tag attached to deny entries so the resulting
// Verdict can name the feed (e.g. "spamhaus", "firehol", "tor").
type Source string

// Entry is one deny record.
type Entry struct {
	Source Source
	Reason string
}

// Provider implements providers.Provider over in-memory maps.
type Provider struct {
	name string
	mu   sync.RWMutex
	deny snapshot
}

type snapshot struct {
	domains map[string]Entry // suffix-match: "example.com" matches "x.example.com"
	ips     map[string]Entry
}

// New returns an empty Provider with the given name.
func New(name string) *Provider {
	if name == "" {
		name = "static"
	}
	return &Provider{name: name, deny: snapshot{
		domains: map[string]Entry{},
		ips:     map[string]Entry{},
	}}
}

// Name implements providers.Provider.
func (p *Provider) Name() string { return p.name }

// Lookup implements providers.Provider.
func (p *Provider) Lookup(_ context.Context, q providers.Query) (providers.Verdict, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if q.Domain != "" {
		if e, ok := lookupDomain(p.deny.domains, q.Domain); ok {
			return providers.Verdict{
				Class:    providers.ClassDeny,
				Reasons:  []string{string(e.Source) + ":" + e.Reason},
				Provider: p.name,
			}, nil
		}
	}
	if q.IP != "" {
		if e, ok := p.deny.ips[q.IP]; ok {
			return providers.Verdict{
				Class:    providers.ClassDeny,
				Reasons:  []string{string(e.Source) + ":" + e.Reason},
				Provider: p.name,
			}, nil
		}
	}
	return providers.Verdict{Class: providers.ClassClean, Provider: p.name}, nil
}

// SetDenyLists replaces the deny snapshot atomically. The maps
// passed in are taken by reference; callers should not mutate
// them after the call.
func (p *Provider) SetDenyLists(domains, ips map[string]Entry) {
	p.mu.Lock()
	p.deny = snapshot{domains: domains, ips: ips}
	p.mu.Unlock()
}

// AddDomain adds one entry. Convenience for small fixtures /
// tests; production callers prefer SetDenyLists for bulk loads.
func (p *Provider) AddDomain(domain string, e Entry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.deny.domains == nil {
		p.deny.domains = map[string]Entry{}
	}
	p.deny.domains[normalize(domain)] = e
}

// AddIP adds one entry.
func (p *Provider) AddIP(ip string, e Entry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.deny.ips == nil {
		p.deny.ips = map[string]Entry{}
	}
	p.deny.ips[ip] = e
}

// Counts returns (#domains, #ips) — useful for status reporting.
func (p *Provider) Counts() (int, int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.deny.domains), len(p.deny.ips)
}

// lookupDomain checks for an exact match, then walks parent
// labels for a suffix match. "x.y.example.com" matches a deny
// entry of "example.com".
func lookupDomain(deny map[string]Entry, domain string) (Entry, bool) {
	d := normalize(domain)
	if e, ok := deny[d]; ok {
		return e, true
	}
	for {
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
		if d == "" {
			break
		}
		if e, ok := deny[d]; ok {
			return e, true
		}
	}
	return Entry{}, false
}

func normalize(d string) string {
	return strings.ToLower(strings.TrimSuffix(d, "."))
}

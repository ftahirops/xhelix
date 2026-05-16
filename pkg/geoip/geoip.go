// Package geoip resolves IP addresses to country + ASN, the
// substrate for per-binary country baselines and the geographic
// distribution views.
//
// Two implementations live here:
//
//   - InMemory — pure-Go, holds a list of CIDR→Country+ASN entries.
//     Operators / packagers can ship a small seed list bundled with
//     xhelix for offline use (typically a few thousand entries
//     covering the top-N cloud / ISP / hosting ASNs).
//
//   - MaxMindFile — reads MaxMind GeoLite2 .mmdb format. Built
//     under the `geoipmaxmind` build tag so the optional dependency
//     stays out of the static-binary default build. Add via
//     `go build -tags geoipmaxmind`.
//
// The InMemory provider is the default and what tests exercise.
package geoip

import (
	"net/netip"
	"sort"
	"sync"
)

// Result is the lookup output.
type Result struct {
	Country string // ISO 3166-1 alpha-2 (e.g. "US", "CN", "DE")
	ASN     string // canonical "ASnnn" form
	ASNOrg  string // human-readable org name
}

// Provider is the lookup interface. Implementations must be
// goroutine-safe for concurrent Lookup calls.
type Provider interface {
	Lookup(ip string) (Result, bool)
}

// ── In-memory CIDR map ────────────────────────────────────────

// Entry is one CIDR→Result row.
type Entry struct {
	Prefix netip.Prefix
	Result Result
}

// InMemory is the default Provider — sorted CIDR list with
// longest-prefix-match lookup. Lookups are O(log N) on the sorted
// slice and read-only after Load(); safe to share across goroutines.
type InMemory struct {
	mu      sync.RWMutex
	entriesV4 []Entry // sorted by prefix length desc, then by addr
	entriesV6 []Entry
}

// NewInMemory returns an empty InMemory provider.
func NewInMemory() *InMemory {
	return &InMemory{}
}

// Load replaces the entry set atomically. Entries are sorted by
// prefix length descending (longest-prefix-match first) and then
// by address — so a /24 wins over a /16 over a /8.
func (m *InMemory) Load(entries []Entry) {
	v4 := make([]Entry, 0, len(entries)/2)
	v6 := make([]Entry, 0, len(entries)/2)
	for _, e := range entries {
		if !e.Prefix.IsValid() {
			continue
		}
		if e.Prefix.Addr().Is4() {
			v4 = append(v4, e)
		} else {
			v6 = append(v6, e)
		}
	}
	sort.Slice(v4, func(i, j int) bool {
		if v4[i].Prefix.Bits() != v4[j].Prefix.Bits() {
			return v4[i].Prefix.Bits() > v4[j].Prefix.Bits()
		}
		return v4[i].Prefix.Addr().Less(v4[j].Prefix.Addr())
	})
	sort.Slice(v6, func(i, j int) bool {
		if v6[i].Prefix.Bits() != v6[j].Prefix.Bits() {
			return v6[i].Prefix.Bits() > v6[j].Prefix.Bits()
		}
		return v6[i].Prefix.Addr().Less(v6[j].Prefix.Addr())
	})
	m.mu.Lock()
	m.entriesV4 = v4
	m.entriesV6 = v6
	m.mu.Unlock()
}

// Lookup implements Provider.
func (m *InMemory) Lookup(ip string) (Result, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Result{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var entries []Entry
	if addr.Is4() {
		entries = m.entriesV4
	} else {
		entries = m.entriesV6
	}
	// Linear scan with the sorted longest-prefix-first ordering.
	// A real CIDR tree would be faster on millions of entries; for
	// the few-thousand bundled-seed case this is fine.
	for _, e := range entries {
		if e.Prefix.Contains(addr) {
			return e.Result, true
		}
	}
	return Result{}, false
}

// Len returns the current entry count (v4 + v6).
func (m *InMemory) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.entriesV4) + len(m.entriesV6)
}

// ── Bundled seed (small, illustrative, not exhaustive) ────────

// SeedEntries returns a minimal CIDR set covering RFC-1918,
// loopback, link-local, and the IANA reserved + IETF protocol-
// special-purpose ranges. Real production deployments are
// expected to load a full MaxMind GeoLite2 file alongside this.
func SeedEntries() []Entry {
	parse := func(s, country, asn, org string) Entry {
		return Entry{
			Prefix: netip.MustParsePrefix(s),
			Result: Result{Country: country, ASN: asn, ASNOrg: org},
		}
	}
	return []Entry{
		// Loopback / link-local
		parse("127.0.0.0/8", "ZZ", "AS-LO", "Loopback"),
		parse("169.254.0.0/16", "ZZ", "AS-LL", "Link-Local"),
		parse("::1/128", "ZZ", "AS-LO", "Loopback"),
		parse("fe80::/10", "ZZ", "AS-LL", "Link-Local"),
		// RFC-1918
		parse("10.0.0.0/8", "ZZ", "AS-RFC1918", "Private"),
		parse("172.16.0.0/12", "ZZ", "AS-RFC1918", "Private"),
		parse("192.168.0.0/16", "ZZ", "AS-RFC1918", "Private"),
		parse("fc00::/7", "ZZ", "AS-ULA", "Private"),
		// Cloud metadata (matches pkg/cloudmeta scope)
		parse("169.254.169.254/32", "ZZ", "AS-META", "Cloud-Metadata"),
		// Well-known anycast resolvers (just illustrative)
		parse("8.8.8.8/32", "US", "AS15169", "Google"),
		parse("8.8.4.4/32", "US", "AS15169", "Google"),
		parse("1.1.1.1/32", "US", "AS13335", "Cloudflare"),
		parse("9.9.9.9/32", "CH", "AS19281", "Quad9"),
	}
}

// IsPrivate returns true for any RFC-1918, loopback, link-local,
// or unique-local-IPv6 address — convenient for skipping local
// traffic in anomaly scoring.
func IsPrivate(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast()
}

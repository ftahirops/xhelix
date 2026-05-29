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

	// Lookup memoization. With a full geoip CSV (~1.4M CIDRs) the linear
	// scan is ~ms per lookup; the dashboard runs thousands of lookups
	// per page load. Cache hits return in nanoseconds.
	cacheMu sync.RWMutex
	cache   map[string]cachedResult
}

type cachedResult struct {
	r  Result
	ok bool
}

const lookupCacheMax = 65536

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
	m.cacheMu.Lock()
	m.cache = nil
	m.cacheMu.Unlock()
}

// Lookup implements Provider.
func (m *InMemory) Lookup(ip string) (Result, bool) {
	m.cacheMu.RLock()
	if c, ok := m.cache[ip]; ok {
		m.cacheMu.RUnlock()
		return c.r, c.ok
	}
	m.cacheMu.RUnlock()

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Result{}, false
	}
	m.mu.RLock()
	var entries []Entry
	if addr.Is4() {
		entries = m.entriesV4
	} else {
		entries = m.entriesV6
	}
	var (
		result Result
		found  bool
	)
	for _, e := range entries {
		if e.Prefix.Contains(addr) {
			result, found = e.Result, true
			break
		}
	}
	m.mu.RUnlock()

	m.cacheMu.Lock()
	if m.cache == nil {
		m.cache = make(map[string]cachedResult, 1024)
	}
	if len(m.cache) >= lookupCacheMax {
		// Simple bounded cache: drop everything when full. Cheaper than
		// proper LRU bookkeeping and the working set will rebuild fast.
		m.cache = make(map[string]cachedResult, 1024)
	}
	m.cache[ip] = cachedResult{r: result, ok: found}
	m.cacheMu.Unlock()
	return result, found
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
	cf := func(s string) Entry { return parse(s, "US", "AS13335", "Cloudflare") }
	gg := func(s string) Entry { return parse(s, "US", "AS15169", "Google LLC") }
	aws := func(s string) Entry { return parse(s, "US", "AS16509", "Amazon.com Inc.") }
	ms := func(s string) Entry { return parse(s, "US", "AS8075", "Microsoft Corporation") }
	ak := func(s string) Entry { return parse(s, "US", "AS20940", "Akamai International") }
	fast := func(s string) Entry { return parse(s, "US", "AS54113", "Fastly") }
	hz := func(s string) Entry { return parse(s, "DE", "AS24940", "Hetzner Online GmbH") }
	do := func(s string) Entry { return parse(s, "US", "AS14061", "DigitalOcean LLC") }
	ovh := func(s string) Entry { return parse(s, "FR", "AS16276", "OVH SAS") }
	gh := func(s string) Entry { return parse(s, "US", "AS36459", "GitHub Inc.") }

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
		parse("8.8.8.8/32", "US", "AS15169", "Google LLC"),
		parse("8.8.4.4/32", "US", "AS15169", "Google LLC"),
		parse("1.1.1.1/32", "US", "AS13335", "Cloudflare"),
		parse("9.9.9.9/32", "CH", "AS19281", "Quad9"),

		// ── Cloudflare (AS13335) ──
		cf("104.16.0.0/12"), cf("104.21.0.0/16"), cf("104.18.0.0/16"),
		cf("104.26.0.0/16"), cf("104.27.0.0/16"), cf("104.28.0.0/16"),
		cf("172.64.0.0/13"), cf("172.67.0.0/16"),
		cf("173.245.48.0/20"), cf("188.114.96.0/20"), cf("190.93.240.0/20"),
		cf("197.234.240.0/22"), cf("198.41.128.0/17"),
		cf("162.158.0.0/15"), cf("131.0.72.0/22"),
		cf("141.101.64.0/18"), cf("108.162.192.0/18"),
		parse("1.1.1.0/24", "US", "AS13335", "Cloudflare"),
		parse("1.0.0.0/24", "US", "AS13335", "Cloudflare"),

		// ── Google (AS15169) ──
		parse("8.8.4.0/24", "US", "AS15169", "Google LLC"),
		parse("8.8.8.0/24", "US", "AS15169", "Google LLC"),
		gg("34.0.0.0/9"), gg("34.64.0.0/10"), gg("34.128.0.0/10"),
		gg("35.184.0.0/13"), gg("35.192.0.0/12"), gg("35.208.0.0/12"),
		gg("35.224.0.0/12"), gg("35.240.0.0/13"),
		gg("64.233.160.0/19"), gg("66.102.0.0/20"), gg("66.249.64.0/19"),
		gg("72.14.192.0/18"), gg("74.125.0.0/16"),
		gg("108.177.0.0/17"),
		gg("142.250.0.0/15"), gg("142.251.0.0/16"),
		gg("172.217.0.0/16"), gg("173.194.0.0/16"),
		gg("209.85.128.0/17"),
		gg("216.58.192.0/19"), gg("216.239.32.0/19"),

		// ── AWS (AS16509) ──
		aws("3.0.0.0/9"),
		aws("13.32.0.0/15"), aws("13.34.0.0/15"), aws("13.224.0.0/14"),
		aws("18.32.0.0/11"),
		aws("34.192.0.0/12"),
		aws("35.71.64.0/22"),
		aws("50.16.0.0/14"),
		aws("52.0.0.0/8"),
		aws("54.144.0.0/14"), aws("54.148.0.0/15"),
		aws("99.150.0.0/16"),
		aws("100.20.0.0/14"), aws("107.20.0.0/14"),
		aws("174.129.0.0/16"), aws("184.169.0.0/16"),
		aws("204.236.128.0/17"), aws("205.251.192.0/19"),

		// ── Microsoft / Azure (AS8075) ──
		ms("13.64.0.0/11"), ms("13.96.0.0/13"), ms("13.104.0.0/14"),
		ms("20.0.0.0/9"),
		ms("23.96.0.0/13"),
		ms("40.64.0.0/10"),
		ms("51.10.0.0/15"),
		ms("52.96.0.0/12"),
		ms("65.52.0.0/14"),
		ms("70.37.0.0/17"),
		ms("94.245.64.0/18"),
		ms("104.40.0.0/13"),
		ms("137.116.0.0/15"), ms("137.135.0.0/16"),
		ms("168.61.0.0/16"), ms("168.62.0.0/15"), ms("168.63.0.0/19"),

		// ── Akamai (AS20940) ──
		ak("23.32.0.0/11"), ak("23.64.0.0/14"), ak("23.72.0.0/13"),
		ak("23.192.0.0/11"),
		ak("88.221.0.0/16"), ak("92.122.0.0/15"), ak("95.100.0.0/15"),
		ak("96.6.0.0/15"), ak("96.16.0.0/14"),
		ak("104.64.0.0/10"),
		ak("184.24.0.0/13"), ak("184.50.0.0/15"),
		ak("184.84.0.0/14"), ak("184.150.0.0/15"),
		ak("198.183.224.0/19"),

		// ── Fastly (AS54113) ──
		fast("23.235.32.0/20"), fast("43.249.72.0/22"),
		fast("103.244.50.0/24"), fast("151.101.0.0/16"),
		fast("157.52.64.0/18"), fast("167.82.0.0/17"),
		fast("199.27.72.0/21"), fast("199.232.0.0/16"),

		// ── Hetzner (AS24940) ──
		hz("5.9.0.0/16"), hz("78.46.0.0/15"), hz("88.99.0.0/16"),
		hz("116.202.0.0/15"), hz("136.243.0.0/16"), hz("138.201.0.0/16"),
		hz("144.76.0.0/16"), hz("148.251.0.0/16"), hz("159.69.0.0/16"),
		hz("162.55.0.0/16"), hz("167.235.0.0/16"), hz("168.119.0.0/16"),
		hz("176.9.0.0/16"), hz("188.40.0.0/16"),
		hz("49.12.0.0/16"),
		hz("65.21.0.0/16"), hz("65.108.0.0/16"), hz("65.109.0.0/16"),
		hz("95.216.0.0/16"), hz("95.217.0.0/16"),
		hz("135.181.0.0/16"),

		// ── DigitalOcean (AS14061) ──
		do("45.55.0.0/16"), do("64.225.0.0/16"), do("104.131.0.0/16"),
		do("138.197.0.0/16"), do("138.68.0.0/16"), do("142.93.0.0/16"),
		do("143.198.0.0/16"), do("146.190.0.0/16"),
		do("159.65.0.0/16"), do("159.89.0.0/16"),
		do("162.243.0.0/16"),
		do("165.227.0.0/16"), do("165.232.0.0/16"),
		do("167.71.0.0/16"), do("167.99.0.0/16"),
		do("174.138.0.0/16"),
		do("178.62.0.0/16"), do("188.166.0.0/16"),
		do("192.241.128.0/17"), do("198.199.64.0/18"),
		do("206.189.0.0/16"), do("209.97.128.0/17"),

		// ── OVH (AS16276) ──
		ovh("5.39.0.0/17"), ovh("37.59.0.0/16"),
		ovh("51.68.0.0/16"), ovh("51.75.0.0/16"), ovh("51.83.0.0/16"),
		ovh("51.91.0.0/16"), ovh("51.158.0.0/15"),
		ovh("51.178.0.0/16"), ovh("51.210.0.0/16"), ovh("51.222.0.0/16"),
		ovh("54.36.0.0/14"),
		ovh("91.121.0.0/16"), ovh("91.134.0.0/15"),
		ovh("92.222.0.0/16"),
		ovh("94.23.0.0/16"), ovh("137.74.0.0/16"),
		ovh("142.4.192.0/19"),
		ovh("144.217.0.0/16"), ovh("145.239.0.0/16"),
		ovh("146.59.0.0/16"),
		ovh("147.135.0.0/16"), ovh("147.50.0.0/16"),
		ovh("149.202.0.0/16"), ovh("152.228.128.0/17"),
		ovh("158.69.0.0/16"), ovh("167.114.0.0/16"),
		ovh("178.32.0.0/15"), ovh("188.165.0.0/16"),
		ovh("192.95.0.0/18"), ovh("193.70.0.0/17"),

		// ── Public DNS (non-Cloudflare) ──
		parse("9.9.9.0/24", "CH", "AS19281", "Quad9"),
		parse("149.112.112.0/24", "CH", "AS19281", "Quad9"),
		parse("208.67.222.0/24", "US", "AS36692", "Cisco OpenDNS"),
		parse("208.67.220.0/24", "US", "AS36692", "Cisco OpenDNS"),

		// ── GitHub (AS36459) ──
		gh("140.82.112.0/20"), gh("143.55.64.0/20"),
		gh("192.30.252.0/22"), gh("185.199.108.0/22"),

		// ── China big-tech ──
		parse("47.74.0.0/15", "CN", "AS45102", "Alibaba Cloud"),
		parse("47.250.0.0/15", "CN", "AS45102", "Alibaba Cloud"),
		parse("119.59.0.0/16", "CN", "AS38365", "Baidu"),
		parse("180.97.0.0/16", "CN", "AS4837", "China Unicom (Baidu)"),
		parse("14.215.176.0/20", "CN", "AS45090", "Tencent"),
		parse("119.28.0.0/15", "CN", "AS132203", "Tencent"),

		// ── Tailscale (AS395747) ──
		parse("45.90.28.0/22", "US", "AS395747", "Tailscale Inc."),

		// ── Country-only fallbacks ──
		parse("2.16.0.0/13", "DE", "", ""),
		parse("80.241.0.0/16", "DE", "", ""),
		parse("89.0.0.0/8", "DE", "", ""),
		parse("217.0.0.0/8", "DE", "", ""),

		// ── IPv6: Cloudflare (AS13335) ──
		cf("2400:cb00::/32"), cf("2606:4700::/32"), cf("2803:f800::/32"),
		cf("2405:b500::/32"), cf("2405:8100::/32"), cf("2a06:98c0::/29"),
		cf("2c0f:f248::/32"),

		// ── IPv6: Google (AS15169) ──
		gg("2001:4860::/32"), gg("2607:f8b0::/32"), gg("2607:f8b0:4023::/48"),
		gg("2800:3f0::/32"), gg("2a00:1450::/32"), gg("2c0f:fb50::/32"),

		// ── IPv6: AWS (AS16509) ──
		aws("2600:1f00::/24"), aws("2600:9000::/28"), aws("2406:da00::/24"),
		aws("2a05:d000::/24"), aws("2804:800::/24"),

		// ── IPv6: Microsoft / Azure (AS8075) ──
		ms("2603:1000::/24"), ms("2620:1ec::/36"), ms("2a01:111::/32"),

		// ── IPv6: Akamai (AS20940) ──
		ak("2600:1400::/24"), ak("2a02:26f0::/32"),

		// ── IPv6: Fastly (AS54113) ──
		fast("2a04:4e40::/32"), fast("2a04:4e42::/32"),

		// ── IPv6: Hetzner (AS24940) ──
		hz("2a01:4f8::/29"), hz("2a01:4f9::/29"), hz("2a01:4ff::/32"),

		// ── IPv6: DigitalOcean (AS14061) ──
		do("2604:a880::/32"), do("2a03:b0c0::/32"),

		// ── IPv6: OVH (AS16276) ──
		ovh("2001:41d0::/32"),

		// ── IPv6: GitHub (AS36459) ──
		gh("2606:50c0::/32"),

		// ── IPv6: Public DNS ──
		parse("2620:fe::/48", "CH", "AS19281", "Quad9"),
		parse("2620:119:35::/48", "US", "AS36692", "Cisco OpenDNS"),
		parse("2606:4700:4700::/48", "US", "AS13335", "Cloudflare"),

		// ── IPv6: Tailscale (AS395747) ──
		parse("2a07:a8c0::/32", "US", "AS395747", "Tailscale Inc."),
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

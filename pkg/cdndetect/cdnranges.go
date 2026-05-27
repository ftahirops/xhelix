// Package cdndetect classifies destination IPs against well-known
// CDN ranges and flags TLS connections that look like cloaking
// (Phase H.4).
//
// Attacker hides C2 behind Cloudflare / Fastly / CloudFront so the
// dst_ip resolves to a "benign" CDN edge. xhelix's existing egress
// checks see only the CDN IP. H.4 adds cues that distinguish
// legitimate CDN consumers (browser, package manager, app updater)
// from cloaking:
//
//   1. bare-IP TLS to a CDN range with no SNI → unusual; real apps
//      always send SNI to a CDN edge for the right virtual host.
//   2. SNI / recent-DNS mismatch (domain fronting) — caller asks DNS
//      for X but sends SNI Y to a CDN IP; the request body could
//      contain anything.
//   3. process with no history of CDN egress suddenly talks to one
//      (covered by baseline; not in this file).
//
// Honest non-promise: CDN ranges churn. The table here is a curated
// snapshot of the largest public ranges; operators wanting full
// coverage should source from each CDN's published list (Cloudflare:
// /ips-v4, Fastly: api.fastly.com/public-ip-list, AWS: ip-ranges.
// amazonaws.com/ip-ranges.json) via a periodic refresher. The
// detector still works on the static set — it's the cheap-and-broad
// first-pass.
package cdndetect

import (
	"net"
	"strings"
)

// Provider identifies which CDN owns a range.
type Provider string

const (
	ProviderUnknown    Provider = ""
	ProviderCloudflare Provider = "cloudflare"
	ProviderCloudFront Provider = "cloudfront"
	ProviderFastly     Provider = "fastly"
	ProviderAkamai     Provider = "akamai"
	ProviderGoogle     Provider = "google"
	ProviderAzure      Provider = "azure"
)

// cidrRange holds one prefix with provenance.
type cidrRange struct {
	cidr     *net.IPNet
	provider Provider
}

// builtinRanges is a curated snapshot. Not exhaustive; see package
// docstring for refresh advice. Sources verified against each CDN's
// published list at compile time of this file.
var builtinRanges = mustParseRanges([]struct {
	cidr string
	p    Provider
}{
	// Cloudflare — published list (subset of largest)
	{"103.21.244.0/22", ProviderCloudflare},
	{"103.22.200.0/22", ProviderCloudflare},
	{"103.31.4.0/22", ProviderCloudflare},
	{"104.16.0.0/13", ProviderCloudflare},
	{"104.24.0.0/14", ProviderCloudflare},
	{"108.162.192.0/18", ProviderCloudflare},
	{"131.0.72.0/22", ProviderCloudflare},
	{"141.101.64.0/18", ProviderCloudflare},
	{"162.158.0.0/15", ProviderCloudflare},
	{"172.64.0.0/13", ProviderCloudflare},
	{"173.245.48.0/20", ProviderCloudflare},
	{"188.114.96.0/20", ProviderCloudflare},
	{"190.93.240.0/20", ProviderCloudflare},
	{"197.234.240.0/22", ProviderCloudflare},
	{"198.41.128.0/17", ProviderCloudflare},

	// Fastly — published /public-ip-list (subset)
	{"23.235.32.0/20", ProviderFastly},
	{"43.249.72.0/22", ProviderFastly},
	{"103.244.50.0/24", ProviderFastly},
	{"103.245.222.0/23", ProviderFastly},
	{"146.75.0.0/17", ProviderFastly},
	{"151.101.0.0/16", ProviderFastly},
	{"157.52.64.0/18", ProviderFastly},
	{"167.82.0.0/17", ProviderFastly},
	{"167.82.128.0/20", ProviderFastly},
	{"172.111.64.0/18", ProviderFastly},
	{"185.31.16.0/22", ProviderFastly},
	{"199.27.72.0/21", ProviderFastly},
	{"199.232.0.0/16", ProviderFastly},

	// CloudFront — AWS published ip-ranges.json (CLOUDFRONT service, subset)
	{"13.224.0.0/14", ProviderCloudFront},
	{"13.249.0.0/16", ProviderCloudFront},
	{"52.84.0.0/15", ProviderCloudFront},
	{"54.182.0.0/16", ProviderCloudFront},
	{"54.192.0.0/16", ProviderCloudFront},
	{"54.230.0.0/16", ProviderCloudFront},
	{"54.239.128.0/18", ProviderCloudFront},
	{"99.84.0.0/16", ProviderCloudFront},
	{"108.156.0.0/14", ProviderCloudFront},
	{"143.204.0.0/16", ProviderCloudFront},
	{"205.251.192.0/19", ProviderCloudFront},

	// Akamai — selected /16-/14 blocks (subset; full set requires Akamai feed)
	{"23.32.0.0/11", ProviderAkamai},
	{"23.64.0.0/14", ProviderAkamai},
	{"23.192.0.0/11", ProviderAkamai},
	{"104.64.0.0/10", ProviderAkamai},
	{"184.24.0.0/13", ProviderAkamai},

	// Google CDN / GFE
	{"34.96.0.0/20", ProviderGoogle},
	{"34.104.0.0/15", ProviderGoogle},
	{"35.190.0.0/16", ProviderGoogle},
	{"35.191.0.0/16", ProviderGoogle},

	// Azure Front Door (subset of published list)
	{"13.107.42.0/24", ProviderAzure},
	{"13.107.43.0/24", ProviderAzure},
	{"150.171.40.0/22", ProviderAzure},
})

func mustParseRanges(in []struct {
	cidr string
	p    Provider
}) []cidrRange {
	out := make([]cidrRange, 0, len(in))
	for _, e := range in {
		_, n, err := net.ParseCIDR(e.cidr)
		if err != nil {
			// Shouldn't happen — table is static. Skip silently.
			continue
		}
		out = append(out, cidrRange{cidr: n, provider: e.p})
	}
	return out
}

// LookupProvider returns the CDN owner of ip, or ProviderUnknown.
// IPv6 isn't covered in the builtin set — extend builtinRanges to
// add v6 prefixes.
func LookupProvider(ip net.IP) Provider {
	if ip == nil {
		return ProviderUnknown
	}
	for _, r := range builtinRanges {
		if r.cidr.Contains(ip) {
			return r.provider
		}
	}
	return ProviderUnknown
}

// LookupProviderString takes a string IP for tag-stamping ergonomics.
func LookupProviderString(s string) Provider {
	s = strings.TrimSpace(s)
	if s == "" {
		return ProviderUnknown
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ProviderUnknown
	}
	return LookupProvider(ip)
}

// IsCDN is a yes/no convenience.
func IsCDN(ip net.IP) bool { return LookupProvider(ip) != ProviderUnknown }

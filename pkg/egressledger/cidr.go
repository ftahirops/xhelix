// Package egressledger / CIDR bucketing policy.
//
// The ledger aggregates outbound flow telemetry by FlowKey, and the
// DestCIDR field of that key drives how many "destinations" collapse
// into one row. The bucket width is chosen PER destclass:
//
//   - For known CDN / cloud providers (cdn, cloud_provider, akamai,
//     fastly, cloudflare, google, aws, azure) the provider sprays
//     traffic across an entire /16 (v4) or /48 (v6). Storing the
//     exact IP just bloats the table and hides nothing — every IP
//     in the prefix is equally "Cloudflare". → /16 (v4) / /48 (v6).
//   - For private / loopback-adjacent prefixes we also use /16; the
//     RFC1918 space is small and operators care about subnet, not
//     host.
//   - For destinations the operator actually investigates — raw,
//     unknown, unclassified, cloud_metadata, intel_bad / threat — we
//     preserve the EXACT IP. Once the connection closes, connstate
//     drops the live row; if we /16-bucketed at write time the exact
//     IP is gone forever. Smart bucketing keeps the IP recoverable
//     three days later.
//   - Empty / missing destclass falls back to /16 — preserves the
//     pre-Week-6 behavior for any caller that hasn't been migrated.
//
// Loopback, link-local, multicast, unspecified addrs return "" and
// are dropped from the ledger entirely (internal traffic isn't a
// ledger concern).
package egressledger

import (
	"net"
	"strings"
)

// IsPublicDestClass returns true if a destclass should be treated as
// public (external) traffic. Anything else — private, loopback,
// link-local, multicast — is internal.
func IsPublicDestClass(class string) bool {
	switch class {
	case "private", "loopback", "rfc1918":
		return false
	}
	return true
}

// IsPublicCIDR is the fallback when the DestClass tag is empty. It
// inspects the CIDR string itself to decide.
func IsPublicCIDR(cidr string) bool {
	// Strip a possible /16 or /48 suffix.
	ip := cidr
	if i := strings.IndexByte(ip, '/'); i >= 0 {
		ip = ip[:i]
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true // unknown → treat as public, default-suspicious
	}
	return !parsed.IsPrivate() && !parsed.IsLoopback() &&
		!parsed.IsLinkLocalUnicast() && !parsed.IsUnspecified()
}

// flowKeyForIP returns the canonical DestCIDR string for an event
// based on its destclass. See the package doc for the bucket policy.
//
// Returns "" for addresses we don't want in the ledger at all
// (loopback / link-local / multicast / unspecified).
func flowKeyForIP(ip net.IP, destClass string) string {
	if ip == nil {
		return ""
	}
	// Multicast / unspecified are NEVER ledger-worthy regardless of
	// class (operational packets, no semantic value).
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() {
		return ""
	}
	// Loopback / link-local are normally excluded. Exception:
	// metadata / cloud_metadata explicitly target 169.254.169.254
	// (IMDS) which is link-local but matters for cloud-key-theft
	// forensics. Other exact-IP classes (raw/unknown/intel_bad) do
	// NOT bypass the link-local guard — random 169.254.x noise is
	// not investigation material.
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		if destClass != "metadata" && destClass != "cloud_metadata" {
			return ""
		}
	}
	// Always return the exact IP regardless of destclass. Bucketing
	// (formerly /16 for CDN/cloud) was rejected by operators: even
	// when the IP is "just Cloudflare", the exact IP is needed for
	// rDNS, ASN-specific edge lookup, intel correlation, and
	// safety-net blocking. Storage cost is bounded by the # of unique
	// remote IPs, not artificially inflated by sub-prefixes.
	_ = destClass
	return ip.String()
}

// isExactIPClass returns true if the destclass is one where the exact
// IP is the unit of investigation. Accepts BOTH the canonical
// pkg/destclass names (unknown, intel_bad) and the operator-facing
// aliases (raw, threat, metadata, ...) so callers from either side of
// the API can drive the same policy.
func isExactIPClass(c string) bool {
	switch c {
	// pkg/destclass canonical names where exact IP matters.
	case "unknown", "intel_bad":
		return true
	// Operator-facing aliases / planned class names.
	case "raw", "unclassified", "metadata", "cloud_metadata", "threat":
		return true
	}
	return false
}

// cidr16 is the legacy entrypoint preserved for backward compat. It
// behaves exactly as flowKeyForIP(ip, "") — always /16 (v4) or /48 (v6).
// New code should call flowKeyForIP directly with a destclass.
func cidr16(ip net.IP) string {
	return flowKeyForIP(ip, "")
}

package cdndetect

import (
	"strings"
	"sync"
	"time"
)

// CloakReason encodes one detection cue. Empty = no cloaking signal.
type CloakReason string

const (
	ReasonNone        CloakReason = ""
	ReasonBareIPToCDN CloakReason = "bare_ip_tls_to_cdn"
	ReasonSNIDNSMiss  CloakReason = "sni_dns_mismatch"
)

// DNSCache tracks recent DNS lookups per process so the cloaking
// classifier can correlate SNI against what the process actually
// asked for. Bounded by retention window + per-process cap.
type DNSCache struct {
	mu        sync.Mutex
	retention time.Duration
	perProc   int
	// key = process group (image or comm); value = list of (qname, ts)
	entries map[string][]dnsEntry
}

type dnsEntry struct {
	qname string
	ts    time.Time
}

// NewDNSCache returns a cache. retention bounds how long a name
// counts toward "recent"; perProc caps memory per process.
func NewDNSCache(retention time.Duration, perProc int) *DNSCache {
	if retention <= 0 {
		retention = 2 * time.Minute
	}
	if perProc <= 0 {
		perProc = 32
	}
	return &DNSCache{
		retention: retention,
		perProc:   perProc,
		entries:   map[string][]dnsEntry{},
	}
}

// Note records a DNS query name observed for process `key`.
func (c *DNSCache) Note(key, qname string, at time.Time) {
	if c == nil || key == "" || qname == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gc(at)
	list := c.entries[key]
	list = append(list, dnsEntry{qname: strings.ToLower(qname), ts: at})
	if len(list) > c.perProc {
		list = list[len(list)-c.perProc:]
	}
	c.entries[key] = list
}

// Recent returns the unique qnames seen for `key` within the
// retention window ending at `at`. Lowercased.
func (c *DNSCache) Recent(key string, at time.Time) []string {
	if c == nil || key == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := at.Add(-c.retention)
	seen := map[string]struct{}{}
	for _, e := range c.entries[key] {
		if e.ts.Before(cutoff) {
			continue
		}
		seen[e.qname] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// gc evicts entries older than retention. Caller holds c.mu.
func (c *DNSCache) gc(now time.Time) {
	cutoff := now.Add(-c.retention)
	for k, list := range c.entries {
		i := 0
		for i < len(list) && list[i].ts.Before(cutoff) {
			i++
		}
		if i == len(list) {
			delete(c.entries, k)
		} else if i > 0 {
			c.entries[k] = list[i:]
		}
	}
}

// Classify inspects one TLS connect attempt and returns the cloaking
// reason (or ReasonNone) plus the CDN provider for tag stamping.
//
// Inputs:
//   procKey — process identifier used for DNS correlation (image)
//   dstIP   — destination IP string
//   sni     — TLS SNI sent on this connect (may be empty)
//   dns     — DNS cache for procKey lookups
//   now     — time of connect (for cache window)
func Classify(procKey, dstIP, sni string, dns *DNSCache, now time.Time) (CloakReason, Provider) {
	prov := LookupProviderString(dstIP)
	if prov == ProviderUnknown {
		// Not a CDN destination — H.4 is silent.
		return ReasonNone, ProviderUnknown
	}

	// Cue 1: bare-IP TLS to a CDN range. Real apps always send SNI
	// to CDN edges (the edge needs SNI to route to the right vhost).
	if sni == "" {
		return ReasonBareIPToCDN, prov
	}

	// Cue 2: SNI does not match (or shouldn't share a suffix with)
	// any recently-resolved name for this process. This is the
	// classic domain-fronting signal — the process asked DNS for X
	// but is sending SNI Y over a CDN that fronts both.
	recent := dns.Recent(procKey, now)
	if len(recent) == 0 {
		// No DNS history. We can't decide; don't flag — falls under
		// the bare-IP rule above if there was no SNI either.
		return ReasonNone, prov
	}
	sniLower := strings.ToLower(sni)
	for _, q := range recent {
		if dnsMatchesSNI(q, sniLower) {
			return ReasonNone, prov
		}
	}
	return ReasonSNIDNSMiss, prov
}

// dnsMatchesSNI returns true when a recently-resolved DNS qname and
// the TLS SNI plausibly refer to the same property. Matches on
// exact equality, suffix containment, or shared registrable suffix
// (last two labels). Lowercased on entry.
func dnsMatchesSNI(qname, sni string) bool {
	if qname == sni {
		return true
	}
	if strings.HasSuffix(qname, "."+sni) || strings.HasSuffix(sni, "."+qname) {
		return true
	}
	return last2(qname) == last2(sni)
}

func last2(s string) string {
	parts := strings.Split(strings.TrimSuffix(s, "."), ".")
	if len(parts) < 2 {
		return s
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

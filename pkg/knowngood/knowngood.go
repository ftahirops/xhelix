// Package knowngood is xhelix's curated corpus of legitimate-service
// endpoints used by the verdict engine's known-good layer.
//
// Entries are factual: domain patterns and ASN numbers operated by
// well-known service providers. They are catalogued here as the
// project's own reference so the verdict layer can recognise common
// legitimate traffic without per-host configuration.
//
// Each entry carries a category (cdn, os-update, time, dns, mail,
// platform, etc.) and a confidence (verified|likely).
package knowngood

import (
	"sync"

	"github.com/xhelix/xhelix/pkg/verdict"
)

// Entry is one catalog row.
type Entry struct {
	Pattern    string // exact host or "*.suffix"
	Category   string // free-form short tag
	Confidence string // "verified" or "likely"
	ASN        uint32 // optional — match by ASN as well
	Note       string // free-form provenance note
}

// Corpus is a thread-safe in-memory store of entries indexed for fast
// host, ASN, and CIDR lookup.
type Corpus struct {
	mu        sync.RWMutex
	hostRules []Entry
	asnRules  map[uint32]Entry
	cidrs     *verdict.CIDRSet
	cidrSeeds []verdict.CIDREntry // accumulated for rebuild on Add
}

// New returns an empty corpus. Use NewDefault for one seeded with the
// project's bundled catalog.
func New() *Corpus {
	return &Corpus{
		asnRules: map[uint32]Entry{},
		cidrs:    verdict.NewCIDRSet(nil),
	}
}

// AddCIDR registers a routed prefix with a label (e.g. "Cloudflare cdn").
// Calls are bulk-friendly: the internal CIDR index is rebuilt once
// when Finalize is called, or lazily on first Lookup if Add* is mixed
// with Lookup. Cheap because the seed catalog is small.
func (c *Corpus) AddCIDR(cidr, label string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cidrSeeds = append(c.cidrSeeds, verdict.CIDREntry{CIDR: cidr, Label: label})
	c.cidrs = verdict.NewCIDRSet(c.cidrSeeds)
}

// LookupIP returns the label of the most-specific prefix that
// contains ip, or empty string.
func (c *Corpus) LookupIP(ip string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cidrs == nil {
		return ""
	}
	return c.cidrs.Lookup(ip)
}

// Add inserts an entry.
func (c *Corpus) Add(e Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.Pattern != "" {
		c.hostRules = append(c.hostRules, e)
	}
	if e.ASN != 0 {
		c.asnRules[e.ASN] = e
	}
}

// Lookup returns the first entry that matches host (SNI/DNS) or ASN.
// host has priority over ASN since hosts are higher-resolution.
func (c *Corpus) Lookup(host string, asn uint32) (Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if host != "" {
		for _, e := range c.hostRules {
			if verdict.MatchHost(e.Pattern, host) {
				return e, true
			}
		}
	}
	if asn != 0 {
		if e, ok := c.asnRules[asn]; ok {
			return e, true
		}
	}
	return Entry{}, false
}

// Size returns the number of host + ASN rules.
func (c *Corpus) Size() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.hostRules), len(c.asnRules)
}

// Layer adapts a Corpus to a verdict.Layer.
type Layer struct {
	C *Corpus
}

func (Layer) Name() string { return "knowngood" }

func (l Layer) Eval(c verdict.Conn) (bool, verdict.Action, verdict.Confidence, []verdict.Reason) {
	host := c.SNI
	if host == "" {
		host = c.DNSName
	}
	// 1) Host or ASN match.
	if host != "" || c.ASN != 0 {
		if e, ok := l.C.Lookup(host, c.ASN); ok {
			conf := verdict.Confidence(10)
			if e.Confidence == "likely" {
				conf = 20
			}
			return true, verdict.ActionAllow, conf, []verdict.Reason{{
				Layer:  "knowngood",
				RuleID: "kg." + e.Category,
				Note:   "matched " + e.Pattern + " (" + e.Category + ")",
			}}
		}
	}
	// 2) IP-prefix match — final fallback when no DNS/SNI/ASN signal.
	if c.DstIP != "" {
		if label := l.C.LookupIP(c.DstIP); label != "" {
			return true, verdict.ActionAllow, 25, []verdict.Reason{{
				Layer:  "knowngood",
				RuleID: "kg.cidr",
				Note:   "matched " + c.DstIP + " in " + label,
			}}
		}
	}
	return false, "", 0, nil
}

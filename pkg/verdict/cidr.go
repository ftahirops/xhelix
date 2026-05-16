package verdict

import (
	"net/netip"
	"sort"
	"strings"
)

// CIDRSet is a small ordered list of prefixes optimised for the
// "does this IP belong to any of these networks" question. It is
// not a trie — for the few thousand prefixes in our bundled corpus
// the linear scan after coarse bucketing is comfortably fast.
type CIDRSet struct {
	v4 []prefix
	v6 []prefix
}

type prefix struct {
	p     netip.Prefix
	label string // free-form, e.g. "Cloudflare AS13335"
}

// NewCIDRSet builds a set from a slice of (cidr, label) pairs.
// Invalid CIDRs are silently dropped — the seed catalog is trusted.
func NewCIDRSet(entries []CIDREntry) *CIDRSet {
	c := &CIDRSet{}
	for _, e := range entries {
		p, err := netip.ParsePrefix(e.CIDR)
		if err != nil {
			continue
		}
		pf := prefix{p: p, label: e.Label}
		if p.Addr().Is4() {
			c.v4 = append(c.v4, pf)
		} else {
			c.v6 = append(c.v6, pf)
		}
	}
	// Sort by mask length descending so a more-specific prefix wins.
	sort.Slice(c.v4, func(i, j int) bool { return c.v4[i].p.Bits() > c.v4[j].p.Bits() })
	sort.Slice(c.v6, func(i, j int) bool { return c.v6[i].p.Bits() > c.v6[j].p.Bits() })
	return c
}

// CIDREntry is one seed row.
type CIDREntry struct {
	CIDR  string
	Label string
}

// Lookup returns the label of the most-specific prefix containing
// the given IP. The empty string means "no match".
func (c *CIDRSet) Lookup(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ""
	}
	list := c.v4
	if addr.Is6() {
		list = c.v6
	}
	for _, e := range list {
		if e.p.Contains(addr) {
			return e.label
		}
	}
	return ""
}

// Size returns the v4 + v6 counts.
func (c *CIDRSet) Size() (int, int) { return len(c.v4), len(c.v6) }

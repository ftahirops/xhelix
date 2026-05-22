// Package destclass classifies outbound network destinations into a
// small set of operationally meaningful categories. It is the data
// layer underneath the egress disarm policy described in
// docs/EGRESS_C2_DISARM_AND_BINARY_INTEGRITY_2026-05-22.md.
//
// The classifier is pure: it takes (ip, sni, port) and returns a
// Decision. It does not block, log, or alert. Callers that want
// enforcement (Mode 2 disarm) consult the decision and apply their
// own policy.
//
// Priority of classification (first match wins):
//
//  1. Intel-bad     — threat-intel hit, any destination
//  2. Private       — RFC1918 / loopback / link-local
//  3. Suffix match  — SNI ends in a known dev-registry / os-update /
//                     cdn / cloud-provider suffix
//  4. CIDR match    — destination IP falls in a well-known cloud-
//                     provider or CDN range
//  5. Fleet baseline — destination seen by ≥N hosts in the fleet
//  6. Unknown       — none of the above; first-seen for this host
//
// Class names are stable strings; treat them as wire-safe.
package destclass

import (
	"net"
	"strings"
	"sync"
)

// Class is a stable wire-safe label.
type Class string

// Class values.
const (
	ClassIntelBad      Class = "intel_bad"
	ClassPrivate       Class = "private"
	ClassDevRegistry   Class = "dev_registry"
	ClassOSUpdate      Class = "os_update"
	ClassCDN           Class = "cdn"
	ClassCloudProvider Class = "cloud_provider"
	ClassFleetBaseline Class = "fleet_baseline"
	ClassUnknown       Class = "unknown"
)

// Decision is the classifier output.
type Decision struct {
	Class  Class
	Reason string
	// Source identifies the table that matched ("static-cidr",
	// "suffix-list:dev_registry", "intel", "fleet:xhub").
	Source string
}

// IntelProvider is the contract pkg/intel.Manager satisfies. Kept as
// an interface to avoid an import cycle and to permit a no-op stub
// in tests.
type IntelProvider interface {
	IsBad(ip net.IP) bool
}

// FleetBaseline answers "how many fleet hosts have observed this
// destination?" Implementations may consult an in-memory cache, a
// local SQLite, or xhub. SeenCount returning ≥ minFleetSeen flips a
// destination to ClassFleetBaseline.
type FleetBaseline interface {
	SeenCount(ip net.IP, sni string) int
}

// noopBaseline is the safe default. Always returns zero.
type noopBaseline struct{}

func (noopBaseline) SeenCount(net.IP, string) int { return 0 }

// noopIntel reports nothing bad.
type noopIntel struct{}

func (noopIntel) IsBad(net.IP) bool { return false }

// Classifier holds the static tables and runtime providers.
type Classifier struct {
	intel        IntelProvider
	fleet        FleetBaseline
	minFleetSeen int

	// mu protects the live CIDR pointers — hot-swappable by SetCIDRs
	// callers (CIDR feed sync goroutine).
	mu sync.RWMutex

	// suffixes are matched against the SNI in priority order.
	registrySuffixes []string
	osUpdateSuffixes []string
	cdnSuffixes      []string
	cloudSuffixes    []string

	// CIDRs are matched against the destination IP.
	cloudCIDRs []*net.IPNet
	cdnCIDRs   []*net.IPNet
}

// SetCloudCIDRs hot-swaps the cloud-provider CIDR table. CIDRs is a
// slice of strings ("1.2.3.0/24"); invalid entries are skipped.
// Designed for periodic feed sync (e.g. AWS ip-ranges.json).
func (c *Classifier) SetCloudCIDRs(cidrs []string) {
	parsed := parseCIDRs(cidrs)
	c.mu.Lock()
	c.cloudCIDRs = parsed
	c.mu.Unlock()
}

// SetCDNCIDRs hot-swaps the CDN CIDR table.
func (c *Classifier) SetCDNCIDRs(cidrs []string) {
	parsed := parseCIDRs(cidrs)
	c.mu.Lock()
	c.cdnCIDRs = parsed
	c.mu.Unlock()
}

// Option configures the classifier.
type Option func(*Classifier)

// WithIntel attaches a threat-intel provider.
func WithIntel(i IntelProvider) Option { return func(c *Classifier) { c.intel = i } }

// WithFleet attaches a fleet-baseline provider and the minimum hosts
// that must have seen a destination before it counts as
// ClassFleetBaseline.
func WithFleet(f FleetBaseline, minHosts int) Option {
	return func(c *Classifier) {
		c.fleet = f
		c.minFleetSeen = minHosts
	}
}

// WithExtraSuffixes appends operator-supplied suffixes to a class.
// Use to add private mirrors, internal registries, etc.
func WithExtraSuffixes(class Class, suffixes ...string) Option {
	return func(c *Classifier) {
		switch class {
		case ClassDevRegistry:
			c.registrySuffixes = append(c.registrySuffixes, suffixes...)
		case ClassOSUpdate:
			c.osUpdateSuffixes = append(c.osUpdateSuffixes, suffixes...)
		case ClassCDN:
			c.cdnSuffixes = append(c.cdnSuffixes, suffixes...)
		case ClassCloudProvider:
			c.cloudSuffixes = append(c.cloudSuffixes, suffixes...)
		}
	}
}

// WithExtraCIDRs appends operator-supplied CIDRs to a class.
func WithExtraCIDRs(class Class, cidrs ...string) Option {
	return func(c *Classifier) {
		for _, s := range cidrs {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				continue
			}
			switch class {
			case ClassCloudProvider:
				c.cloudCIDRs = append(c.cloudCIDRs, n)
			case ClassCDN:
				c.cdnCIDRs = append(c.cdnCIDRs, n)
			}
		}
	}
}

// New constructs a Classifier with sensible built-in defaults. Override
// or extend with Option functions.
func New(opts ...Option) *Classifier {
	c := &Classifier{
		intel:            noopIntel{},
		fleet:            noopBaseline{},
		minFleetSeen:     3,
		registrySuffixes: defaultRegistrySuffixes(),
		osUpdateSuffixes: defaultOSUpdateSuffixes(),
		cdnSuffixes:      defaultCDNSuffixes(),
		cloudSuffixes:    defaultCloudSuffixes(),
		cloudCIDRs:       parseCIDRs(defaultCloudCIDRs()),
		cdnCIDRs:         parseCIDRs(defaultCDNCIDRs()),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Classify is the core call. ip MUST be non-nil; sni MAY be empty
// (e.g. plain TCP with no TLS). port is informational; not used in
// classification today but reserved for future port-based rules.
func (c *Classifier) Classify(ip net.IP, sni string, port uint16) Decision {
	if ip == nil {
		return Decision{Class: ClassUnknown, Reason: "nil destination IP"}
	}
	// 1. Intel-bad wins over everything.
	if c.intel != nil && c.intel.IsBad(ip) {
		return Decision{
			Class:  ClassIntelBad,
			Reason: "threat-intel hit",
			Source: "intel",
		}
	}
	// 2. Private / loopback / link-local — internal traffic, no
	//    internet C2 risk by definition.
	if isPrivate(ip) {
		return Decision{
			Class:  ClassPrivate,
			Reason: "RFC1918 / loopback / link-local",
			Source: "ipnet",
		}
	}
	// 3. SNI suffix matching. Most powerful single signal because
	//    modern egress is overwhelmingly TLS and TLS-with-SNI.
	sni = strings.ToLower(strings.TrimRight(sni, "."))
	if sni != "" {
		if m := matchSuffix(sni, c.registrySuffixes); m != "" {
			return Decision{
				Class: ClassDevRegistry, Reason: "SNI suffix " + m,
				Source: "suffix-list:dev_registry",
			}
		}
		if m := matchSuffix(sni, c.osUpdateSuffixes); m != "" {
			return Decision{
				Class: ClassOSUpdate, Reason: "SNI suffix " + m,
				Source: "suffix-list:os_update",
			}
		}
		if m := matchSuffix(sni, c.cdnSuffixes); m != "" {
			return Decision{
				Class: ClassCDN, Reason: "SNI suffix " + m,
				Source: "suffix-list:cdn",
			}
		}
		if m := matchSuffix(sni, c.cloudSuffixes); m != "" {
			return Decision{
				Class: ClassCloudProvider, Reason: "SNI suffix " + m,
				Source: "suffix-list:cloud_provider",
			}
		}
	}
	// 4. CIDR matching. Static tables cover the major cloud
	//    providers and CDN edges so we can classify even without SNI.
	c.mu.RLock()
	cloud := c.cloudCIDRs
	cdn := c.cdnCIDRs
	c.mu.RUnlock()
	if matchCIDRs(ip, cloud) {
		return Decision{
			Class: ClassCloudProvider, Reason: "IP in cloud CIDR",
			Source: "cidr:cloud",
		}
	}
	if matchCIDRs(ip, cdn) {
		return Decision{
			Class: ClassCDN, Reason: "IP in CDN CIDR",
			Source: "cidr:cdn",
		}
	}
	// 5. Fleet baseline.
	if c.fleet != nil && c.minFleetSeen > 0 {
		if c.fleet.SeenCount(ip, sni) >= c.minFleetSeen {
			return Decision{
				Class: ClassFleetBaseline,
				Reason: "destination observed by ≥ minFleetSeen fleet hosts",
				Source: "fleet",
			}
		}
	}
	// 6. Truly unknown.
	return Decision{
		Class:  ClassUnknown,
		Reason: "no static or fleet match",
		Source: "default",
	}
}

// matchSuffix returns the suffix that matched sni, or "".
func matchSuffix(sni string, suffixes []string) string {
	for _, s := range suffixes {
		if sni == s || strings.HasSuffix(sni, "."+s) {
			return s
		}
	}
	return ""
}

func matchCIDRs(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isPrivate reports whether ip is RFC1918 / loopback / link-local /
// unspecified / IPv6 ULA. We use the stdlib classifiers and add the
// CGNAT range (100.64.0.0/10) because it's another class of
// non-internet traffic.
func isPrivate(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsMulticast() {
		return true
	}
	// CGNAT 100.64.0.0/10.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && (v4[1]&0xC0) == 64 {
			return true
		}
	}
	return false
}

func parseCIDRs(strs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(strs))
	for _, s := range strs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

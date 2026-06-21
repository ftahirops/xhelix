// Package egressresolve resolves operator-declared FQDNs to IP CIDRs for
// the pre-start egress allowlist (SP-1b.2a). Resolution happens AT ARM
// TIME — it is a static snapshot, not a live tracker. The Resolver is an
// interface so the arm path is testable without real DNS, and so the
// production path can stay on the pure-Go net.DefaultResolver (required
// under CGO_ENABLED=0).
package egressresolve

import (
	"context"
	"fmt"
	"net"
	"sort"
)

// Resolver resolves a hostname to IPs. net.DefaultResolver satisfies the
// shape via Default().
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

type stdResolver struct{ r *net.Resolver }

func (s stdResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := s.r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// Default returns a Resolver backed by the pure-Go net.DefaultResolver.
func Default() Resolver { return stdResolver{r: net.DefaultResolver} }

// ResolveCIDRs resolves each FQDN to host-route CIDRs (ip/32 for IPv4,
// ip/128 for IPv6), de-duplicated and sorted for a stable drop-in. It
// returns an error naming the first FQDN that resolved to ZERO IPs, so the
// caller can refuse to install an egress lockdown that would block it.
func ResolveCIDRs(ctx context.Context, r Resolver, fqdns []string) ([]string, error) {
	if len(fqdns) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, fqdn := range fqdns {
		ips, err := r.LookupIP(ctx, fqdn)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("egressresolve: %q resolved to no IPs: %v", fqdn, err)
		}
		for _, ip := range ips {
			cidr := ipToHostCIDR(ip)
			if cidr == "" || seen[cidr] {
				continue
			}
			seen[cidr] = true
			out = append(out, cidr)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ipToHostCIDR formats an IP as a single-host CIDR. Returns "" for a nil/
// invalid IP.
func ipToHostCIDR(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String() + "/32"
	}
	if ip.To16() != nil {
		return ip.String() + "/128"
	}
	return ""
}

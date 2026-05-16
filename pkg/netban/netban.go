// Package netban implements automatic IP banning via nftables and
// the XDP drop set.
//
// Banning is layered:
//   1. nftables: blocks at the kernel netfilter layer (always works)
//   2. XDP drop set: drops at the NIC driver layer (faster, available
//      when xhelix's eBPF backend is loaded)
//
// We add to both when both are available. nftables is idempotent and
// reversible via TTL; XDP drop set has its own admin path.
//
// Localhost / RFC1918 protections live in the response engine, not
// here — netban is a pure mechanism.
package netban

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// XDPAdmin is implemented by pkg/xdpadmin.Admin; we accept the
// interface so we don't pull a concrete dep.
type XDPAdmin interface {
	Add(ip net.IP) error
	Remove(ip net.IP) error
	List() ([]net.IP, error)
}

// Banner is the public API.
type Banner struct {
	xdp     XDPAdmin
	useNFT  bool

	mu      sync.Mutex
	entries map[string]*entry

	quarantineOn atomic.Bool

	// SkipOperatorIPCheck disables the safety check that EngageQuarantine
	// performs to ensure the active SSH peer is in the allow-list.
	// Default false. Set to true ONLY for headless automation that
	// runs outside an SSH session (e.g. cron-driven incident response).
	SkipOperatorIPCheck bool
}

type entry struct {
	ip      net.IP
	reason  string
	addedAt time.Time
	expires time.Time
}

// NewBanner returns a banner. Pass an XDPAdmin (or nil to disable
// NIC-level drops) and useNFT=true to install nftables rules.
func NewBanner(xdp XDPAdmin, useNFT bool) *Banner {
	return &Banner{
		xdp:     xdp,
		useNFT:  useNFT,
		entries: map[string]*entry{},
	}
}

// EnsureNFT creates the xhelix nftables table + chain + set if they
// don't exist. Idempotent — safe to call repeatedly.
//
// Layout:
//   table inet xhelix {
//     set bad_ips_v4 { type ipv4_addr; flags timeout; }
//     chain input { type filter hook input priority -10;
//                   ip saddr @bad_ips_v4 drop; }
//   }
func (b *Banner) EnsureNFT(ctx context.Context) error {
	if !b.useNFT {
		return nil
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("netban: nft not installed: %w", err)
	}
	cmds := [][]string{
		{"nft", "add", "table", "inet", "xhelix"},
		{"nft", "add", "set", "inet", "xhelix", "bad_ips_v4",
			"{ type ipv4_addr; flags timeout; }"},
		{"nft", "add", "set", "inet", "xhelix", "bad_ips_v6",
			"{ type ipv6_addr; flags timeout; }"},
		{"nft", "add", "chain", "inet", "xhelix", "input",
			"{ type filter hook input priority -10; }"},
		{"nft", "add", "rule", "inet", "xhelix", "input",
			"ip saddr @bad_ips_v4 drop"},
		{"nft", "add", "rule", "inet", "xhelix", "input",
			"ip6 saddr @bad_ips_v6 drop"},
	}
	for _, c := range cmds {
		cmd := exec.CommandContext(ctx, c[0], c[1:]...)
		// nft errors on duplicate-add are fine.
		_ = cmd.Run()
	}
	return nil
}

// Ban adds ip to both the nftables drop set (with timeout) and the
// XDP drop set. Returns first error.
//
// ttl <= 0 selects 1 hour. nftables enforces the timeout natively;
// XDP drops persist until Unban or restart.
func (b *Banner) Ban(ip net.IP, reason string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = time.Hour
	}
	b.mu.Lock()
	b.entries[ip.String()] = &entry{
		ip: ip, reason: reason, addedAt: time.Now(),
		expires: time.Now().Add(ttl),
	}
	b.mu.Unlock()

	var firstErr error
	if b.xdp != nil {
		if err := b.xdp.Add(ip); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if b.useNFT {
		if err := b.nftAdd(ip, ttl); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Unban removes ip from both sets.
func (b *Banner) Unban(ip net.IP) error {
	b.mu.Lock()
	delete(b.entries, ip.String())
	b.mu.Unlock()

	var firstErr error
	if b.xdp != nil {
		if err := b.xdp.Remove(ip); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if b.useNFT {
		if err := b.nftDel(ip); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// List returns a snapshot of current bans.
func (b *Banner) List() ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.entries))
	for k := range b.entries {
		out = append(out, k)
	}
	return out, nil
}

// Sweep removes expired entries. Run on a 60s ticker.
func (b *Banner) Sweep() {
	now := time.Now()
	b.mu.Lock()
	expired := make([]net.IP, 0)
	for k, e := range b.entries {
		if now.After(e.expires) {
			expired = append(expired, e.ip)
			delete(b.entries, k)
		}
	}
	b.mu.Unlock()
	for _, ip := range expired {
		if b.xdp != nil {
			_ = b.xdp.Remove(ip)
		}
		if b.useNFT {
			_ = b.nftDel(ip)
		}
	}
}

func (b *Banner) nftAdd(ip net.IP, ttl time.Duration) error {
	setName := "bad_ips_v4"
	if ip.To4() == nil {
		setName = "bad_ips_v6"
	}
	cmd := exec.Command("nft", "add", "element", "inet", "xhelix",
		setName, fmt.Sprintf("{ %s timeout %ds }", ip.String(), int(ttl.Seconds())))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft add: %w (%s)", err, out)
	}
	return nil
}

func (b *Banner) nftDel(ip net.IP) error {
	setName := "bad_ips_v4"
	if ip.To4() == nil {
		setName = "bad_ips_v6"
	}
	cmd := exec.Command("nft", "delete", "element", "inet", "xhelix",
		setName, fmt.Sprintf("{ %s }", ip.String()))
	if out, err := cmd.CombinedOutput(); err != nil {
		// "No such file or directory" on missing element is fine.
		if len(out) > 0 && string(out) != "" {
			return errors.New("nft delete: " + string(out))
		}
	}
	return nil
}

// Stats reports current ban counters.
type Stats struct {
	Active uint64
}

// Stats returns ban counters for the dashboard.
func (b *Banner) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Stats{Active: uint64(len(b.entries))}
}

package netban

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// Host quarantine — drop ALL inbound and outbound except a small
// allow-list of management IPs (typically the operator's SSH client).
//
// Mechanism: a separate nftables table "xhelix_quarantine" with two
// chains, both at priority -200 so they fire before any other rule
// (including the regular xhelix bad_ips chain). Default policy drop;
// allow-list is matched by source on input and destination on output,
// plus loopback and established/related connections so the operator
// keeps their SSH session and so xhelix's own webhook responses
// complete.
//
// The contract: while quarantine is active, the host is functionally
// disconnected from the network except for the operator. Lifting it
// is a single Disengage() call which deletes the table.

// Quarantined reports whether host quarantine is currently engaged.
func (b *Banner) Quarantined() bool { return b.quarantineOn.Load() }

// EngageQuarantine drops the host into network-isolation mode.
// allowIPs is the management allow-list — empty list refuses (would
// lock the operator out). Loopback is always allowed.
//
// Idempotent: calling while engaged updates the allow-list.
//
// Safety check: if the operator has an active SSH session, we read
// /proc/net/tcp[+6] for established :22 connections and verify at
// least one peer IP is in allowIPs. If none match, refuse — that
// mismatch means engaging would drop the operator's reconnect path
// even though the existing TCP session survives via ct established.
// Set b.SkipOperatorIPCheck = true (e.g. for headless automation
// running outside an SSH session) to bypass.
func (b *Banner) EngageQuarantine(ctx context.Context, allowIPs []string) error {
	if len(allowIPs) == 0 {
		return errors.New("netban: refusing to engage quarantine with empty allow-list")
	}
	if !b.SkipOperatorIPCheck {
		if peers, _ := activeSSHPeers(); len(peers) > 0 {
			matched := false
			for _, p := range peers {
				for _, a := range allowIPs {
					if strings.TrimSpace(a) == p {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				return fmt.Errorf("netban: refusing — active SSH peer(s) %v not in allow-list %v "+
					"(set SkipOperatorIPCheck to override)", peers, allowIPs)
			}
		}
	}
	if !b.useNFT {
		return errors.New("netban: quarantine requires nftables")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("netban: nft not installed: %w", err)
	}

	// Validate allow-list before touching nft.
	parsed := make([]net.IP, 0, len(allowIPs))
	for _, s := range allowIPs {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			return fmt.Errorf("netban: invalid allow IP %q", s)
		}
		parsed = append(parsed, ip)
	}

	// Tear down any prior quarantine first so we re-create with the
	// new allow-list atomically (nft applies in one txn per command).
	_ = b.nftFlushQuarantine(ctx)

	v4 := make([]string, 0)
	v6 := make([]string, 0)
	for _, ip := range parsed {
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}

	build := [][]string{
		{"add", "table", "inet", "xhelix_quarantine"},
		{"add", "chain", "inet", "xhelix_quarantine", "input",
			"{ type filter hook input priority -200; policy drop; }"},
		{"add", "chain", "inet", "xhelix_quarantine", "output",
			"{ type filter hook output priority -200; policy drop; }"},
		// Loopback always allowed.
		{"add", "rule", "inet", "xhelix_quarantine", "input", "iif", "lo", "accept"},
		{"add", "rule", "inet", "xhelix_quarantine", "output", "oif", "lo", "accept"},
		// Established/related — preserves the operator's existing SSH.
		{"add", "rule", "inet", "xhelix_quarantine", "input",
			"ct", "state", "established,related", "accept"},
		{"add", "rule", "inet", "xhelix_quarantine", "output",
			"ct", "state", "established,related", "accept"},
	}
	for _, c := range build {
		args := append([]string{}, c...)
		if err := exec.CommandContext(ctx, "nft", args...).Run(); err != nil {
			return fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
		}
	}

	// Allow-list rules.
	if len(v4) > 0 {
		set := "{ " + strings.Join(v4, ", ") + " }"
		for _, c := range [][]string{
			{"add", "rule", "inet", "xhelix_quarantine", "input", "ip", "saddr", set, "accept"},
			{"add", "rule", "inet", "xhelix_quarantine", "output", "ip", "daddr", set, "accept"},
		} {
			if err := exec.CommandContext(ctx, "nft", c...).Run(); err != nil {
				return fmt.Errorf("nft allow v4: %w", err)
			}
		}
	}
	if len(v6) > 0 {
		set := "{ " + strings.Join(v6, ", ") + " }"
		for _, c := range [][]string{
			{"add", "rule", "inet", "xhelix_quarantine", "input", "ip6", "saddr", set, "accept"},
			{"add", "rule", "inet", "xhelix_quarantine", "output", "ip6", "daddr", set, "accept"},
		} {
			if err := exec.CommandContext(ctx, "nft", c...).Run(); err != nil {
				return fmt.Errorf("nft allow v6: %w", err)
			}
		}
	}

	b.quarantineOn.Store(true)
	return nil
}

// DisengageQuarantine deletes the quarantine table, restoring full
// connectivity. Idempotent.
func (b *Banner) DisengageQuarantine(ctx context.Context) error {
	if err := b.nftFlushQuarantine(ctx); err != nil {
		return err
	}
	b.quarantineOn.Store(false)
	return nil
}

func (b *Banner) nftFlushQuarantine(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "nft", "delete", "table", "inet", "xhelix_quarantine")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// "No such file or directory" means the table never existed; that's fine.
		if strings.Contains(string(out), "No such file") {
			return nil
		}
		return fmt.Errorf("nft delete table: %w (%s)", err, out)
	}
	return nil
}


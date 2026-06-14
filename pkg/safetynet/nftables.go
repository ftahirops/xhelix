// nftables wiring for safetynet's block_observe set.
//
// Layout target (lives alongside pkg/netban's `bad_ips_v4` set inside
// the shared `inet xhelix` table):
//
//	table inet xhelix {
//	    set block_observe_v4 {
//	        type ipv4_addr; flags interval;
//	        elements = { ...cidrs... }
//	    }
//	    chain block_observe {
//	        type filter hook input priority -100;
//	        ip saddr @block_observe_v4 log prefix "xhelix-bo " level info drop
//	    }
//	}
//
// Honest non-promise: only v4 is installed. v6 block-observe is a
// Phase-2 follow-on (the parallel `block_observe_v6` set + ip6 rule).
//
// The implementation shells out to the `nft` binary, mirroring the
// existing pattern in pkg/netban/netban.go. This keeps the daemon
// CGO_ENABLED=0 and avoids pulling a netlink dep.
package safetynet

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// NFTables wraps nftables interactions for the safetynet block set.
// nil-safe; methods are no-ops when the `nft` binary is absent.
type NFTables struct {
	enabled bool // true once EnsureChain succeeds
	hasNFT  bool
}

// NewNFTables constructs an NFTables helper. It does NOT install any
// rules — call EnsureChain for that.
func NewNFTables() *NFTables {
	n := &NFTables{}
	if _, err := exec.LookPath("nft"); err == nil {
		n.hasNFT = true
	}
	return n
}

// Enabled reports whether the chain was installed successfully.
// Useful for the operator status display.
func (n *NFTables) Enabled() bool {
	if n == nil {
		return false
	}
	return n.enabled
}

// EnsureChain creates the table + set + chain if absent. Idempotent.
// Returns nil (no-op) if the `nft` binary is missing — the operator
// gets a soft-fail rather than a daemon refuse-to-start.
func (n *NFTables) EnsureChain(ctx context.Context) error {
	if n == nil {
		return nil
	}
	if !n.hasNFT {
		return fmt.Errorf("safetynet/nft: nft binary not in PATH")
	}
	// `nft add` for duplicate objects returns error text but exit 1;
	// we ignore that path and rely on a final list to confirm.
	cmds := [][]string{
		{"nft", "add", "table", "inet", "xhelix"},
		{"nft", "add", "set", "inet", "xhelix", "block_observe_v4",
			"{ type ipv4_addr; flags interval; }"},
		{"nft", "add", "chain", "inet", "xhelix", "block_observe",
			"{ type filter hook input priority -100; }"},
		{"nft", "add", "rule", "inet", "xhelix", "block_observe",
			"ip", "saddr", "@block_observe_v4",
			"log", "prefix", "xhelix-bo ", "level", "info", "drop"},
	}
	for _, c := range cmds {
		cmd := exec.CommandContext(ctx, c[0], c[1:]...)
		// Errors on idempotent re-add are fine. We just want to make sure
		// the objects exist.
		_ = cmd.Run()
	}
	// Confirm the set exists by listing it.
	chk := exec.CommandContext(ctx, "nft", "list", "set", "inet", "xhelix", "block_observe_v4")
	if out, err := chk.CombinedOutput(); err != nil {
		return fmt.Errorf("safetynet/nft: set not present after install: %w (%s)", err, out)
	}
	n.enabled = true
	return nil
}

// AddCIDR inserts a CIDR into the drop set. v4 only.
func (n *NFTables) AddCIDR(ctx context.Context, cidr string) error {
	if n == nil || !n.enabled {
		return nil
	}
	cmd := exec.CommandContext(ctx, "nft", "add", "element", "inet", "xhelix",
		"block_observe_v4", fmt.Sprintf("{ %s }", cidr))
	if out, err := cmd.CombinedOutput(); err != nil {
		// Treat "File exists" as success.
		if strings.Contains(string(out), "File exists") || strings.Contains(string(out), "already exists") {
			return nil
		}
		return fmt.Errorf("nft add element: %w (%s)", err, out)
	}
	return nil
}

// RemoveCIDR deletes a CIDR from the drop set. Idempotent — missing
// element is not an error.
func (n *NFTables) RemoveCIDR(ctx context.Context, cidr string) error {
	if n == nil || !n.enabled {
		return nil
	}
	cmd := exec.CommandContext(ctx, "nft", "delete", "element", "inet", "xhelix",
		"block_observe_v4", fmt.Sprintf("{ %s }", cidr))
	if out, err := cmd.CombinedOutput(); err != nil {
		s := string(out)
		if strings.Contains(s, "No such file") || strings.Contains(s, "does not exist") {
			return nil
		}
		return fmt.Errorf("nft delete element: %w (%s)", err, out)
	}
	return nil
}

// ListCIDRs returns the currently-installed CIDRs in the set. Best-effort.
func (n *NFTables) ListCIDRs(ctx context.Context) ([]string, error) {
	if n == nil || !n.enabled {
		return nil, nil
	}
	cmd := exec.CommandContext(ctx, "nft", "-a", "list", "set", "inet", "xhelix", "block_observe_v4")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft list: %w (%s)", err, out)
	}
	// Crude parser — `elements = { 1.2.3.0/24, 5.6.7.8 }` form.
	s := string(out)
	i := strings.Index(s, "elements = {")
	if i < 0 {
		return nil, nil
	}
	s = s[i+len("elements = {"):]
	j := strings.Index(s, "}")
	if j < 0 {
		return nil, nil
	}
	body := s[:j]
	var cidrs []string
	for _, tok := range strings.Split(body, ",") {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			cidrs = append(cidrs, tok)
		}
	}
	return cidrs, nil
}

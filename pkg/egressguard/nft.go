package egressguard

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// nft.go — nftables backend helpers. Pattern follows pkg/netban: shell
// out to the `nft` binary. The table/chain/set provisioning is
// idempotent (uses `nft add ... ; create ignored on existing`).

const (
	nftTable   = "xhelix_egress"
	nftChain   = "xhelix_egress_out"
	nftSetV4   = "xhelix_egress_deny_v4"
	nftSetV6   = "xhelix_egress_deny_v6"
)

var (
	nftBinaryPath   string
	nftBinaryProbe  sync.Once
	nftTableEnsured sync.Once
	nftTableErr     error
)

func nftBinaryAvailable() bool {
	nftBinaryProbe.Do(func() {
		path, err := exec.LookPath("nft")
		if err == nil {
			nftBinaryPath = path
		}
	})
	return nftBinaryPath != ""
}

// ensureNFTTable creates table + chain + sets if absent. Idempotent.
// Run lazily on the first Push, so a host with nft installed but never
// pushed-to doesn't have spurious table state.
func ensureNFTTable() error {
	nftTableEnsured.Do(func() {
		if !nftBinaryAvailable() {
			nftTableErr = fmt.Errorf("nft binary not available")
			return
		}
		cmds := [][]string{
			{"add", "table", "inet", nftTable},
			{"add", "set", "inet", nftTable, nftSetV4,
				"{ type ipv4_addr; flags timeout; }"},
			{"add", "set", "inet", nftTable, nftSetV6,
				"{ type ipv6_addr; flags timeout; }"},
			{"add", "chain", "inet", nftTable, nftChain,
				"{ type filter hook output priority 0; policy accept; }"},
			// Drop rule for v4 / v6 sets. nft rejects duplicate rules,
			// so check first via list. Simple approach: flush chain
			// and re-add. Acceptable here because xhelix_egress is
			// xhelix-owned.
		}
		for _, c := range cmds {
			args := append([]string{}, c...)
			out, err := exec.Command(nftBinaryPath, args...).CombinedOutput()
			if err != nil && !strings.Contains(string(out), "File exists") {
				nftTableErr = fmt.Errorf("nft %v: %w (%s)", c, err, out)
				return
			}
		}
		// Now flush chain + add the deny rules.
		exec.Command(nftBinaryPath, "flush", "chain", "inet",
			nftTable, nftChain).Run()
		ruleV4 := []string{"add", "rule", "inet", nftTable, nftChain,
			"ip", "daddr", "@" + nftSetV4, "drop"}
		ruleV6 := []string{"add", "rule", "inet", nftTable, nftChain,
			"ip6", "daddr", "@" + nftSetV6, "drop"}
		if out, err := exec.Command(nftBinaryPath, ruleV4...).CombinedOutput(); err != nil {
			nftTableErr = fmt.Errorf("nft add rule v4: %w (%s)", err, out)
			return
		}
		if out, err := exec.Command(nftBinaryPath, ruleV6...).CombinedOutput(); err != nil {
			nftTableErr = fmt.Errorf("nft add rule v6: %w (%s)", err, out)
			return
		}
	})
	return nftTableErr
}

func nftAddDeny(dest string, ttl time.Duration) error {
	ip := net.ParseIP(dest)
	if ip == nil {
		return fmt.Errorf("egressguard nft: dest %q is not an IP", dest)
	}
	set := nftSetV4
	if ip.To4() == nil {
		set = nftSetV6
	}
	ttlStr := fmt.Sprintf("%ds", int(ttl.Seconds()))
	cmd := []string{"add", "element", "inet", nftTable, set,
		fmt.Sprintf("{ %s timeout %s }", ip.String(), ttlStr)}
	out, err := exec.Command(nftBinaryPath, cmd...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft add element: %w (%s)", err, out)
	}
	return nil
}

func nftDelDeny(dest string) error {
	ip := net.ParseIP(dest)
	if ip == nil {
		return fmt.Errorf("egressguard nft: dest %q is not an IP", dest)
	}
	set := nftSetV4
	if ip.To4() == nil {
		set = nftSetV6
	}
	cmd := []string{"delete", "element", "inet", nftTable, set,
		fmt.Sprintf("{ %s }", ip.String())}
	out, err := exec.Command(nftBinaryPath, cmd...).CombinedOutput()
	if err != nil {
		// Idempotent delete: not-found is OK.
		if strings.Contains(string(out), "No such file") ||
			strings.Contains(string(out), "does not exist") {
			return nil
		}
		return fmt.Errorf("nft del element: %w (%s)", err, out)
	}
	return nil
}

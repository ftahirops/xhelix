package doctor

import (
	"context"
	"fmt"
	"strings"
)

// firewallChecks audit nftables / iptables and the listening surface.
// We don't try to encode "the right firewall ruleset" — we check the
// existence of any policy and the listening surface.
func firewallChecks() []Check {
	return []Check{
		{
			ID:       "firewall.active",
			Title:    "Firewall (nftables or iptables) has rules loaded",
			Category: "firewall",
			Severity: SeverityHigh,
			Description: "An empty firewall is the default state on minimal images. Production hosts need at least default-drop with explicit allows.",
			Impact:      "Without a firewall, every listening socket is internet-reachable if the network is. Misconfigured services become trivial entry points.",
			Recommendation: "Install ufw, firewalld, nftables-config, or hand-write nftables rules. At minimum: `nft add table inet filter; nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'` plus your accept rules.",
			Run: func(ctx context.Context) Result {
				if has, evidence := hasNftablesRules(ctx); has {
					return PassResult("nftables: " + evidence)
				}
				if has, evidence := hasIptablesRules(ctx); has {
					return PassResult("iptables: " + evidence)
				}
				return FailResult("no nftables or iptables rules loaded")
			},
		},
		{
			ID:       "firewall.listening_surface",
			Title:    "Listening TCP surface is small",
			Category: "firewall",
			Severity: SeverityMedium,
			Description: "Each listening port is a potential entry point. Audit `ss -tlnp` against a known-good list periodically.",
			Impact:      "Forgotten test daemons, misconfigured Docker bind-alls, or stray databases listening on 0.0.0.0 are how breaches start.",
			Recommendation: "Run `ss -tlnp` and reconcile against your inventory. Bind everything internal to 127.0.0.1 or use a unix socket.",
			Run: func(ctx context.Context) Result {
				ports, err := listeningTCP(ctx)
				if err != nil {
					return ErrorResult(err)
				}
				public := filterPublic(ports)
				switch {
				case len(public) == 0:
					return PassResult("no externally-bound TCP listeners")
				case len(public) <= 3:
					return PassResult(fmt.Sprintf("%d public listeners: %s",
						len(public), strings.Join(public, " ")))
				default:
					return WarnResult(fmt.Sprintf("%d public listeners: %s",
						len(public), strings.Join(public, " ")))
				}
			},
		},
	}
}

func hasNftablesRules(ctx context.Context) (bool, string) {
	out, err := runOutput(ctx, "nft", "list", "ruleset")
	if err != nil {
		return false, ""
	}
	if strings.TrimSpace(out) == "" {
		return false, ""
	}
	// "table" appearing means at least one table is loaded.
	if strings.Contains(out, "table ") {
		nTables := strings.Count(out, "\ntable ")
		if strings.HasPrefix(out, "table ") {
			nTables++
		}
		return true, fmt.Sprintf("%d tables", nTables)
	}
	return false, ""
}

func hasIptablesRules(ctx context.Context) (bool, string) {
	out, err := runOutput(ctx, "iptables", "-S")
	if err != nil {
		return false, ""
	}
	// `-S` always prints chain policies even when empty; look for at
	// least one explicit -A rule.
	if strings.Contains(out, "-A ") {
		return true, fmt.Sprintf("%d rules", strings.Count(out, "-A "))
	}
	return false, ""
}

// listeningTCP returns "addr:port/proc" strings parsed from ss output.
func listeningTCP(ctx context.Context) ([]string, error) {
	out, err := runOutput(ctx, "ss", "-tlnH")
	if err != nil {
		return nil, err
	}
	var ports []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// ss columns: state recv-q send-q local-addr peer-addr [proc]
		ports = append(ports, fields[3])
	}
	return ports, nil
}

// filterPublic keeps entries that bind to a non-loopback address —
// i.e. *, 0.0.0.0, [::], or any non-127.x.x.x / non-::1 IP.
func filterPublic(ports []string) []string {
	var out []string
	for _, p := range ports {
		// p looks like "0.0.0.0:22" or "[::]:80" or "127.0.0.1:5432"
		switch {
		case strings.HasPrefix(p, "127."):
			continue
		case strings.HasPrefix(p, "[::1]"):
			continue
		case strings.HasPrefix(p, "[fe80"):
			// link-local; not really public but not loopback either
			out = append(out, p)
		default:
			out = append(out, p)
		}
	}
	return out
}

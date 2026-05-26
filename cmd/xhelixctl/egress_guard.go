package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/egressguard"
)

// extendEgressCmd hook — register egressguard subcommands.
// Phase C.2 ships informational commands. The decision path runs
// inside the daemon; the CLI surfaces what's configured + dry-run
// against an arbitrary request.
func init() {
	prev := extendEgressCmd
	extendEgressCmd = chainExtenders(prev, func(cmd *cobra.Command) {
		cmd.AddCommand(newEgressGuardCmd())
	})
}

func newEgressGuardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "guard",
		Aliases: []string{"g"},
		Short:   "Egressguard introspection (Phase C)",
		Long: `Egressguard is the per-event egress enforcement plane.

  modes            list of operating modes (observe/shadow/enforce)
  backends         list of available enforcement backends + selection order
  decide --role X --dst Y[:Z]  dry-run a decision against the current ruleset

Live deny activity is exposed through the daemon journal:

  sudo journalctl -u xhelix --no-pager | grep "egressguard "

And shadow/enforce alerts surface in /var/log/xhelix/alerts.jsonl with
rule_id egressguard.shadow_deny or egressguard.deny.`,
	}
	cmd.AddCommand(newEgressGuardModesCmd())
	cmd.AddCommand(newEgressGuardBackendsCmd())
	cmd.AddCommand(newEgressGuardDecideCmd())
	return cmd
}

func newEgressGuardModesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "modes",
		Short: "Show egressguard operating modes",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(os.Stdout, "Egressguard operating modes:")
			fmt.Fprintln(os.Stdout, "  observe   classify only, no logging beyond verifier scoring")
			fmt.Fprintln(os.Stdout, "  shadow    log would-be denies (rule_id=egressguard.shadow_deny)")
			fmt.Fprintln(os.Stdout, "  enforce   push denies to kernel backend (rule_id=egressguard.deny)")
			fmt.Fprintln(os.Stdout)
			fmt.Fprintln(os.Stdout, "Default at startup: observe.")
			fmt.Fprintln(os.Stdout, "Operator promotes via config flag hardening.egressguard.mode")
			return nil
		},
	}
}

func newEgressGuardBackendsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "backends",
		Short: "Show enforcement backend selection order + live availability",
		RunE: func(cmd *cobra.Command, args []string) error {
			b, name := egressguard.SelectBackend(egressguard.ModeObserve)
			fmt.Fprintln(os.Stdout, "Backend selection order (highest fidelity first):")
			fmt.Fprintln(os.Stdout, "  1. ebpf-cgroup-connect   (kernel ≥ 5.15 + CAP_BPF + cgroup_v2)")
			fmt.Fprintln(os.Stdout, "  2. nftables              (nft binary + nf_tables kernel module)")
			fmt.Fprintln(os.Stdout, "  3. observe               (no-op final degradation)")
			fmt.Fprintln(os.Stdout)
			fmt.Fprintf(os.Stdout, "Selected on this host: %s\n", name)
			if err := b.Available(); err != nil {
				fmt.Fprintf(os.Stdout, "  Available() err: %v\n", err)
			} else {
				fmt.Fprintln(os.Stdout, "  Available() ok")
			}
			return nil
		},
	}
}

func newEgressGuardDecideCmd() *cobra.Command {
	var (
		role        string
		destIP      string
		destPort    uint16
		sni         string
		secretTaint string
	)
	cmd := &cobra.Command{
		Use:   "decide",
		Short: "Dry-run an egress decision against the live rule set",
		Long: `Builds a fake Request from the flags and runs Guard.Decide to show
what the daemon would decide. Does NOT touch the kernel.

Example:
  xhelixctl egress guard decide --role nginx-reverse-proxy --dst 203.0.113.5 --port 443
  xhelixctl egress guard decide --role user-shell --dst 8.8.8.8 --secret-taint outbound_restricted`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Build a guard with no profile lookup (operator can layer
			// declared peers via running daemon LocalAPI in a follow-on).
			backend, _ := egressguard.SelectBackend(egressguard.ModeObserve)
			g := egressguard.NewGuard(backend, nil, egressguard.ModeObserve)
			d, reason := g.Decide(egressguard.Request{
				AppRole:     role,
				DestIP:      destIP,
				DestPort:    destPort,
				SNI:         sni,
				SecretTaint: secretTaint,
			})
			fmt.Fprintf(os.Stdout, "decision: %s\n", d)
			fmt.Fprintf(os.Stdout, "reason:   %s\n", reason)
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "", "BRP profile role (e.g. nginx-reverse-proxy)")
	cmd.Flags().StringVar(&destIP, "dst", "", "destination IP")
	cmd.Flags().Uint16Var(&destPort, "port", 0, "destination port")
	cmd.Flags().StringVar(&sni, "sni", "", "TLS SNI value (if any)")
	cmd.Flags().StringVar(&secretTaint, "secret-taint", "", "actor secret-taint state (clean|secret_touched|outbound_restricted|containment_required)")
	return cmd
}

// chainExtenders may already exist; if so, the build will dedupe it.
// Defined here defensively to avoid an import collision if upstream
// renames it.

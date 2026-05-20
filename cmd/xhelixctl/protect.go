package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/localapi"
	"github.com/xhelix/xhelix/pkg/protectsvcapi"
)

func newProtectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "protect",
		Short: "Inspect Protected Services state (read-only)",
		Long:  `Query the daemon for the protected-service registry: list services, view the resolved contract, see deception-layer coverage, and surface residual risk.`,
	}
	cmd.AddCommand(newProtectListCmd())
	cmd.AddCommand(newProtectContractCmd())
	cmd.AddCommand(newProtectDeceptionCmd())
	cmd.AddCommand(newProtectResidualCmd())
	return cmd
}

func newProtectListCmd() *cobra.Command {
	var (
		sock    string
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all protected services configured on this host",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var out []protectsvcapi.ServiceSummary
			if err := c.Call("protected.list", struct{}{}, &out); err != nil {
				return err
			}
			if jsonOut {
				return jsonPrint(out)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tKIND\tROLE\tUNIT\tEXEC\tDECEPTION\tWRITES\tUPSTREAMS\tSTRICT")
			for _, s := range out {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%v\n",
					s.Name, s.Kind, s.Role, dashIfEmpty(s.Unit),
					s.ExecPath, s.DeceptionMode,
					s.WriteRootsCount, s.UpstreamsCount, s.StrictReadOnly)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON instead of a table")
	return cmd
}

func newProtectContractCmd() *cobra.Command {
	var (
		sock    string
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "contract <name>",
		Short: "Show the resolved contract for one protected service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var cv protectsvcapi.ContractView
			if err := c.Call("protected.contract", map[string]string{"name": args[0]}, &cv); err != nil {
				return err
			}
			if jsonOut {
				return jsonPrint(cv)
			}
			fmt.Printf("Service: %s\n", cv.Name)
			fmt.Printf("  strict_read_only: %v\n", cv.Contract.StrictReadOnly)
			fmt.Printf("  deny exec paths: %d (incl %d never-learnable)\n", cv.DenyExecCount, cv.NeverLearnedCount)
			fmt.Printf("  allow exec paths: %d\n", cv.AllowExecCount)
			fmt.Printf("  deny syscalls: %d\n", cv.DenySyscallCount)
			fmt.Println("  write roots:")
			for _, w := range cv.Contract.WriteRoots {
				fmt.Printf("    %s\n", w)
			}
			if len(cv.Contract.UpstreamCIDRs) > 0 {
				fmt.Println("  upstream CIDRs:")
				for _, u := range cv.Contract.UpstreamCIDRs {
					fmt.Printf("    %s\n", u)
				}
			} else {
				fmt.Println("  upstream CIDRs: (none — service cannot reach upstream IPs)")
			}
			if len(cv.Contract.UnixSockets) > 0 {
				fmt.Println("  unix sockets:")
				for _, u := range cv.Contract.UnixSockets {
					fmt.Printf("    %s\n", u)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON instead of human format")
	return cmd
}

func newProtectDeceptionCmd() *cobra.Command {
	var (
		sock    string
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "deception",
		Short: "Show which Ring 2 trap layers are active per service",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var covs []protectsvcapi.DeceptionCoverage
			if err := c.Call("protected.deception_cov", struct{}{}, &covs); err != nil {
				return err
			}
			if jsonOut {
				return jsonPrint(covs)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tENABLED\tFAKE_EXEC\tSINKHOLE\tDECOY_FS\tPOISON_DNS\tSCORE")
			for _, c := range covs {
				fmt.Fprintf(tw, "%s\t%v\t%s\t%s\t%s\t%s\t%d/4\n",
					c.Name, c.Enabled,
					checkmark(c.FakeExec), checkmark(c.Sinkhole),
					checkmark(c.DecoyFS), checkmark(c.PoisonDNS), c.Score)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON instead of a table")
	return cmd
}

func newProtectResidualCmd() *cobra.Command {
	var (
		sock    string
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "residual <name>",
		Short: "Show residual risk for one protected service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var rr protectsvcapi.ResidualRisk
			if err := c.Call("protected.residual_risk", map[string]string{"name": args[0]}, &rr); err != nil {
				return err
			}
			if jsonOut {
				return jsonPrint(rr)
			}
			fmt.Printf("Service: %s\n", rr.Name)
			fmt.Println("\nReadable sensitive paths (NOT denied by current contract):")
			for _, p := range rr.ReadablePaths {
				fmt.Printf("  %s\n", p)
			}
			fmt.Println("\nReachable upstream CIDRs:")
			for _, u := range rr.ReachableUpstreams {
				fmt.Printf("  %s\n", u)
			}
			fmt.Println("\nWritable roots:")
			for _, w := range rr.WritableRoots {
				fmt.Printf("  %s\n", w)
			}
			if len(rr.DisabledLayers) > 0 {
				fmt.Println("\nDISABLED Ring-2 deception layers:")
				for _, l := range rr.DisabledLayers {
					fmt.Printf("  - %s\n", l)
				}
			}
			if len(rr.Notes) > 0 {
				fmt.Println("\nNotes:")
				for _, n := range rr.Notes {
					fmt.Printf("  - %s\n", n)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON instead of human format")
	return cmd
}

// --- helpers ---

func jsonPrint(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func checkmark(b bool) string {
	if b {
		return "yes"
	}
	return "-"
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/localapi"
)

// newIntegrityCmd is the operator surface for the binary-integrity
// subsystem (B1+B2+B3, see EGRESS_C2_DISARM_AND_BINARY_INTEGRITY_2026-05-22.md).
func newIntegrityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "integrity",
		Short: "Binary integrity baseline + verifier (B1+B2+B3)",
		Long: `xhelix tracks the SHA-256 of every binary under critical
system paths (/usr/bin, /usr/sbin, /lib, etc.). Each execve checks
the running binary against the baseline; mismatch + no authentic
package-manager writer = critical alert + lineage disarm.

  status            — counters, mode, source breakdown
  verify <path>     — re-hash a single path, compare to baseline
  refresh <pkg>     — refresh baseline for a specific dpkg package
  refresh-recent    — re-hash anything dpkg touched recently (apt hook)
  rebuild           — wipe baseline + re-walk all critical paths`,
	}
	cmd.AddCommand(newIntegrityStatusCmd())
	cmd.AddCommand(newIntegrityVerifyCmd())
	cmd.AddCommand(newIntegrityRefreshCmd())
	cmd.AddCommand(newIntegrityRefreshRecentCmd())
	cmd.AddCommand(newIntegrityRebuildCmd())
	return cmd
}

func newIntegrityStatusCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Baseline counters, mode, source breakdown",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			var resp struct {
				Enabled      bool           `json:"enabled"`
				Mode         string         `json:"mode"`
				TotalRows    int            `json:"total_rows"`
				PerSource    map[string]int `json:"per_source"`
				BaselineDB   string         `json:"baseline_db"`
				VerifierStat struct {
					BaselineMatched uint64 `json:"baseline_matched"`
					HashMismatched  uint64 `json:"hash_mismatched"`
					TOFUAccepted    uint64 `json:"tofu_accepted"`
					UpgradeRecovers uint64 `json:"upgrade_recovers"`
					Errors          uint64 `json:"errors"`
				} `json:"verifier"`
			}
			if err := c.Call("integrity.status", struct{}{}, &resp); err != nil {
				return err
			}
			if !resp.Enabled {
				fmt.Println("Integrity verifier is DISABLED.")
				fmt.Println("Enable in /etc/xhelix/xhelix.yaml:")
				fmt.Println()
				fmt.Println("  integrity:")
				fmt.Println("    enabled: true")
				fmt.Println("    mode: detect      # or 'enforce'")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintf(tw, "Mode:\t%s\n", resp.Mode)
			fmt.Fprintf(tw, "Baseline DB:\t%s\n", resp.BaselineDB)
			fmt.Fprintf(tw, "Total rows:\t%d\n", resp.TotalRows)
			fmt.Fprintln(tw, "Per source:")
			for src, n := range resp.PerSource {
				fmt.Fprintf(tw, "  %s\t%d\n", src, n)
			}
			fmt.Fprintln(tw, "Verifier stats:")
			fmt.Fprintf(tw, "  baseline_matched\t%d\n", resp.VerifierStat.BaselineMatched)
			fmt.Fprintf(tw, "  hash_mismatched\t%d\n", resp.VerifierStat.HashMismatched)
			fmt.Fprintf(tw, "  tofu_accepted\t%d\n", resp.VerifierStat.TOFUAccepted)
			fmt.Fprintf(tw, "  upgrade_recovers\t%d\n", resp.VerifierStat.UpgradeRecovers)
			fmt.Fprintf(tw, "  errors\t%d\n", resp.VerifierStat.Errors)
			tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	return cmd
}

func newIntegrityVerifyCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "verify <path>",
		Short: "Re-hash a single path and compare to baseline",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			var resp struct {
				Match    bool   `json:"match"`
				Reason   string `json:"reason"`
				Baseline string `json:"baseline_sha256"`
				Current  string `json:"current_sha256"`
				Source   string `json:"source"`
				Package  string `json:"package"`
			}
			if err := c.Call("integrity.verify", map[string]any{"path": args[0]}, &resp); err != nil {
				return err
			}
			marker := "✓"
			if !resp.Match {
				marker = "✗"
			}
			fmt.Printf("%s %s\n", marker, args[0])
			fmt.Printf("  baseline_sha256: %s\n", resp.Baseline)
			fmt.Printf("  current_sha256:  %s\n", resp.Current)
			fmt.Printf("  source:          %s\n", resp.Source)
			if resp.Package != "" {
				fmt.Printf("  package:         %s\n", resp.Package)
			}
			if resp.Reason != "" {
				fmt.Printf("  reason:          %s\n", resp.Reason)
			}
			if !resp.Match {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	return cmd
}

func newIntegrityRefreshCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "refresh <package>",
		Short: "Re-hash and re-baseline every file owned by <package>",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			var resp struct {
				Refreshed int `json:"refreshed"`
			}
			if err := c.Call("integrity.refresh", map[string]any{"package": args[0]}, &resp); err != nil {
				return err
			}
			fmt.Printf("refreshed %d files in package %s\n", resp.Refreshed, args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	return cmd
}

func newIntegrityRefreshRecentCmd() *cobra.Command {
	var sock string
	var quiet bool
	cmd := &cobra.Command{
		Use:   "refresh-recent",
		Short: "Refresh baseline for files touched in the last hour (apt hook)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				if quiet {
					return nil
				}
				return err
			}
			defer c.Close()
			var resp struct {
				Refreshed int `json:"refreshed"`
			}
			if err := c.Call("integrity.refresh_recent", struct{}{}, &resp); err != nil {
				if quiet {
					return nil
				}
				return err
			}
			if !quiet {
				fmt.Printf("refreshed %d recently-touched files\n", resp.Refreshed)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress output (for apt post-invoke hook)")
	return cmd
}

func newIntegrityRebuildCmd() *cobra.Command {
	var sock string
	var force bool
	cmd := &cobra.Command{
		Use:   "rebuild",
		Short: "Wipe the baseline and re-walk all critical paths",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				return fmt.Errorf("rebuild wipes the existing baseline. Pass --force to confirm.")
			}
			c, err := localapi.Dial(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			var resp struct {
				FilesHashed uint64 `json:"files_hashed"`
				BytesHashed uint64 `json:"bytes_hashed"`
			}
			if err := c.Call("integrity.rebuild", struct{}{}, &resp); err != nil {
				return err
			}
			fmt.Printf("rebuild complete: %d files hashed, %.1f MB\n",
				resp.FilesHashed, float64(resp.BytesHashed)/(1024*1024))
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	cmd.Flags().BoolVar(&force, "force", false, "confirm rebuild (mandatory)")
	return cmd
}

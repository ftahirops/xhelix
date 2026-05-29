package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/localapi"
)

// newSafetyCmd is the xhelixctl wrapper for the Safety Net subsystem
// (global IP allow-list + block-with-observe list). All ops go through
// the daemon's REST endpoints; CLI just renders.
func newSafetyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "safety",
		Short: "Manage the global IP allow/block list (safety net)",
		Long: `Safety net is the global IP allow/block list.

  always_allow:  vetoes ANY block decision — your management IPs go here
  block_observe: nftables drop + log for blocked IPs; attempts logged

The safety net refuses to block any IP that's in always_allow, even if
the API is asked to. Allow always wins.`,
	}
	cmd.AddCommand(newSafetyListCmd())
	cmd.AddCommand(newSafetyAllowCmd())
	cmd.AddCommand(newSafetyUnallowCmd())
	cmd.AddCommand(newSafetyBlockCmd())
	cmd.AddCommand(newSafetyUnblockCmd())
	cmd.AddCommand(newSafetyAttemptsCmd())
	cmd.AddCommand(newSafetyStatsCmd())
	return cmd
}

func newSafetyListCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show current allow + block lists",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			var resp struct {
				Allow []string `json:"allow"`
				Block []string `json:"block"`
			}
			if err := c.Call("safety.list", nil, &resp); err != nil {
				return err
			}
			fmt.Println("ALWAYS ALLOW")
			for _, a := range resp.Allow {
				fmt.Printf("  %s\n", a)
			}
			if len(resp.Allow) == 0 {
				fmt.Println("  (none)")
			}
			fmt.Println()
			fmt.Println("BLOCK & OBSERVE")
			for _, b := range resp.Block {
				fmt.Printf("  %s\n", b)
			}
			if len(resp.Block) == 0 {
				fmt.Println("  (none)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/xhelix.sock", "daemon socket")
	return cmd
}

func mutateSafetyCLI(method string, cidr string, sock string) error {
	c, err := localapi.Dial(sock)
	if err != nil {
		return err
	}
	defer c.Close()
	var resp map[string]any
	if err := c.Call(method, map[string]string{"cidr": cidr}, &resp); err != nil {
		return err
	}
	if ok, _ := resp["ok"].(bool); ok {
		fmt.Printf("OK: %s %s\n", method, cidr)
		return nil
	}
	if msg, ok := resp["error"].(string); ok {
		return fmt.Errorf("%s", msg)
	}
	body, _ := json.Marshal(resp)
	fmt.Println(string(body))
	return nil
}

func newSafetyAllowCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "allow <cidr>",
		Short: "Add an IP/CIDR to the always_allow list (never blocked)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return mutateSafetyCLI("safety.allow.add", args[0], sock)
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/xhelix.sock", "daemon socket")
	return cmd
}

func newSafetyUnallowCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "unallow <cidr>",
		Short: "Remove an IP/CIDR from always_allow",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return mutateSafetyCLI("safety.allow.del", args[0], sock)
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/xhelix.sock", "daemon socket")
	return cmd
}

func newSafetyBlockCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "block <cidr>",
		Short: "Add an IP/CIDR to block_observe (dropped + logged)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return mutateSafetyCLI("safety.block.add", args[0], sock)
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/xhelix.sock", "daemon socket")
	return cmd
}

func newSafetyUnblockCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "unblock <cidr>",
		Short: "Remove an IP/CIDR from block_observe",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return mutateSafetyCLI("safety.block.del", args[0], sock)
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/xhelix.sock", "daemon socket")
	return cmd
}

func newSafetyAttemptsCmd() *cobra.Command {
	var sock string
	var n int
	cmd := &cobra.Command{
		Use:   "attempts",
		Short: "Show recent blocked attempts (drops captured from kernel log)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			var resp []struct {
				Time    time.Time `json:"time"`
				SrcIP   string    `json:"src_ip"`
				DstIP   string    `json:"dst_ip"`
				DstPort uint16    `json:"dst_port"`
				Proto   string    `json:"proto"`
				Bytes   uint64    `json:"bytes"`
			}
			if err := c.Call("safety.attempts", map[string]int{"n": n}, &resp); err != nil {
				return err
			}
			if len(resp) == 0 {
				fmt.Println("(no blocked attempts in ring)")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "TIME\tSRC\tDST\tPORT\tPROTO\tBYTES")
			for _, a := range resp {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%d\n",
					a.Time.Format("15:04:05"), a.SrcIP, a.DstIP, a.DstPort, a.Proto, a.Bytes)
			}
			tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/xhelix.sock", "daemon socket")
	cmd.Flags().IntVar(&n, "n", 50, "max attempts to show")
	return cmd
}

func newSafetyStatsCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show safety net counters",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			var resp struct {
				AllowChecks uint64 `json:"allow_checks"`
				AllowHits   uint64 `json:"allow_hits"`
				BlockChecks uint64 `json:"block_checks"`
				BlockHits   uint64 `json:"block_hits"`
				AllowCount  int    `json:"allow_count"`
				BlockCount  int    `json:"block_count"`
				AttemptsLog int    `json:"attempts_log"`
			}
			if err := c.Call("safety.stats", nil, &resp); err != nil {
				return err
			}
			fmt.Printf("Allow entries:    %d\n", resp.AllowCount)
			fmt.Printf("Block entries:    %d\n", resp.BlockCount)
			fmt.Printf("Allow checks:     %d (hits: %d)\n", resp.AllowChecks, resp.AllowHits)
			fmt.Printf("Block checks:     %d (hits: %d)\n", resp.BlockChecks, resp.BlockHits)
			fmt.Printf("Attempts in ring: %d\n", resp.AttemptsLog)
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/xhelix.sock", "daemon socket")
	return cmd
}

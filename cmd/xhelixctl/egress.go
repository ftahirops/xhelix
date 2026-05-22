package main

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/localapi"
)

// newEgressCmd surfaces the P-EGRESS.M1 observer for operators.
// Read-only at this milestone — Mode 2 disarm is a future command set.
func newEgressCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "egress",
		Short: "Egress observability — per-lineage destination classes",
		Long: `Egress Mode 1 (observe + classify) summary view. Shows every
lineage the daemon has seen outbound from, classified into:

  intel_bad        — threat-intel hit on the destination IP
  private          — RFC1918 / loopback / link-local (no internet risk)
  dev_registry     — github / npm / pypi / etc.
  os_update        — debian / ubuntu / microsoft update / etc.
  cdn              — cloudflare / fastly / akamai / cloudfront
  cloud_provider   — aws / gcp / azure
  fleet_baseline   — destination seen by ≥ minFleetSeen fleet hosts
  unknown          — never-seen by this host or fleet (the C2 signal)

A lineage with many unique destinations in class=unknown is the
shape of a beaconing implant. Mode 2 disarm (future) will gate
these into default-deny.`,
	}
	cmd.AddCommand(newEgressObserveCmd())
	if extendEgressCmd != nil {
		extendEgressCmd(cmd)
	}
	return cmd
}

func newEgressObserveCmd() *cobra.Command {
	var sock string
	var lineage uint64
	var verbose bool
	cmd := &cobra.Command{
		Use:   "observe",
		Short: "Show per-lineage egress observations",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var resp struct {
				Enabled  bool `json:"enabled"`
				Lineages []struct {
					Lineage        uint64            `json:"lineage"`
					TotalConnects  int               `json:"total_connects"`
					ByClass        map[string]int    `json:"by_class"`
					UniqueDests    int               `json:"unique_dests"`
					UniqueUnknown  int               `json:"unique_unknown"`
					LastConnect    time.Time         `json:"last_connect"`
					FirstUnknownAt time.Time         `json:"first_unknown_at"`
					FirstIntelBad  time.Time         `json:"first_intel_bad"`
					RecentSample   []struct {
						At    time.Time `json:"at"`
						IP    string    `json:"ip"`
						SNI   string    `json:"sni"`
						Port  uint16    `json:"port"`
						Class string    `json:"class"`
					} `json:"recent_sample"`
				} `json:"lineages"`
			}
			req := map[string]any{"lineage": lineage}
			if err := c.Call("egress.observe", req, &resp); err != nil {
				return fmt.Errorf("egress.observe: %w", err)
			}
			if !resp.Enabled {
				fmt.Println("Egress observer is DISABLED. Enable in /etc/xhelix/xhelix.yaml:")
				fmt.Println()
				fmt.Println("  egress:")
				fmt.Println("    observe: true")
				fmt.Println()
				fmt.Println("Then: systemctl restart xhelix")
				return nil
			}
			if len(resp.Lineages) == 0 {
				fmt.Println("No outbound connects observed yet.")
				return nil
			}
			// Sort by unique_unknown desc — that's the suspicion signal.
			sort.Slice(resp.Lineages, func(i, j int) bool {
				if resp.Lineages[i].UniqueUnknown != resp.Lineages[j].UniqueUnknown {
					return resp.Lineages[i].UniqueUnknown > resp.Lineages[j].UniqueUnknown
				}
				return resp.Lineages[i].TotalConnects > resp.Lineages[j].TotalConnects
			})
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "LINEAGE\tCONNECTS\tUNIQUE\tUNKNOWN\tINTEL_BAD\tCLOUD\tCDN\tREG\tOS_UPD\tPRIV\tLAST_CONNECT")
			for _, lg := range resp.Lineages {
				bad := lg.ByClass["intel_bad"]
				badStr := fmt.Sprintf("%d", bad)
				if bad > 0 {
					badStr = "!" + badStr // visual flag
				}
				fmt.Fprintf(tw, "%d\t%d\t%d\t%d\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n",
					lg.Lineage, lg.TotalConnects, lg.UniqueDests, lg.UniqueUnknown,
					badStr,
					lg.ByClass["cloud_provider"], lg.ByClass["cdn"],
					lg.ByClass["dev_registry"], lg.ByClass["os_update"],
					lg.ByClass["private"],
					lg.LastConnect.Format("15:04:05"),
				)
			}
			tw.Flush()
			if verbose {
				for _, lg := range resp.Lineages {
					if len(lg.RecentSample) == 0 {
						continue
					}
					fmt.Printf("\nLineage %d — last %d observations:\n", lg.Lineage, len(lg.RecentSample))
					for _, s := range lg.RecentSample {
						sni := s.SNI
						if sni == "" {
							sni = "-"
						}
						fmt.Printf("  %s  %-15s  %-40s  :%d  [%s]\n",
							s.At.Format("15:04:05"), s.IP, sni, s.Port, s.Class)
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	cmd.Flags().Uint64Var(&lineage, "lineage", 0, "filter to one lineage (cgroup id or pid); 0 = all")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "include forensic sample of recent observations")
	return cmd
}

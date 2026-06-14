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
	cmd.AddCommand(newEgressLiveCmd())
	cmd.AddCommand(newEgressLedgerTimelineCmd())
	cmd.AddCommand(newEgressBinaryCmd())
	cmd.AddCommand(newEgressStatsCmd())
	if extendEgressCmd != nil {
		extendEgressCmd(cmd)
	}
	return cmd
}

// flowRecord mirrors egressledger.FlowRecord for JSON decoding.
type flowRecord struct {
	Key struct {
		Binary    string `json:"binary"`
		ExeSHA    string `json:"exe_sha,omitempty"`
		UID       uint32 `json:"uid"`
		CGroupID  uint64 `json:"cgroup_id"`
		DestCIDR  string `json:"dest_cidr"`
		DestPort  uint16 `json:"dest_port"`
		Protocol  string `json:"protocol"`
		SNI       string `json:"sni,omitempty"`
		DNSName   string `json:"dns_name,omitempty"`
		DestClass string `json:"dest_class,omitempty"`
	} `json:"key"`
	Metrics struct {
		FirstSeen    time.Time `json:"first_seen"`
		LastSeen     time.Time `json:"last_seen"`
		Connects     uint64    `json:"connects"`
		BytesOut     uint64    `json:"bytes_out"`
		BytesIn      uint64    `json:"bytes_in"`
		DenyEvents   uint64    `json:"deny_events"`
		VerifyEvents uint64    `json:"verify_events"`
	} `json:"metrics"`
	Bucket time.Time `json:"bucket"`
}

func printFlowRecords(records []flowRecord) {
	if len(records) == 0 {
		fmt.Println("(no records)")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "BUCKET\tBINARY\tUID\tDEST\tPORT\tPROTO\tSNI\tCLASS\tCONNECTS\tBYTES_OUT\tBYTES_IN\tDENY")
	for _, r := range records {
		sni := r.Key.SNI
		if len(sni) > 24 {
			sni = sni[:24]
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%d\t%s\t%s\t%s\t%d\t%d\t%d\t%d\n",
			r.Bucket.Format("15:04:05"),
			truncStr(r.Key.Binary, 24),
			r.Key.UID,
			r.Key.DestCIDR,
			r.Key.DestPort,
			r.Key.Protocol,
			sni,
			r.Key.DestClass,
			r.Metrics.Connects,
			r.Metrics.BytesOut,
			r.Metrics.BytesIn,
			r.Metrics.DenyEvents,
		)
	}
	tw.Flush()
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func newEgressLiveCmd() *cobra.Command {
	var sock, binary, sni, class string
	var uid, port int
	var denyOnly bool
	cmd := &cobra.Command{
		Use:   "live",
		Short: "Live snapshot from the egress ledger hot tier (last 60 min)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			req := map[string]any{
				"binary":     binary,
				"uid":        uid,
				"cgroup_id":  -1,
				"dest_port":  port,
				"sni":        sni,
				"dest_class": class,
				"deny_only":  denyOnly,
			}
			var resp []flowRecord
			if err := c.Call("egress.live", req, &resp); err != nil {
				return fmt.Errorf("egress.live: %w", err)
			}
			sort.SliceStable(resp, func(i, j int) bool { return resp[i].Metrics.LastSeen.After(resp[j].Metrics.LastSeen) })
			printFlowRecords(resp)
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/api.sock", "daemon socket")
	cmd.Flags().StringVar(&binary, "binary", "", "filter by binary substring")
	cmd.Flags().IntVar(&uid, "uid", -1, "filter by uid (-1 = any)")
	cmd.Flags().IntVar(&port, "port", -1, "filter by dest port (-1 = any)")
	cmd.Flags().StringVar(&sni, "sni", "", "filter by SNI substring")
	cmd.Flags().StringVar(&class, "class", "", "filter by dest_class")
	cmd.Flags().BoolVar(&denyOnly, "deny-only", false, "only rows with deny events")
	return cmd
}

func newEgressLedgerTimelineCmd() *cobra.Command {
	var sock, binary string
	var hours int
	cmd := &cobra.Command{
		Use:   "timeline",
		Short: "Range query across hot/warm/cold tiers",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			end := time.Now()
			start := end.Add(-time.Duration(hours) * time.Hour)
			req := map[string]any{
				"start": start,
				"end":   end,
				"filter": map[string]any{
					"binary":    binary,
					"uid":       -1,
					"cgroup_id": -1,
					"dest_port": -1,
				},
			}
			var resp []flowRecord
			if err := c.Call("egress.timeline", req, &resp); err != nil {
				return fmt.Errorf("egress.timeline: %w", err)
			}
			printFlowRecords(resp)
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/api.sock", "daemon socket")
	cmd.Flags().StringVar(&binary, "binary", "", "filter by binary substring")
	cmd.Flags().IntVar(&hours, "hours", 1, "range width in hours back from now")
	return cmd
}

func newEgressBinaryCmd() *cobra.Command {
	var sock string
	var days int
	cmd := &cobra.Command{
		Use:   "binary <name>",
		Short: "All egress activity for one binary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			end := time.Now()
			start := end.Add(-time.Duration(days) * 24 * time.Hour)
			req := map[string]any{
				"binary": args[0],
				"start":  start,
				"end":    end,
			}
			var resp []flowRecord
			if err := c.Call("egress.binary", req, &resp); err != nil {
				return fmt.Errorf("egress.binary: %w", err)
			}
			printFlowRecords(resp)
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/api.sock", "daemon socket")
	cmd.Flags().IntVar(&days, "days", 1, "lookback in days")
	return cmd
}

func newEgressStatsCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Egress ledger storage stats",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var resp struct {
				HotRows       int       `json:"hot_rows"`
				WarmKeys      int       `json:"warm_keys"`
				ColdDays      int       `json:"cold_days"`
				ColdBytes     int64     `json:"cold_bytes"`
				LastTickAt    time.Time `json:"last_tick_at"`
				LastCompactAt time.Time `json:"last_compact_at"`
				RetentionDays int       `json:"retention_days"`
			}
			if err := c.Call("egress.stats", nil, &resp); err != nil {
				return fmt.Errorf("egress.stats: %w", err)
			}
			fmt.Printf("Hot rows:          %d\n", resp.HotRows)
			fmt.Printf("Warm keys:         %d\n", resp.WarmKeys)
			fmt.Printf("Cold days:         %d (%.1f MB)\n", resp.ColdDays, float64(resp.ColdBytes)/1024/1024)
			fmt.Printf("Retention:         %d days\n", resp.RetentionDays)
			fmt.Printf("Last tick:         %s\n", resp.LastTickAt.Format(time.RFC3339))
			fmt.Printf("Last compaction:   %s\n", resp.LastCompactAt.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/api.sock", "daemon socket")
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
			fmt.Fprintln(tw, " \tLINEAGE\tCONNECTS\tUNIQUE\tUNKNOWN\tINTEL_BAD\tCLOUD\tCDN\tREG\tOS_UPD\tPRIV\tLAST_CONNECT")
			for _, lg := range resp.Lineages {
				bad := lg.ByClass["intel_bad"]
				// We don't have the AppID on the observe-snapshot
				// response yet — heuristic uses lineage info only.
				// (Analytics has AppID; observe shows raw lineages.)
				sus := LineageSuspicion("", lg.UniqueUnknown, bad)
				badStr := fmt.Sprintf("%d", bad)
				if bad > 0 {
					badStr = colorize(fmt.Sprintf("!%d", bad), ansiRed)
				}
				fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n",
					sus.Tag(),
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

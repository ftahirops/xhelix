package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/localapi"
)

// Phase H operator surfaces: per-rule fire-rate suppression stats
// (H.3) and per-image rolling byte top-N (H.1). Both go over the
// existing /run/xhelix/xhelix.sock localapi.

func newFireRateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "firerate",
		Short: "Per-rule fire-rate suppression stats (Phase H.3)",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "stats",
		Short: "Show how many alerts each rule's rate cap suppressed",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial("/run/xhelix/xhelix.sock")
			if err != nil {
				return fmt.Errorf("dial daemon socket: %w", err)
			}
			defer c.Close()
			var stats map[string]int
			if err := c.Call("firerate.stats", nil, &stats); err != nil {
				return err
			}
			if len(stats) == 0 {
				fmt.Println("no rules have hit their fire-rate cap")
				return nil
			}
			type row struct {
				rule string
				n    int
			}
			rows := make([]row, 0, len(stats))
			for k, v := range stats {
				rows = append(rows, row{k, v})
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "RULE\tSUPPRESSED")
			for _, r := range rows {
				fmt.Fprintf(tw, "%s\t%d\n", r.rule, r.n)
			}
			tw.Flush()
			return nil
		},
	})
	return cmd
}

func newFlowStatsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flowstats",
		Short: "Per-image rolling byte counters (Phase H.1)",
	}
	var topN int
	top := &cobra.Command{
		Use:   "top",
		Short: "Show top images by outbound bytes in the current window",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial("/run/xhelix/xhelix.sock")
			if err != nil {
				return fmt.Errorf("dial daemon socket: %w", err)
			}
			defer c.Close()
			req, _ := json.Marshal(struct{ N int }{N: topN})
			var rows []struct {
				Image string
				Bytes uint64
			}
			if err := c.Call("flowstats.top", json.RawMessage(req), &rows); err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Println("no flow stats yet (idle or daemon just started)")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "IMAGE\tBYTES_OUT_WINDOW")
			for _, r := range rows {
				fmt.Fprintf(tw, "%s\t%d\n", r.Image, r.Bytes)
			}
			tw.Flush()
			return nil
		},
	}
	top.Flags().IntVarP(&topN, "top", "n", 20, "show top N images by outbound bytes")
	cmd.AddCommand(top)
	return cmd
}

// newEndpointScoreCmd shows the host-level T10 chain-rollup score
// pulled live from the daemon.
func newEndpointScoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "endpointscore",
		Short: "Show current endpoint risk score across the 5 canonical chains (T10)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial("/run/xhelix/xhelix.sock")
			if err != nil {
				return fmt.Errorf("dial daemon socket: %w", err)
			}
			defer c.Close()
			var es struct {
				Score    int
				Chain    string
				Severity string
				Matches  []struct {
					ChainID string
					Score   int
					Matched bool
					Missing []string
					Hit     []string
				}
				At string
			}
			if err := c.Call("endpointscore.current", nil, &es); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "endpoint score: %d/100  severity=%s  top_chain=%s\n\n",
				es.Score, es.Severity, es.Chain)
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "CHAIN\tSCORE\tMATCHED\tHIT\tMISSING")
			for _, m := range es.Matches {
				fmt.Fprintf(tw, "%s\t%d\t%v\t%v\t%v\n",
					m.ChainID, m.Score, m.Matched, m.Hit, m.Missing)
			}
			return tw.Flush()
		},
	}
}

// suppress unused-import lint when context isn't referenced from a build
// tag combination (defensive — the file always uses cobra).
var _ = context.Background

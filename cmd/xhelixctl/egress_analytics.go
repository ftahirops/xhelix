package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/egressmon"
	"github.com/xhelix/xhelix/pkg/localapi"
)

func init() {
	// Append analytics + timeline + block + deep-observe subcommands to
	// the existing newEgressCmd() group. We do this in init() so the
	// existing newEgressCmd in egress.go stays focused on "observe".
}

// extendEgressCmd is invoked from newEgressCmd's constructor in egress.go.
// We expose it via a global hook so we can register here without editing
// the other file's constructor body.
var extendEgressCmd = func(cmd *cobra.Command) {
	cmd.AddCommand(newEgressAnalyticsCmd())
	cmd.AddCommand(newEgressTimelineCmd())
	cmd.AddCommand(newEgressBlockCmd())
	cmd.AddCommand(newEgressDeepObserveCmd())
}

const defaultAnalyticsDir = "/var/lib/xhelix/egress-analytics"

func newEgressAnalyticsCmd() *cobra.Command {
	var (
		dir     string
		date    string
		groupBy string
		top     int
	)
	cmd := &cobra.Command{
		Use:   "analytics",
		Short: "Group + summarise the daily egress rollup",
		Long: `Read /var/lib/xhelix/egress-analytics/YYYY-MM-DD.jsonl and roll up
the per-lineage snapshots by a chosen dimension. The last record per
lineage in the day is used (final state).

  --group-by app          per-AppID totals (default)
  --group-by class        per-destination-class totals
  --group-by lineage      raw per-lineage rows
  --group-by dest         per-destination (ip|sni) totals
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if date == "" {
				date = time.Now().UTC().Format("2006-01-02")
			}
			recs, err := egressmon.LoadDay(dir, date)
			if err != nil {
				return fmt.Errorf("load %s/%s.jsonl: %w", dir, date, err)
			}
			if len(recs) == 0 {
				fmt.Printf("No data for %s (file may not exist yet).\n", date)
				return nil
			}
			// Reduce to the last snapshot per lineage.
			latest := map[egressmon.LineageID]egressmon.RollupRecord{}
			for _, r := range recs {
				cur, ok := latest[r.Stats.LineageID]
				if !ok || r.At.After(cur.At) {
					latest[r.Stats.LineageID] = r
				}
			}
			switch groupBy {
			case "", "app":
				printGroupBy(latest, keyApp, top)
			case "class":
				printGroupByClass(latest, top)
			case "lineage":
				printPerLineage(latest, top)
			case "dest":
				printPerDest(latest, top)
			default:
				return fmt.Errorf("unknown --group-by %q (app|class|lineage|dest)", groupBy)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", defaultAnalyticsDir, "rollup directory")
	cmd.Flags().StringVar(&date, "date", "", "YYYY-MM-DD (default: today UTC)")
	cmd.Flags().StringVar(&groupBy, "group-by", "app", "app|class|lineage|dest")
	cmd.Flags().IntVar(&top, "top", 25, "show top N rows by total bytes")
	return cmd
}

type aggRow struct {
	Key      string
	Connects int
	Bytes    uint64
	Unique   int
	Unknown  int
}

func keyApp(s egressmon.PerLineageStats) string {
	if s.AppID == "" {
		return "(unidentified)"
	}
	return s.AppID
}

func printGroupBy(latest map[egressmon.LineageID]egressmon.RollupRecord, key func(egressmon.PerLineageStats) string, top int) {
	agg := map[string]*aggRow{}
	for _, r := range latest {
		k := key(r.Stats)
		row := agg[k]
		if row == nil {
			row = &aggRow{Key: k}
			agg[k] = row
		}
		row.Connects += r.Stats.TotalConnects
		row.Bytes += r.Stats.TotalBytesOut
		row.Unique += r.Stats.UniqueDests
		row.Unknown += r.Stats.UniqueUnknown
	}
	rows := make([]*aggRow, 0, len(agg))
	for _, r := range agg {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Bytes > rows[j].Bytes })
	if top > 0 && len(rows) > top {
		rows = rows[:top]
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, " \tAPP\tCONNECTS\tBYTES_OUT\tUNIQUE\tUNKNOWN")
	for _, r := range rows {
		sus := LineageSuspicion(r.Key, r.Unknown, 0)
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%d\t%d\n",
			sus.Tag(), r.Key, r.Connects, humanBytes(r.Bytes), r.Unique, r.Unknown)
	}
	tw.Flush()
}

func printGroupByClass(latest map[egressmon.LineageID]egressmon.RollupRecord, top int) {
	classBytes := map[string]uint64{}
	classConnects := map[string]int{}
	for _, r := range latest {
		for c, b := range r.Stats.BytesOutByClass {
			classBytes[string(c)] += b
		}
		for c, n := range r.Stats.ByClass {
			classConnects[string(c)] += n
		}
	}
	type kv struct {
		Class    string
		Bytes    uint64
		Connects int
	}
	rows := make([]kv, 0, len(classBytes))
	keys := map[string]bool{}
	for c := range classBytes {
		keys[c] = true
	}
	for c := range classConnects {
		keys[c] = true
	}
	for c := range keys {
		rows = append(rows, kv{Class: c, Bytes: classBytes[c], Connects: classConnects[c]})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Bytes > rows[j].Bytes })
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CLASS\tCONNECTS\tBYTES_OUT")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%d\t%s\n", r.Class, r.Connects, humanBytes(r.Bytes))
	}
	tw.Flush()
}

func printPerLineage(latest map[egressmon.LineageID]egressmon.RollupRecord, top int) {
	rows := make([]egressmon.RollupRecord, 0, len(latest))
	for _, r := range latest {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Stats.TotalBytesOut > rows[j].Stats.TotalBytesOut })
	if top > 0 && len(rows) > top {
		rows = rows[:top]
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "LINEAGE\tAPP\tCONNECTS\tBYTES_OUT\tUNIQUE\tUNKNOWN\tLAST")
	for _, r := range rows {
		app := r.Stats.AppID
		if app == "" {
			app = "-"
		}
		fmt.Fprintf(tw, "%d\t%s\t%d\t%s\t%d\t%d\t%s\n",
			r.Stats.LineageID, app, r.Stats.TotalConnects, humanBytes(r.Stats.TotalBytesOut),
			r.Stats.UniqueDests, r.Stats.UniqueUnknown,
			r.Stats.LastConnect.Format("15:04"))
	}
	tw.Flush()
}

func printPerDest(latest map[egressmon.LineageID]egressmon.RollupRecord, top int) {
	dest := map[string]uint64{}
	for _, r := range latest {
		for k, b := range r.Stats.BytesOutByDest {
			dest[k] += b
		}
	}
	type kv struct {
		Key   string
		Bytes uint64
	}
	rows := make([]kv, 0, len(dest))
	for k, v := range dest {
		rows = append(rows, kv{Key: k, Bytes: v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Bytes > rows[j].Bytes })
	if top > 0 && len(rows) > top {
		rows = rows[:top]
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "DEST (ip|sni)\tBYTES_OUT")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\n", r.Key, humanBytes(r.Bytes))
	}
	tw.Flush()
}

func humanBytes(n uint64) string {
	const k, m, g = uint64(1024), uint64(1024 * 1024), uint64(1024 * 1024 * 1024)
	switch {
	case n >= g:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(g))
	case n >= m:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(m))
	case n >= k:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(k))
	}
	return fmt.Sprintf("%d B", n)
}

func newEgressTimelineCmd() *cobra.Command {
	var (
		dir  string
		date string
		app  string
	)
	cmd := &cobra.Command{
		Use:   "timeline <app>",
		Short: "Per-hour bytes-out timeline for one app",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				app = args[0]
			}
			if date == "" {
				date = time.Now().UTC().Format("2006-01-02")
			}
			recs, err := egressmon.LoadDay(dir, date)
			if err != nil {
				return err
			}
			if len(recs) == 0 {
				fmt.Printf("No data for %s.\n", date)
				return nil
			}
			hour := [24]uint64{}
			for _, r := range recs {
				if app != "" && r.Stats.AppID != app {
					continue
				}
				h := r.At.Hour()
				// We can't compute deltas without a previous snapshot
				// per lineage; for v1 we present total-bytes-as-of
				// each hour. Mode-2 will add proper deltas.
				if r.Stats.TotalBytesOut > hour[h] {
					hour[h] = r.Stats.TotalBytesOut
				}
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "HOUR (UTC)\tBYTES_OUT")
			for h := 0; h < 24; h++ {
				if hour[h] == 0 {
					continue
				}
				fmt.Fprintf(tw, "%02d:00\t%s\n", h, humanBytes(hour[h]))
			}
			tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", defaultAnalyticsDir, "rollup directory")
	cmd.Flags().StringVar(&date, "date", "", "YYYY-MM-DD (default: today UTC)")
	return cmd
}

func newEgressBlockCmd() *cobra.Command {
	var (
		sock   string
		reason string
		cidr   bool
	)
	cmd := &cobra.Command{
		Use:   "block <dest>",
		Short: "Add a destination IP or CIDR to the manual outbound blocklist",
		Long: `Adds <dest> to the netban manual blocklist via daemon
LocalAPI. <dest> may be a single IP or, with --cidr, a CIDR range
(e.g. 192.0.2.0/24).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			req := map[string]any{
				"dest":   args[0],
				"reason": reason,
				"cidr":   cidr,
			}
			var resp map[string]any
			if err := c.Call("egress.block", req, &resp); err != nil {
				return err
			}
			fmt.Printf("blocked %s (%s)\n", args[0], reason)
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	cmd.Flags().StringVar(&reason, "reason", "", "operator-supplied reason (audit)")
	cmd.Flags().BoolVar(&cidr, "cidr", false, "dest is a CIDR range, not a single IP")
	return cmd
}

func newEgressDeepObserveCmd() *cobra.Command {
	var (
		sock   string
		port   uint16
		reason string
	)
	cmd := &cobra.Command{
		Use:   "deep-observe <dest>",
		Short: "Mark a destination for verbose per-flow recording",
		Long: `Tells the daemon to record full per-flow observation (every
connect, every byte, full forensic sample) for any traffic to <dest>
[on the given port]. Use after seeing something suspicious.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			req := map[string]any{
				"dest":   args[0],
				"port":   port,
				"reason": reason,
			}
			var resp map[string]any
			if err := c.Call("egress.deep_observe", req, &resp); err != nil {
				return err
			}
			extra := ""
			if port != 0 {
				extra = fmt.Sprintf(" port=%d", port)
			}
			fmt.Printf("deep-observe enabled for %s%s\n", args[0], extra)
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	cmd.Flags().Uint16Var(&port, "port", 0, "scope deep observation to a specific port (0 = any)")
	cmd.Flags().StringVar(&reason, "reason", "", "operator-supplied reason (audit)")
	return cmd
}

// unused imports placeholder
var _ = strings.Builder{}

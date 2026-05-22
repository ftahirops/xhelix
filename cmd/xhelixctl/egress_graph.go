package main

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/localapi"
)

// Sparkline runes — eight-step gradient.
var sparkRunes = []rune("▁▂▃▄▅▆▇█")

func init() {
	extendEgressCmd = chainExtenders(extendEgressCmd, func(cmd *cobra.Command) {
		cmd.AddCommand(newEgressGraphCmd())
		cmd.AddCommand(newEgressTopIPsCmd())
	})
}

// chainExtenders composes the existing extender (set by other files
// in init order) with a new one. Keeps egress.go's constructor
// agnostic of which files add subcommands.
func chainExtenders(prev, next func(*cobra.Command)) func(*cobra.Command) {
	return func(c *cobra.Command) {
		if prev != nil {
			prev(c)
		}
		next(c)
	}
}

func newEgressGraphCmd() *cobra.Command {
	var (
		sock  string
		hours int
		width int
	)
	cmd := &cobra.Command{
		Use:   "graph <ip>",
		Short: "ASCII sparkline of bytes in/out for one IP",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			var resp struct {
				Enabled bool   `json:"enabled"`
				IP      string `json:"ip"`
				Points  []struct {
					BucketTs int64  `json:"bucket_ts"`
					BytesOut uint64 `json:"bytes_out"`
					BytesIn  uint64 `json:"bytes_in"`
				} `json:"points"`
			}
			if err := c.Call("egress.ip_timeseries", map[string]any{
				"ip": args[0], "hours": hours,
			}, &resp); err != nil {
				return err
			}
			if !resp.Enabled {
				fmt.Println("IP timeseries is DISABLED. Enable egress.observe in /etc/xhelix/xhelix.yaml.")
				return nil
			}
			if len(resp.Points) == 0 {
				fmt.Printf("No traffic recorded for %s in the last %dh.\n", args[0], hours)
				return nil
			}
			renderSparklineFromPoints(resp.IP, resp.Points, width, hours)
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	cmd.Flags().IntVar(&hours, "hours", 24, "lookback window in hours")
	cmd.Flags().IntVar(&width, "width", 60, "sparkline width in columns")
	return cmd
}

func newEgressTopIPsCmd() *cobra.Command {
	var (
		sock  string
		hours int
		top   int
	)
	cmd := &cobra.Command{
		Use:   "top-ips",
		Short: "Top destination IPs by bytes-out (with per-IP totals)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			var resp struct {
				Enabled bool `json:"enabled"`
				Top     []struct {
					IP       string `json:"ip"`
					BytesOut uint64 `json:"bytes_out"`
					BytesIn  uint64 `json:"bytes_in"`
				} `json:"top"`
			}
			if err := c.Call("egress.top_ips", map[string]any{
				"hours": hours, "top": top,
			}, &resp); err != nil {
				return err
			}
			if !resp.Enabled {
				fmt.Println("IP timeseries is DISABLED. Enable egress.observe in /etc/xhelix/xhelix.yaml.")
				return nil
			}
			if len(resp.Top) == 0 {
				fmt.Printf("No IPs recorded in the last %dh.\n", hours)
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "IP\tBYTES_OUT\tBYTES_IN\tTOTAL")
			for _, r := range resp.Top {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
					r.IP, humanBytes(r.BytesOut), humanBytes(r.BytesIn),
					humanBytes(r.BytesOut+r.BytesIn))
			}
			tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	cmd.Flags().IntVar(&hours, "hours", 24, "lookback window in hours")
	cmd.Flags().IntVar(&top, "top", 25, "show top N IPs")
	return cmd
}

func renderSparklineFromPoints(ip string, pts []struct {
	BucketTs int64  `json:"bucket_ts"`
	BytesOut uint64 `json:"bytes_out"`
	BytesIn  uint64 `json:"bytes_in"`
}, width, hours int) {
	sort.Slice(pts, func(i, j int) bool { return pts[i].BucketTs < pts[j].BucketTs })
	// Compress into `width` columns by averaging buckets per column.
	cols := width
	if len(pts) < cols {
		cols = len(pts)
	}
	if cols < 1 {
		cols = 1
	}
	outVals := make([]uint64, cols)
	inVals := make([]uint64, cols)
	step := float64(len(pts)) / float64(cols)
	for c := 0; c < cols; c++ {
		lo := int(float64(c) * step)
		hi := int(float64(c+1) * step)
		if hi > len(pts) {
			hi = len(pts)
		}
		if lo == hi && lo < len(pts) {
			hi = lo + 1
		}
		var o, i uint64
		for k := lo; k < hi; k++ {
			o += pts[k].BytesOut
			i += pts[k].BytesIn
		}
		outVals[c] = o
		inVals[c] = i
	}
	maxO := slMax(outVals)
	maxI := slMax(inVals)
	maxBoth := maxO
	if maxI > maxBoth {
		maxBoth = maxI
	}
	fmt.Printf("\n%s — last %dh, %d buckets compressed to %d cols (peak %s)\n",
		ip, hours, len(pts), cols, humanBytes(maxBoth))
	fmt.Printf("  out  %s\n", spark(outVals, maxBoth))
	fmt.Printf("  in   %s\n", spark(inVals, maxBoth))
	// Tick row.
	if len(pts) > 0 {
		first := time.Unix(pts[0].BucketTs, 0).UTC().Format("15:04")
		last := time.Unix(pts[len(pts)-1].BucketTs, 0).UTC().Format("15:04")
		pad := cols - len(first) - len(last)
		if pad < 1 {
			pad = 1
		}
		ticks := first + strings.Repeat(" ", pad) + last
		fmt.Printf("       %s\n\n", ticks)
	}
	// Totals.
	var totalOut, totalIn uint64
	for _, p := range pts {
		totalOut += p.BytesOut
		totalIn += p.BytesIn
	}
	fmt.Printf("  total_out=%s  total_in=%s  combined=%s  buckets=%d\n",
		humanBytes(totalOut), humanBytes(totalIn),
		humanBytes(totalOut+totalIn), len(pts))
}

func spark(vals []uint64, max uint64) string {
	if max == 0 {
		return strings.Repeat(" ", len(vals))
	}
	out := make([]rune, len(vals))
	for i, v := range vals {
		if v == 0 {
			out[i] = ' '
			continue
		}
		idx := int(math.Floor(float64(v)/float64(max)*float64(len(sparkRunes)-1) + 0.5))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkRunes) {
			idx = len(sparkRunes) - 1
		}
		out[i] = sparkRunes[idx]
	}
	return string(out)
}

func slMax(v []uint64) uint64 {
	var m uint64
	for _, x := range v {
		if x > m {
			m = x
		}
	}
	return m
}

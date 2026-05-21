package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// alertRow is the on-disk row shape in /var/log/xhelix/alerts.jsonl.
// Loose typing: we only consume the fields we display + filter on.
type alertRow struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
	Mode   int    `json:"mode"`
	Event  struct {
		ID        string            `json:"id"`
		Time      string            `json:"time"`
		Sensor    string            `json:"sensor"`
		Severity  int               `json:"severity"`
		PID       int               `json:"pid"`
		ParentPID int               `json:"parent_pid"`
		Comm      string            `json:"comm"`
		Image     string            `json:"image"`
		Tags      map[string]string `json:"tags"`
	} `json:"event"`
}

const defaultAlertPath = "/var/log/xhelix/alerts.jsonl"

func newAlertsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "List, tail, and summarize the alert stream",
		Long: `Operator entry into the alert stream. Reads
/var/log/xhelix/alerts.jsonl. Override with --path.

  xhelixctl alerts ls --since 1h --rule shell_with_socket_fd
  xhelixctl alerts tail --rule memfd_run_pattern
  xhelixctl alerts stats --since 24h
  xhelixctl alerts show <event-id>`,
	}
	cmd.AddCommand(newAlertsLsCmd())
	cmd.AddCommand(newAlertsTailCmd())
	cmd.AddCommand(newAlertsStatsCmd())
	cmd.AddCommand(newAlertsShowCmd())
	return cmd
}

// ── ls ────────────────────────────────────────────────────────

func newAlertsLsCmd() *cobra.Command {
	var (
		path     string
		ruleFlt  string
		commFlt  string
		sevMin   string
		sinceStr string
		limit    int
	)
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List recent alerts (most-recent first)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cutoff := parseAlertsSince(sinceStr)
			minSev := severityForName(sevMin)
			rows, err := loadAlerts(path, cutoff, ruleFlt, commFlt, minSev)
			if err != nil {
				return err
			}
			// Reverse — newest first.
			for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
				rows[i], rows[j] = rows[j], rows[i]
			}
			if limit > 0 && len(rows) > limit {
				rows = rows[:limit]
			}
			printAlertTable(rows)
			fmt.Fprintf(os.Stderr, "\n%d alerts\n", len(rows))
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", defaultAlertPath, "alerts.jsonl path")
	cmd.Flags().StringVar(&ruleFlt, "rule", "", "filter by rule_id (substring)")
	cmd.Flags().StringVar(&commFlt, "comm", "", "filter by comm")
	cmd.Flags().StringVar(&sevMin, "severity", "info", "min severity (info|notice|warn|high|critical)")
	cmd.Flags().StringVar(&sinceStr, "since", "10m", "time window (e.g. 30m, 2h, 24h, 7d)")
	cmd.Flags().IntVar(&limit, "limit", 50, "max rows to print")
	return cmd
}

// ── tail ──────────────────────────────────────────────────────

func newAlertsTailCmd() *cobra.Command {
	var (
		path    string
		ruleFlt string
		commFlt string
	)
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Stream alerts as they land",
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("open %s: %w", path, err)
			}
			defer f.Close()
			if _, err := f.Seek(0, io.SeekEnd); err != nil {
				return err
			}
			rd := bufio.NewReader(f)
			for {
				line, err := rd.ReadString('\n')
				if err == io.EOF {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				if err != nil {
					return err
				}
				var row alertRow
				if err := json.Unmarshal([]byte(line), &row); err != nil {
					continue
				}
				if ruleFlt != "" && !strings.Contains(row.RuleID, ruleFlt) {
					continue
				}
				if commFlt != "" && row.Event.Comm != commFlt {
					continue
				}
				printAlertRow(row)
			}
		},
	}
	cmd.Flags().StringVar(&path, "path", defaultAlertPath, "alerts.jsonl path")
	cmd.Flags().StringVar(&ruleFlt, "rule", "", "filter by rule_id substring")
	cmd.Flags().StringVar(&commFlt, "comm", "", "filter by comm")
	return cmd
}

// ── stats ─────────────────────────────────────────────────────

func newAlertsStatsCmd() *cobra.Command {
	var (
		path     string
		sinceStr string
		groupBy  string
	)
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Histogram alerts by rule / comm / severity in a time window",
		RunE: func(cmd *cobra.Command, args []string) error {
			cutoff := parseAlertsSince(sinceStr)
			rows, err := loadAlerts(path, cutoff, "", "", 0)
			if err != nil {
				return err
			}
			counts := map[string]int{}
			for _, r := range rows {
				var key string
				switch groupBy {
				case "comm":
					key = r.Event.Comm
				case "severity":
					key = severityName(r.Event.Severity)
				case "image":
					key = r.Event.Image
				default:
					key = r.RuleID
				}
				if key == "" {
					key = "(empty)"
				}
				counts[key]++
			}
			type kv struct {
				K string
				V int
			}
			pairs := make([]kv, 0, len(counts))
			for k, v := range counts {
				pairs = append(pairs, kv{k, v})
			}
			sort.Slice(pairs, func(i, j int) bool { return pairs[i].V > pairs[j].V })
			fmt.Printf("%-40s %s\n", "  "+groupBy, "count")
			fmt.Printf("%-40s %s\n", strings.Repeat("-", 40), "-----")
			for _, p := range pairs {
				fmt.Printf("  %-38s %5d\n", truncateStr(p.K, 38), p.V)
			}
			fmt.Fprintf(os.Stderr, "\nwindow=%s, total alerts=%d, distinct %s=%d\n",
				sinceStr, len(rows), groupBy, len(pairs))
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", defaultAlertPath, "alerts.jsonl path")
	cmd.Flags().StringVar(&sinceStr, "since", "1h", "time window")
	cmd.Flags().StringVar(&groupBy, "by", "rule", "group-by: rule|comm|severity|image")
	return cmd
}

// ── show ──────────────────────────────────────────────────────

func newAlertsShowCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "show <event-id>",
		Short: "Print full JSON for an alert by event.id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 1<<20)
			for scanner.Scan() {
				if strings.Contains(scanner.Text(), `"id":"`+target+`"`) {
					var pretty map[string]any
					if err := json.Unmarshal(scanner.Bytes(), &pretty); err == nil {
						b, _ := json.MarshalIndent(pretty, "", "  ")
						fmt.Println(string(b))
					} else {
						fmt.Println(scanner.Text())
					}
					return nil
				}
			}
			return fmt.Errorf("event id %q not found", target)
		},
	}
	cmd.Flags().StringVar(&path, "path", defaultAlertPath, "alerts.jsonl path")
	return cmd
}

// ── helpers ───────────────────────────────────────────────────

func loadAlerts(path string, cutoff time.Time, ruleFlt, commFlt string, minSev int) ([]alertRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	var rows []alertRow
	for scanner.Scan() {
		var r alertRow
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			continue
		}
		if !cutoff.IsZero() && r.Event.Time != "" {
			t, err := time.Parse(time.RFC3339Nano, r.Event.Time)
			if err == nil && t.Before(cutoff) {
				continue
			}
		}
		if ruleFlt != "" && !strings.Contains(r.RuleID, ruleFlt) {
			continue
		}
		if commFlt != "" && r.Event.Comm != commFlt {
			continue
		}
		if minSev > 0 && r.Event.Severity < minSev {
			continue
		}
		rows = append(rows, r)
	}
	return rows, scanner.Err()
}

func parseAlertsSince(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	// time.ParseDuration handles s/m/h. Add naive 'd' = 24h.
	if strings.HasSuffix(s, "d") {
		days := 0
		fmt.Sscanf(s, "%dd", &days)
		if days > 0 {
			return time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return time.Time{}
	}
	return time.Now().Add(-d)
}

// Severity int values are sensor-dependent in xhelix. Use a lookup
// that matches what model.Severity uses (1=info..5=critical).
func severityForName(name string) int {
	switch strings.ToLower(name) {
	case "info":
		return 1
	case "notice":
		return 2
	case "warn":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	}
	return 0
}
func severityName(s int) string {
	switch s {
	case 1:
		return "info"
	case 2:
		return "notice"
	case 3:
		return "warn"
	case 4:
		return "high"
	case 5:
		return "critical"
	}
	return fmt.Sprintf("sev%d", s)
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func printAlertTable(rows []alertRow) {
	fmt.Printf("%-19s %-9s %-28s %-7s %-15s %s\n",
		"TIME", "SEV", "RULE", "PID", "COMM", "REASON")
	for _, r := range rows {
		t := r.Event.Time
		if len(t) > 19 {
			t = t[:19]
		}
		fmt.Printf("%-19s %-9s %-28s %-7d %-15s %s\n",
			t, severityName(r.Event.Severity),
			truncateStr(r.RuleID, 28), r.Event.PID,
			truncateStr(r.Event.Comm, 15), truncateStr(r.Reason, 60))
	}
}

func printAlertRow(r alertRow) {
	t := r.Event.Time
	if len(t) > 19 {
		t = t[:19]
	}
	fmt.Printf("[%s] %-9s %-28s pid=%-7d comm=%-15s %s\n",
		t, severityName(r.Event.Severity),
		truncateStr(r.RuleID, 28), r.Event.PID,
		truncateStr(r.Event.Comm, 15), truncateStr(r.Reason, 80))
}

package main

import (
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// newReportCmd produces a single-shot executive summary for a time
// window. Output is markdown by default; --format=html for the
// stakeholder-facing version.
//
// What's in the report:
//   - posture line (mode, sensors, allowlist loaded)
//   - alert totals by rule
//   - top-5 attack-class alerts (full event detail)
//   - top-5 lineages by takeover scorer
//   - reproducibility footer (commit, host, command line)
func newReportCmd() *cobra.Command {
	var (
		alertPath string
		logPath   string
		sinceStr  string
		format    string
	)
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate an executive summary for a time window",
		RunE: func(cmd *cobra.Command, args []string) error {
			cutoff := parseAlertsSince(sinceStr)
			rows, err := loadAlerts(alertPath, cutoff, "", "", 0)
			if err != nil {
				return err
			}
			plans, _ := loadPlannerShadow(logPath, cutoff)

			r := reportData{
				Window:    sinceStr,
				Generated: time.Now().UTC().Format(time.RFC3339),
				Total:     len(rows),
			}
			r.computeRuleHistogram(rows)
			r.computeAttackHeadlines(rows)
			r.computeTopLineages(rows, plans)

			switch format {
			case "html":
				renderHTML(os.Stdout, r)
			default:
				renderMarkdown(os.Stdout, r)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&alertPath, "path", defaultAlertPath, "alerts.jsonl path")
	cmd.Flags().StringVar(&logPath, "log", "/var/log/xhelix/xhelix.out", "xhelix.out path")
	cmd.Flags().StringVar(&sinceStr, "since", "1h", "time window")
	cmd.Flags().StringVar(&format, "format", "md", "output format: md|html")
	return cmd
}

type reportData struct {
	Window    string
	Generated string
	Total     int
	Rules     []ruleStat
	Attack    []alertRow
	Lineages  []LineageInfo
}

type ruleStat struct {
	Rule  string
	Count int
}

func (r *reportData) computeRuleHistogram(rows []alertRow) {
	c := map[string]int{}
	for _, a := range rows {
		c[a.RuleID]++
	}
	for k, v := range c {
		r.Rules = append(r.Rules, ruleStat{k, v})
	}
	sort.Slice(r.Rules, func(i, j int) bool { return r.Rules[i].Count > r.Rules[j].Count })
}

func (r *reportData) computeAttackHeadlines(rows []alertRow) {
	attack := map[string]bool{
		"shell_with_socket_fd": true, "revshell.detected": true,
		"memfd_run_pattern": true, "web_server_spawns_shell": true,
		"ld_so_preload_modified": true, "cron_new_unit": true,
		"ssh_key_added_root": true, "tamper_passwd": true, "tamper_shadow": true,
		"metadata_svc_unexpected": true, "metadata.access_by_unexpected": true,
		"ptrace_sensitive_target": true, "binary_runs_from_tmp": true,
		"lolbin.suspicious": true, "pam_module_drop": true,
		"systemd_unit_added": true, "any_ptrace": true,
	}
	for i := len(rows) - 1; i >= 0 && len(r.Attack) < 10; i-- {
		if attack[rows[i].RuleID] {
			r.Attack = append(r.Attack, rows[i])
		}
	}
}

func (r *reportData) computeTopLineages(rows []alertRow, plans map[int]plannerShadow) {
	lin := groupByLineage(rows, plans)
	sort.Slice(lin, func(i, j int) bool { return lin[i].Suspicion > lin[j].Suspicion })
	if len(lin) > 10 {
		lin = lin[:10]
	}
	r.Lineages = lin
}

// ── markdown ─────────────────────────────────────────────────

func renderMarkdown(w *os.File, r reportData) {
	fmt.Fprintf(w, "# xhelix detection report — %s window\n\n", r.Window)
	fmt.Fprintf(w, "*Generated %s · total alerts: %d*\n\n", r.Generated, r.Total)

	fmt.Fprintln(w, "## Alerts by rule")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "| Rule | Count |")
	fmt.Fprintln(w, "|---|---|")
	for _, rs := range r.Rules {
		fmt.Fprintf(w, "| `%s` | %d |\n", rs.Rule, rs.Count)
	}

	fmt.Fprintln(w, "\n## Top attack-class events")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "| Time | Rule | PID | Comm | Reason |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for _, a := range r.Attack {
		t := a.Event.Time
		if len(t) > 19 {
			t = t[:19]
		}
		fmt.Fprintf(w, "| %s | `%s` | %d | `%s` | %s |\n",
			t, a.RuleID, a.Event.PID, a.Event.Comm, sanitizeMD(a.Reason))
	}

	fmt.Fprintln(w, "\n## Top lineages (causal chain)")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "| Lineage | PIDs | Tier | Score | Alerts | Top rules | Comms |")
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|")
	for _, l := range r.Lineages {
		comms := []string{}
		commSet := map[string]struct{}{}
		for _, c := range l.Pids {
			if _, ok := commSet[c]; !ok {
				commSet[c] = struct{}{}
				comms = append(comms, c)
			}
		}
		topRules := []string{}
		for rule, n := range l.RuleCounts {
			topRules = append(topRules, fmt.Sprintf("%s(%d)", rule, n))
		}
		sort.Strings(topRules)
		if len(topRules) > 3 {
			topRules = topRules[:3]
		}
		tier := l.Tier
		if tier == "" {
			tier = "-"
		}
		score := "-"
		if l.Score > 0 {
			score = fmt.Sprintf("%d", l.Score)
		}
		fmt.Fprintf(w, "| %d | %d | %s | %s | %d | %s | %s |\n",
			l.CGroupID, len(l.Pids), tier, score, l.AlertCount,
			strings.Join(topRules, ", "), strings.Join(comms, ", "))
	}
	fmt.Fprintf(w, "\n---\n*Window: %s · Generated by xhelixctl report*\n", r.Window)
}

// ── html ────────────────────────────────────────────────────

func renderHTML(w *os.File, r reportData) {
	fmt.Fprintln(w, `<!doctype html><meta charset=utf-8>`)
	fmt.Fprintf(w, `<title>xhelix report — %s</title>`, r.Window)
	fmt.Fprintln(w, `<style>
body{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#222}
h1{border-bottom:2px solid #333;padding-bottom:6px}
h2{margin-top:32px;color:#0a4}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #ddd;padding:6px 10px;text-align:left;font-size:13px}
th{background:#f4f4f4}
tr.attack{background:#fff5f5}
tr.isolated{background:#ffe5e5;font-weight:600}
tr.triaged{background:#fff8e1}
tr.suspended{background:#ffefcc}
code{background:#eef;padding:1px 4px;border-radius:3px;font-family:Menlo,monospace}
.foot{color:#888;margin-top:24px;font-size:12px}
</style>`)
	fmt.Fprintf(w, `<h1>xhelix detection report — %s window</h1>`, html.EscapeString(r.Window))
	fmt.Fprintf(w, `<p>Generated <code>%s</code> · total alerts <b>%d</b></p>`,
		html.EscapeString(r.Generated), r.Total)

	fmt.Fprintln(w, `<h2>Alerts by rule</h2><table><tr><th>Rule</th><th>Count</th></tr>`)
	for _, rs := range r.Rules {
		fmt.Fprintf(w, `<tr><td><code>%s</code></td><td>%d</td></tr>`,
			html.EscapeString(rs.Rule), rs.Count)
	}
	fmt.Fprintln(w, `</table>`)

	fmt.Fprintln(w, `<h2>Top attack-class events</h2><table><tr><th>Time</th><th>Rule</th><th>PID</th><th>Comm</th><th>Reason</th></tr>`)
	for _, a := range r.Attack {
		t := a.Event.Time
		if len(t) > 19 {
			t = t[:19]
		}
		fmt.Fprintf(w, `<tr class=attack><td>%s</td><td><code>%s</code></td><td>%d</td><td><code>%s</code></td><td>%s</td></tr>`,
			html.EscapeString(t), html.EscapeString(a.RuleID),
			a.Event.PID, html.EscapeString(a.Event.Comm),
			html.EscapeString(a.Reason))
	}
	fmt.Fprintln(w, `</table>`)

	fmt.Fprintln(w, `<h2>Top lineages (causal chain)</h2><table><tr><th>Lineage</th><th>PIDs</th><th>Tier</th><th>Score</th><th>Alerts</th><th>Top rules</th><th>Comms</th></tr>`)
	for _, l := range r.Lineages {
		commSet := map[string]struct{}{}
		for _, c := range l.Pids {
			commSet[c] = struct{}{}
		}
		comms := make([]string, 0, len(commSet))
		for c := range commSet {
			comms = append(comms, c)
		}
		sort.Strings(comms)
		topRules := []string{}
		for rule, n := range l.RuleCounts {
			topRules = append(topRules, fmt.Sprintf("%s(%d)", rule, n))
		}
		sort.Strings(topRules)
		if len(topRules) > 3 {
			topRules = topRules[:3]
		}
		tier := l.Tier
		if tier == "" {
			tier = "-"
		}
		score := "-"
		if l.Score > 0 {
			score = fmt.Sprintf("%d", l.Score)
		}
		cls := tier
		fmt.Fprintf(w, `<tr class=%s><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>`,
			html.EscapeString(cls), l.CGroupID, len(l.Pids),
			html.EscapeString(tier), html.EscapeString(score),
			l.AlertCount, html.EscapeString(strings.Join(topRules, ", ")),
			html.EscapeString(strings.Join(comms, ", ")))
	}
	fmt.Fprintln(w, `</table>`)
	fmt.Fprintf(w, `<p class=foot>Window: %s · Generated by xhelixctl report</p>`,
		html.EscapeString(r.Window))
}

func sanitizeMD(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// newTakeoverCmd surfaces the per-lineage view of attacker activity.
// This is the operator's "blast radius" tool: ONE process tree per
// row, with the count of alerts that lineage caused and (if a
// "planner shadow" line was logged) the takeover scorer's tier +
// score. The intent of the screen is to make legit vs attacker
// lineages distinguishable at a glance.
//
// Data sources:
//   - /var/log/xhelix/alerts.jsonl  (per-event records)
//   - /var/log/xhelix/xhelix.out   (planner shadow lines)
func newTakeoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "takeover",
		Short: "Per-lineage takeover-scorer view (blast-radius)",
	}
	cmd.AddCommand(newLineagesCmd())
	return cmd
}

func newLineagesCmd() *cobra.Command {
	var (
		alertPath string
		logPath   string
		sinceStr  string
		top       int
		minAlerts int
	)
	cmd := &cobra.Command{
		Use:   "lineages",
		Short: "Rank process lineages by alert volume + planner score",
		Long: `Reads alerts.jsonl, groups by (cgroup_id, parent_pid)
ancestry, and ranks lineages by an aggregate suspicion score derived
from alert count + per-rule severity weight. When the daemon's
planner emits a "planner shadow" line for a lineage (logged to
xhelix.out), its tier + score are joined in. The result is the demo
proof that ONE attacker lineage stands apart from N legit ones.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cutoff := parseAlertsSince(sinceStr)
			rows, err := loadAlerts(alertPath, cutoff, "", "", 0)
			if err != nil {
				return err
			}
			plans, _ := loadPlannerShadow(logPath, cutoff)
			lineages := groupByLineage(rows, plans)

			// Filter + sort by suspicion score, descending.
			filtered := lineages[:0]
			for _, l := range lineages {
				if l.AlertCount >= minAlerts {
					filtered = append(filtered, l)
				}
			}
			sort.Slice(filtered, func(i, j int) bool {
				return filtered[i].Suspicion > filtered[j].Suspicion
			})
			if top > 0 && len(filtered) > top {
				filtered = filtered[:top]
			}

			printLineageTable(filtered)
			fmt.Fprintf(os.Stderr, "\nwindow=%s, lineages with >=%d alerts=%d, scored=%d\n",
				sinceStr, minAlerts, len(filtered), countWithPlanner(filtered))
			return nil
		},
	}
	cmd.Flags().StringVar(&alertPath, "path", defaultAlertPath, "alerts.jsonl path")
	cmd.Flags().StringVar(&logPath, "log", "/var/log/xhelix/xhelix.out", "xhelix.out path (for planner shadow)")
	cmd.Flags().StringVar(&sinceStr, "since", "5m", "time window (s/m/h/d)")
	cmd.Flags().IntVar(&top, "top", 10, "show top N lineages")
	cmd.Flags().IntVar(&minAlerts, "min-alerts", 1, "drop lineages with fewer alerts")
	return cmd
}

// ── lineage aggregation ──────────────────────────────────────

// LineageInfo aggregates everything we know about one process tree
// for the window.
type LineageInfo struct {
	RootPID    int
	CGroupID   int
	Pids       map[int]string // pid -> comm
	RuleCounts map[string]int
	AlertCount int
	Suspicion  int // ≈ alert count weighted by per-rule severity
	Tier       string
	Score      int
	Actions    string
}

// groupByLineage joins alerts to (cgroup_id, root-of-pid-tree) and
// joins planner shadow data when keyable by cgroup_id.
func groupByLineage(alerts []alertRow, plans map[int]plannerShadow) []LineageInfo {
	// First pass: collect pid → parent_pid + comm + cgroup_id, plus
	// the per-pid suspicion contributions.
	type pidInfo struct {
		Comm        string
		ParentPID   int
		CGroupID    int
		Rules       map[string]int
		Suspicion   int
	}
	pids := map[int]*pidInfo{}
	for _, a := range alerts {
		e := a.Event
		if e.PID == 0 {
			continue
		}
		info, ok := pids[e.PID]
		if !ok {
			info = &pidInfo{Rules: map[string]int{}}
			pids[e.PID] = info
		}
		info.Comm = e.Comm
		info.ParentPID = e.ParentPID
		// alertRow loses cgroup_id by default; pull from tags.
		if cg := e.Tags["cgroup_id"]; cg != "" {
			fmt.Sscanf(cg, "%d", &info.CGroupID)
		}
		info.Rules[a.RuleID]++
		info.Suspicion += ruleSuspicion(a.RuleID)
	}
	// Second pass: cluster by cgroup_id if present; else by walking
	// parent_pid to the highest ancestor we have data for.
	byKey := map[int]*LineageInfo{}
	for pid, info := range pids {
		key := info.CGroupID
		if key == 0 {
			// Walk up the parent chain until parent is unknown.
			cur := pid
			for {
				p, ok := pids[cur]
				if !ok || p.ParentPID == 0 {
					break
				}
				if _, hasParent := pids[p.ParentPID]; !hasParent {
					break
				}
				cur = p.ParentPID
			}
			key = -cur // negative: distinguishes from real cgroup_id
		}
		li, ok := byKey[key]
		if !ok {
			li = &LineageInfo{
				CGroupID:   info.CGroupID,
				Pids:       map[int]string{},
				RuleCounts: map[string]int{},
			}
			byKey[key] = li
		}
		if li.RootPID == 0 || pid < li.RootPID {
			li.RootPID = pid // approximate: smallest PID we've seen
		}
		li.Pids[pid] = info.Comm
		for r, n := range info.Rules {
			li.RuleCounts[r] += n
			li.AlertCount += n
		}
		li.Suspicion += info.Suspicion
	}
	// Third pass: join planner shadow by cgroup_id (the planner uses
	// lineage_id which derives from cgroup_id + start_time).
	out := make([]LineageInfo, 0, len(byKey))
	for _, li := range byKey {
		if li.CGroupID > 0 {
			if p, ok := plans[li.CGroupID]; ok {
				li.Tier = p.Tier
				li.Score = p.Score
				li.Actions = p.Actions
			}
		}
		out = append(out, *li)
	}
	return out
}

// ruleSuspicion is a per-rule weight that biases the per-lineage
// score so that high-confidence attack rules dominate noisy ones.
func ruleSuspicion(ruleID string) int {
	switch ruleID {
	case "shell_with_socket_fd", "revshell.detected",
		"web_server_spawns_shell", "ld_so_preload_modified",
		"pam_module_drop", "ssh_key_added_root", "tamper_shadow",
		"tamper_passwd", "metadata_svc_unexpected",
		"metadata.access_by_unexpected":
		return 5
	case "memfd_run_pattern", "binary_runs_from_tmp",
		"cron_new_unit", "ptrace_sensitive_target",
		"systemd_unit_added", "any_ptrace":
		return 3
	case "mem_mprotect_rwx", "bpf_syscall_unexpected", "lolbin.suspicious":
		return 2
	case "cap.gained", "ungated", "fim.drift":
		return 1
	}
	return 1
}

// ── planner shadow ───────────────────────────────────────────

type plannerShadow struct {
	LineageID int
	Tier      string
	Score     int
	Actions   string
}

func loadPlannerShadow(path string, cutoff time.Time) (map[int]plannerShadow, error) {
	f, err := os.Open(path)
	if err != nil {
		return map[int]plannerShadow{}, err
	}
	defer f.Close()
	out := map[int]plannerShadow{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "planner shadow") {
			continue
		}
		// Parse loose key=value-from-slog format.
		ts := extractField(line, "time=")
		if ts != "" && !cutoff.IsZero() {
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil && t.Before(cutoff) {
				continue
			}
		}
		var lin, score int
		fmt.Sscanf(extractField(line, "lineage="), "%d", &lin)
		fmt.Sscanf(extractField(line, "score="), "%d", &score)
		tier := extractField(line, "tier=")
		actions := extractQuoted(line, "actions=")
		if lin > 0 {
			// Keep the highest-score plan per lineage in the window.
			if existing, ok := out[lin]; !ok || score > existing.Score {
				out[lin] = plannerShadow{
					LineageID: lin, Tier: tier, Score: score, Actions: actions,
				}
			}
		}
	}
	return out, scanner.Err()
}

func extractField(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(key):]
	end := strings.IndexAny(rest, " \"")
	if end < 0 {
		return rest
	}
	return rest[:end]
}
func extractQuoted(line, key string) string {
	idx := strings.Index(line, key+"\"")
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(key)+1:]
	end := strings.Index(rest, "\"")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// ── output ───────────────────────────────────────────────────

func printLineageTable(rows []LineageInfo) {
	fmt.Printf("%-8s %-12s %-9s %-7s %-7s %-30s %s\n",
		"LINEAGE", "PIDS", "TIER", "SCORE", "ALERTS", "TOP-RULES", "COMMS")
	fmt.Printf("%-8s %-12s %-9s %-7s %-7s %-30s %s\n",
		strings.Repeat("-", 8), strings.Repeat("-", 12),
		strings.Repeat("-", 9), strings.Repeat("-", 7),
		strings.Repeat("-", 7), strings.Repeat("-", 30),
		strings.Repeat("-", 20))
	for _, r := range rows {
		// Top-3 rules
		type rk struct {
			Rule string
			N    int
		}
		ranked := make([]rk, 0, len(r.RuleCounts))
		for rule, n := range r.RuleCounts {
			ranked = append(ranked, rk{rule, n})
		}
		sort.Slice(ranked, func(i, j int) bool { return ranked[i].N > ranked[j].N })
		topRules := []string{}
		for i, x := range ranked {
			if i >= 3 {
				break
			}
			topRules = append(topRules, fmt.Sprintf("%s(%d)", shortRule(x.Rule), x.N))
		}
		// Distinct comms (truncated)
		commSet := map[string]struct{}{}
		for _, c := range r.Pids {
			commSet[c] = struct{}{}
		}
		comms := make([]string, 0, len(commSet))
		for c := range commSet {
			comms = append(comms, c)
		}
		sort.Strings(comms)
		commsStr := strings.Join(comms, ",")
		tier := r.Tier
		if tier == "" {
			tier = "-"
		}
		score := "-"
		if r.Score > 0 {
			score = fmt.Sprintf("%d", r.Score)
		}
		fmt.Printf("%-8d %-12d %-9s %-7s %-7d %-30s %s\n",
			r.CGroupID, len(r.Pids), tier, score, r.AlertCount,
			truncateStr(strings.Join(topRules, ","), 30),
			truncateStr(commsStr, 60))
	}
}

func shortRule(r string) string {
	r = strings.TrimSuffix(r, ".detected")
	if len(r) > 10 {
		return r[:10]
	}
	return r
}

func countWithPlanner(rows []LineageInfo) int {
	n := 0
	for _, r := range rows {
		if r.Tier != "" {
			n++
		}
	}
	return n
}

// json-marshaling helper for alerts.jsonl loaders not in this file
// (kept for compile cleanliness — alertRow defined in alerts.go).
var _ = json.Unmarshal

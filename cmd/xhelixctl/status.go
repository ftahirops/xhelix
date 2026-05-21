package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// newStatusCmd is the operator's single-pane summary: is xhelix
// alive, what sensors are loaded, how busy is the alert pipeline,
// what's the top-rule histogram for the most recent window. With
// --watch it refreshes every 2s in-place, becoming the demo
// dashboard.
func newStatusCmd() *cobra.Command {
	var (
		watch     bool
		interval  time.Duration
		alertPath string
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Single-pane daemon + alert summary (use --watch for live)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !watch {
				return renderStatus(os.Stdout, alertPath)
			}
			fmt.Print("\033[2J\033[H") // clear screen
			for {
				fmt.Print("\033[H") // home cursor (don't clear — flicker)
				if err := renderStatus(os.Stdout, alertPath); err != nil {
					return err
				}
				time.Sleep(interval)
			}
		},
	}
	cmd.Flags().BoolVarP(&watch, "watch", "w", false, "refresh in place every --interval")
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "refresh interval for --watch")
	cmd.Flags().StringVar(&alertPath, "path", defaultAlertPath, "alerts.jsonl path")
	return cmd
}

func renderStatus(w *os.File, alertPath string) error {
	const sep = "════════════════════════════════════════════════════════════════"
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, " xhelix status — %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintln(w, sep)

	// Daemon health
	dpid, dage, dmem := daemonHealth()
	fmt.Fprintf(w, " daemon: ")
	if dpid > 0 {
		fmt.Fprintf(w, "RUNNING pid=%d age=%s rss=%s\n", dpid, dage, dmem)
	} else {
		fmt.Fprintln(w, "NOT RUNNING")
	}

	// Socket reachable?
	if _, err := os.Stat("/run/xhelix/xhelix.sock"); err == nil {
		fmt.Fprintln(w, " localapi socket: /run/xhelix/xhelix.sock present")
	}

	// Sensors started (parsed from xhelix.out)
	sensors := loadStartedSensors("/var/log/xhelix/xhelix.out")
	fmt.Fprintf(w, " sensors started: %s\n", strings.Join(sensors, ", "))

	// Config posture knobs
	for _, line := range readPostureLines("/var/log/xhelix/xhelix.out") {
		fmt.Fprintf(w, " %s\n", line)
	}

	fmt.Fprintln(w, sep)
	fmt.Fprintln(w, " alert volume — last 1m / 5m / 1h")
	fmt.Fprintln(w, sep)
	for _, win := range []string{"1m", "5m", "1h"} {
		cutoff := parseAlertsSince(win)
		rows, _ := loadAlerts(alertPath, cutoff, "", "", 0)
		fmt.Fprintf(w, "   %s: %5d alerts\n", win, len(rows))
	}

	// Last 1m: per-rule top 8
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w, " top rules in last 5 min")
	fmt.Fprintln(w, sep)
	cutoff := parseAlertsSince("5m")
	rows, _ := loadAlerts(alertPath, cutoff, "", "", 0)
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.RuleID]++
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
	for i, p := range pairs {
		if i >= 8 {
			break
		}
		fmt.Fprintf(w, "   %-32s %5d\n", truncateStr(p.K, 32), p.V)
	}

	// Recent attack-class alerts (the demo headline)
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w, " recent attack-class alerts (last 5m)")
	fmt.Fprintln(w, sep)
	attack := []string{
		"shell_with_socket_fd", "revshell.detected", "memfd_run_pattern",
		"web_server_spawns_shell", "ld_so_preload_modified",
		"cron_new_unit", "ssh_key_added_root", "systemd_unit_added",
		"tamper_passwd", "tamper_shadow", "metadata_svc_unexpected",
		"metadata.access_by_unexpected", "ptrace_sensitive_target",
		"binary_runs_from_tmp", "lolbin.suspicious", "any_ptrace",
	}
	attackSet := map[string]bool{}
	for _, a := range attack {
		attackSet[a] = true
	}
	matched := 0
	for i := len(rows) - 1; i >= 0 && matched < 8; i-- {
		r := rows[i]
		if !attackSet[r.RuleID] {
			continue
		}
		t := r.Event.Time
		if len(t) > 19 {
			t = t[:19]
		}
		fmt.Fprintf(w, "   [%s] %-25s pid=%-6d comm=%-12s %s\n",
			t, truncateStr(r.RuleID, 25), r.Event.PID,
			truncateStr(r.Event.Comm, 12),
			truncateStr(r.Reason, 60))
		matched++
	}
	if matched == 0 {
		fmt.Fprintln(w, "   (none — quiet)")
	}

	// Top planner shadow plans (causal-chain demo)
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w, " takeover planner — top scored lineages (last 5m)")
	fmt.Fprintln(w, sep)
	plans, _ := loadPlannerShadow("/var/log/xhelix/xhelix.out", cutoff)
	plist := make([]plannerShadow, 0, len(plans))
	for _, p := range plans {
		plist = append(plist, p)
	}
	sort.Slice(plist, func(i, j int) bool { return plist[i].Score > plist[j].Score })
	for i, p := range plist {
		if i >= 5 {
			break
		}
		fmt.Fprintf(w, "   lineage=%-8d tier=%-9s score=%-3d actions=%s\n",
			p.LineageID, p.Tier, p.Score, truncateStr(p.Actions, 60))
	}
	if len(plist) == 0 {
		fmt.Fprintln(w, "   (no planner plans in window)")
	}
	fmt.Fprintln(w, sep)
	return nil
}

// ── helpers ────────────────────────────────────────────────────

func daemonHealth() (int, string, string) {
	out, err := exec.Command("pgrep", "-f", "xhelix run --config").Output()
	if err != nil {
		return 0, "", ""
	}
	first := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	pid, err := strconv.Atoi(first)
	if err != nil {
		return 0, "", ""
	}
	// etime + rss via ps
	ps, err := exec.Command("ps", "-o", "etime=,rss=", "-p", first).Output()
	if err != nil {
		return pid, "", ""
	}
	fields := strings.Fields(string(ps))
	age, rss := "", ""
	if len(fields) >= 1 {
		age = fields[0]
	}
	if len(fields) >= 2 {
		// rss in KB
		if k, err := strconv.Atoi(fields[1]); err == nil {
			if k > 1024 {
				rss = fmt.Sprintf("%dMB", k/1024)
			} else {
				rss = fmt.Sprintf("%dKB", k)
			}
		}
	}
	return pid, age, rss
}

func loadStartedSensors(logPath string) []string {
	f, err := os.Open(logPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	set := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "sensor started") {
			continue
		}
		s := extractField(line, "sensor=")
		if s != "" {
			set[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func readPostureLines(logPath string) []string {
	f, err := os.Open(logPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	matches := []string{}
	wantPrefixes := []string{
		"response engine enabled",
		"runtime-allowlist loaded",
		"protected services loaded",
		"planner wiring enabled",
		"forensic ingestor enabled",
		"chain ready",
		"file sink configured",
	}
	for scanner.Scan() {
		line := scanner.Text()
		for _, p := range wantPrefixes {
			if strings.Contains(line, p) {
				// Keep only most-recent occurrence per prefix.
				matches = appendUniqueByPrefix(matches, line, p)
				break
			}
		}
	}
	return matches
}

func appendUniqueByPrefix(arr []string, line, key string) []string {
	for i, e := range arr {
		if strings.Contains(e, key) {
			arr[i] = line
			return arr
		}
	}
	return append(arr, line)
}

// keep linter happy — these refer to types defined elsewhere in the
// xhelixctl package.
var _ = filepath.Base
var _ = json.Unmarshal
var _ net.IP

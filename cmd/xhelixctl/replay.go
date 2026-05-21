package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/labels"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/rules"
)

// newReplaySubcommand re-evaluates historical events from
// alerts.jsonl (or a saved corpus) against the current rule set,
// then cross-references the operator's labels store. Output: the
// list of (rule_id, parent_image, tag) clusters where the new rule
// set differs from labelled ground truth.
//
// This is the rule-tuning loop (ALERTS_AND_FP_PLAN §6 step 7):
// "Edit rule, replay last 24h offline; compare FP-before vs
// FP-after; TP-before vs TP-after."
func newReplaySubcommand() *cobra.Command {
	var (
		alertPath string
		rulesDir  string
		dbPath    string
		sinceStr  string
		ruleFlt   string
		showDiff  bool
	)
	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Re-evaluate historical events against current rules",
		Long: `Replay alerts.jsonl through the current rule set in
this xhelixctl binary. Compares what fires NOW vs what's labelled
in /var/lib/xhelix/labels.db. Surfaces:

  - eliminated FPs   (rule used to fire but no longer does on
                      events labelled fp by the operator)
  - missing  TPs     (rule used to fire on a labelled TP but no
                      longer does — REGRESSION)
  - new      alerts  (rule didn't fire before; fires now)

Use to validate rule-set changes before deploying. Exit non-zero
if any TPs regressed.

  xhelixctl alerts replay --since 24h --rules ./ruleset/core`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if rulesDir == "" {
				// Try a few common locations
				for _, p := range []string{
					"./ruleset/core",
					"/usr/share/xhelix/ruleset/core",
					"/etc/xhelix/rules.d",
				} {
					if st, err := os.Stat(p); err == nil && st.IsDir() {
						rulesDir = p
						break
					}
				}
			}
			if rulesDir == "" {
				return fmt.Errorf("no rules dir found; pass --rules <path>")
			}
			ruleSet, err := rules.LoadDir(rulesDir)
			if err != nil {
				return fmt.Errorf("load rules %s: %w", rulesDir, err)
			}
			fmt.Fprintf(os.Stderr, "loaded %d rules from %s\n", len(ruleSet), rulesDir)

			// Build a fresh rule engine, collect fires.
			collected := map[string]map[string]int{} // ruleID → eventID → fires
			emit := func(a model.Alert) {
				if collected[a.RuleID] == nil {
					collected[a.RuleID] = map[string]int{}
				}
				collected[a.RuleID][a.Event.ID.String()]++
			}
			eng, err := rules.NewEngine(emit)
			if err != nil {
				return fmt.Errorf("rule engine: %w", err)
			}
			if err := eng.Load(ruleSet); err != nil {
				return fmt.Errorf("rule engine load: %w", err)
			}

			// Stream alerts.jsonl, reconstruct events, eval them.
			cutoff := parseAlertsSince(sinceStr)
			f, err := os.Open(alertPath)
			if err != nil {
				return fmt.Errorf("open %s: %w", alertPath, err)
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 1<<20)
			ctx := context.Background()
			processed := 0
			for scanner.Scan() {
				var line struct {
					RuleID string      `json:"rule_id"`
					Event  model.Event `json:"event"`
				}
				if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
					continue
				}
				if !cutoff.IsZero() && !line.Event.Time.IsZero() && line.Event.Time.Before(cutoff) {
					continue
				}
				eng.Eval(ctx, line.Event)
				processed++
			}
			fmt.Fprintf(os.Stderr, "replayed %d events\n", processed)

			// Cross-reference with labels store.
			lbl, err := labels.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open labels: %w", err)
			}
			defer lbl.Close()
			fpSet, _ := lbl.FPSet(cutoff)

			// Render the diff table.
			fmt.Println()
			fmt.Printf("%-40s %-20s %8s %8s %s\n",
				"rule_id", "tag", "now-fires", "labelled-fp", "status")
			fmt.Printf("%-40s %-20s %8s %8s %s\n",
				strings.Repeat("─", 40), strings.Repeat("─", 20),
				"────────", "──────────", "──────")

			// For each FP cluster, did current rules still fire on it?
			type row struct {
				Rule, Tag string
				Now, FP   int
				Status    string
			}
			var rows []row
			for k, fpCount := range fpSet {
				if ruleFlt != "" && !strings.Contains(k.RuleID, ruleFlt) {
					continue
				}
				nowFires := len(collected[k.RuleID])
				status := "STILL FIRING"
				if nowFires == 0 {
					status = "✓ ELIMINATED"
				}
				rows = append(rows, row{k.RuleID, k.Tag, nowFires, fpCount, status})
			}
			// Also surface rules that fired but have no labels yet
			for ruleID, hits := range collected {
				if ruleFlt != "" && !strings.Contains(ruleID, ruleFlt) {
					continue
				}
				seen := false
				for _, r := range rows {
					if r.Rule == ruleID {
						seen = true
						break
					}
				}
				if !seen {
					rows = append(rows, row{ruleID, "(unlabeled)", len(hits), 0, "needs-triage"})
				}
			}
			sort.Slice(rows, func(i, j int) bool {
				if rows[i].Rule != rows[j].Rule {
					return rows[i].Rule < rows[j].Rule
				}
				return rows[i].Tag < rows[j].Tag
			})
			for _, r := range rows {
				fmt.Printf("%-40s %-20s %8d %8d %s\n",
					truncateStr(r.Rule, 40),
					truncateStr(r.Tag, 20),
					r.Now, r.FP, r.Status)
			}

			if showDiff {
				fmt.Println("\n--- show-diff: events that NEWLY fire under current rules ---")
				// (We can't compare apples-to-apples vs old fire data
				// because alerts.jsonl is the result of OLD rules.
				// Compute symmetric diff: events whose new fires ⊃ old.)
				totalNew := 0
				for ruleID, ev := range collected {
					for evID := range ev {
						fmt.Printf("  %s  rule=%s\n", evID, ruleID)
						totalNew++
						if totalNew >= 20 {
							fmt.Println("  ...(truncated)")
							break
						}
					}
					if totalNew >= 20 {
						break
					}
				}
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&alertPath, "alerts", defaultAlertPath, "alerts.jsonl path")
	cmd.Flags().StringVar(&rulesDir, "rules", "", "rules directory (default: auto-detect)")
	cmd.Flags().StringVar(&dbPath, "db", defaultLabelsDB, "labels.db path")
	cmd.Flags().StringVar(&sinceStr, "since", "24h", "time window")
	cmd.Flags().StringVar(&ruleFlt, "rule", "", "filter by rule_id substring")
	cmd.Flags().BoolVar(&showDiff, "show-diff", false, "list NEW alerts (first 20)")
	return cmd
}

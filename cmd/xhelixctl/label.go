package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/labels"
)

const defaultLabelsDB = "/var/lib/xhelix/labels.db"

// newLabelSubcommand returns the `alerts label` subcommand that
// records an operator's verdict on a specific event_id. Used as
// the ground-truth input for FP-rate measurement (see ALERTS_AND
// _FP_PLAN §3).
func newLabelSubcommand() *cobra.Command {
	var (
		dbPath    string
		verdict   string
		tag       string
		notes     string
		byUser    string
		hostClass string
		ruleID    string
	)
	cmd := &cobra.Command{
		Use:   "label <event-id>",
		Short: "Record TP / FP verdict for an alert",
		Long: `Records the operator's verdict on a specific alert.
Inputs feed the per-rule FP-rate dashboard and the replay tool's
regression detection. Verdicts: tp | fp | benign | unknown.

  xhelixctl alerts label 01KS5A47B4APDYTXPYT5MX6F1T --verdict fp \
      --tag node-jit --notes "legit V8 JIT churn"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eventID := args[0]
			s, err := labels.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open labels db at %s: %w", dbPath, err)
			}
			defer s.Close()
			if byUser == "" {
				byUser = os.Getenv("USER")
				if byUser == "" {
					byUser = "anon"
				}
			}
			// Best-effort rule_id lookup from alerts.jsonl if not given
			if ruleID == "" {
				if r := lookupRuleID(eventID); r != "" {
					ruleID = r
				}
			}
			l := labels.Label{
				EventID:   eventID,
				RuleID:    ruleID,
				Verdict:   labels.Verdict(verdict),
				Tag:       tag,
				By:        byUser,
				At:        time.Now().UTC(),
				HostClass: hostClass,
				Notes:     notes,
			}
			if err := s.Put(l); err != nil {
				return fmt.Errorf("put label: %w", err)
			}
			fmt.Printf("labelled %s rule=%s verdict=%s tag=%s by=%s\n",
				eventID, ruleID, verdict, tag, byUser)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", defaultLabelsDB, "labels.db path")
	cmd.Flags().StringVar(&verdict, "verdict", "fp", "tp | fp | benign | unknown")
	cmd.Flags().StringVar(&tag, "tag", "", "free-text tag (e.g. node-jit)")
	cmd.Flags().StringVar(&notes, "notes", "", "free-text notes")
	cmd.Flags().StringVar(&byUser, "by", "", "operator user (default $USER)")
	cmd.Flags().StringVar(&hostClass, "host-class", "", "host class (dev_ws|prod_web|...)")
	cmd.Flags().StringVar(&ruleID, "rule", "", "rule_id (auto-detected from alerts.jsonl if omitted)")
	return cmd
}

// lookupRuleID searches alerts.jsonl for an event id and returns
// its rule_id, or "" if not found. Best-effort only.
func lookupRuleID(eventID string) string {
	rows, err := loadAlerts(defaultAlertPath, time.Time{}, "", "", 0)
	if err != nil {
		return ""
	}
	for _, r := range rows {
		if r.Event.ID == eventID {
			return r.RuleID
		}
	}
	return ""
}

// newFPRateSubcommand surfaces the per-rule FP-rate table from
// the labels store.
func newFPRateSubcommand() *cobra.Command {
	var (
		dbPath   string
		sinceStr string
	)
	cmd := &cobra.Command{
		Use:   "fp-rate",
		Short: "Per-rule TP/FP/benign breakdown from operator labels",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := labels.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open labels db: %w", err)
			}
			defer s.Close()
			since := parseAlertsSince(sinceStr)
			stats, err := s.PerRule(since)
			if err != nil {
				return err
			}
			total, _ := s.Count()
			fmt.Printf("%-32s %5s %5s %7s %7s %7s\n",
				"rule", "TP", "FP", "benign", "unknown", "FP%")
			fmt.Printf("%-32s %5s %5s %7s %7s %7s\n",
				"────", "──", "──", "──────", "───────", "───")
			for _, st := range stats {
				labelled := st.TP + st.FP + st.Benign
				fpRate := "-"
				if labelled > 0 {
					fpRate = fmt.Sprintf("%.1f%%", float64(st.FP)*100/float64(labelled))
				}
				fmt.Printf("%-32s %5d %5d %7d %7d %7s\n",
					truncateStr(st.RuleID, 32),
					st.TP, st.FP, st.Benign, st.Unknown, fpRate)
			}
			fmt.Fprintf(os.Stderr, "\ntotal labels in DB: %d  window=%s\n",
				total, sinceStr)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", defaultLabelsDB, "labels.db path")
	cmd.Flags().StringVar(&sinceStr, "since", "30d", "time window for stats")
	return cmd
}

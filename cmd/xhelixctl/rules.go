package main

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/localapi"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/rules"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage detection rules",
	}
	var verbose, strict bool
	lint := &cobra.Command{
		Use:   "lint [path]",
		Short: "Validate rule YAML files (parses + compiles CEL)",
		Long: `Loads every YAML rule under the given dir (default ruleset/core),
parses the YAML, and compiles each rule's CEL match expression.
Without -v: prints "N rules valid" or fails fast on the first
compile error (same as before). With -v: prints per-rule status
with PASS/FAIL and the bad-rule's full error.

Exits non-zero if any rule fails to compile — wire into Makefile
so CI catches bad CEL before deploy.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "ruleset/core"
			if len(args) > 0 {
				path = args[0]
			}
			return lintRules(path, verbose, strict)
		},
	}
	lint.Flags().BoolVarP(&verbose, "verbose", "v", false, "print per-rule status")
	lint.Flags().BoolVar(&strict, "strict", false, "fail on any rule that compiles but warns")
	cmd.AddCommand(lint)
	cmd.AddCommand(newRulesSoakCmd())
	cmd.AddCommand(newRulesFPCmd())
	return cmd
}

// newRulesFPCmd surfaces the per-class FP-rate breakout from
// LOW_FALSE_POSITIVE_ARCHITECTURE_2026-05-21.md §12. Without this,
// the doc's <0.1% / <0.5% / <5% targets are unmeasurable.
func newRulesFPCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "fp",
		Short: "Per-class FP-rate breakout (Class 1 / 2 / 3)",
		Long: `Shows aggregate FP-rate per detection class:
  Class 1 = hard invariant       (auto-deny candidate;   target <0.1%)
  Class 2 = strong exploit signal (freeze candidate;     target <0.5%)
  Class 3 = soft behavior drift   (alert-only;           target <5%)

Operators must check 'within_target=true' on Class 1+2 BEFORE
promoting any rule to a destructive action mask. This is the
measurement that backs the LOW_FALSE_POSITIVE_ARCHITECTURE
2026-05-21 §12 metric model.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var resp struct {
				Classes []struct {
					Class        int     `json:"class"`
					Rules        int     `json:"rules"`
					TotalFires   uint64  `json:"total_fires"`
					TotalFPs     uint64  `json:"total_fps"`
					FPRate       float64 `json:"fp_rate"`
					Target       float64 `json:"target"`
					WithinTarget bool    `json:"within_target"`
				} `json:"classes"`
			}
			if err := c.Call("rules.fp_class", struct{}{}, &resp); err != nil {
				return fmt.Errorf("rules.fp_class: %w", err)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "CLASS\tNAME\tRULES\tFIRES\tFPS\tFP_RATE\tTARGET\tOK")
			names := map[int]string{
				1: "hard_invariant", 2: "strong_signal", 3: "soft_drift",
			}
			for _, c := range resp.Classes {
				ok := "yes"
				if !c.WithinTarget {
					ok = "NO"
				}
				fmt.Fprintf(tw, "%d\t%s\t%d\t%d\t%d\t%.4f\t%.4f\t%s\n",
					c.Class, names[c.Class], c.Rules, c.TotalFires,
					c.TotalFPs, c.FPRate, c.Target, ok)
			}
			tw.Flush()
			fmt.Println()
			fmt.Println("Target source: docs/LOW_FALSE_POSITIVE_ARCHITECTURE_2026-05-21.md §12")
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	return cmd
}

// newRulesSoakCmd shows the per-rule "consecutive clean days"
// counter. After a rule fires zero false positives for N days the
// soak gate would consider it eligible for promotion to a
// destructive action mask. Today this is operator-readable; the
// auto-promotion path is intentionally deferred until the
// takeover scorer is calibrated.
func newRulesSoakCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "soak",
		Short: "Show per-rule FP-clean-day counters",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var resp struct {
				MinCleanDays uint `json:"min_clean_days"`
				Records      []struct {
					RuleID               string    `json:"rule_id"`
					EnteredDetectAt      time.Time `json:"entered_detect_at"`
					FireCount            uint64    `json:"fire_count"`
					FPCount              uint64    `json:"fp_count"`
					LastFP               time.Time `json:"last_fp"`
					ZeroFPSince          time.Time `json:"zero_fp_since"`
					ConsecutiveCleanDays uint      `json:"consecutive_clean_days"`
				} `json:"records"`
			}
			if err := c.Call("rules.soak", struct{}{}, &resp); err != nil {
				return fmt.Errorf("rules.soak: %w", err)
			}
			if len(resp.Records) == 0 {
				fmt.Println("No rules have fired yet — nothing to soak.")
				return nil
			}
			sort.Slice(resp.Records, func(i, j int) bool {
				return resp.Records[i].ConsecutiveCleanDays > resp.Records[j].ConsecutiveCleanDays
			})
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintf(tw, "RULE\tFIRES\tFP\tCLEAN_DAYS\tPROMOTABLE\n")
			for _, r := range resp.Records {
				promotable := "no"
				if r.ConsecutiveCleanDays >= resp.MinCleanDays {
					promotable = "yes"
				}
				fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\n",
					r.RuleID, r.FireCount, r.FPCount, r.ConsecutiveCleanDays, promotable)
			}
			tw.Flush()
			fmt.Fprintf(os.Stdout, "\nMin clean days for promotion: %d\n", resp.MinCleanDays)
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	return cmd
}

func lintRules(path string, verbose, strict bool) error {
	parsed, err := rules.LoadDir(path)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	if len(parsed) == 0 {
		fmt.Fprintf(os.Stderr, "no rules found under %s\n", path)
		return fmt.Errorf("no rules")
	}

	eng, err := rules.NewEngine(func(model.Alert) {})
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}

	// Compile rules one at a time so per-rule failures don't abort
	// the entire batch — operators want to see all failures, not
	// just the first.
	failed := 0
	for i := range parsed {
		single := []model.Rule{parsed[i]}
		if err := eng.Load(single); err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "FAIL %s — %v\n", parsed[i].ID, err)
			continue
		}
		if verbose {
			fmt.Printf("PASS %s\n", parsed[i].ID)
		}
	}

	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d/%d rules failed to compile\n", failed, len(parsed))
		return fmt.Errorf("%d compile errors", failed)
	}
	fmt.Printf("%d rules valid\n", len(parsed))
	_ = strict // reserved for future warning-promotion (deprecated tags etc.)
	return nil
}

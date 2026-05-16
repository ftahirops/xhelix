package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/config"
	"github.com/xhelix/xhelix/pkg/doctor"
)

// newDoctorCmd implements `xhelix doctor` — the security audit and
// remediation tool.
//
// Modes (selected by flags):
//
//   xhelix doctor                     audit, print text report
//   xhelix doctor --json              audit, emit JSON to stdout
//   xhelix doctor --html out.html     audit, write HTML report to file
//   xhelix doctor --apply             interactive: per-finding y/n/q to fix
//   xhelix doctor --apply --yes       non-interactive: auto-apply NON-RISKY fixes
//   xhelix doctor --category kernel   only run kernel checks
//   xhelix doctor --check kptr        only run checks whose ID contains "kptr"
//
// "Risky" fixes (PasswordAuthentication=no, mount remounts, package
// upgrades) always require explicit y/n even with --yes, because
// applying them blind can lock you out of the host or restart
// services unexpectedly.
func newDoctorCmd() *cobra.Command {
	var (
		flagJSON     bool
		flagHTML     string
		flagApply    bool
		flagYes      bool
		flagCategory string
		flagCheck    string
		flagNoColor  bool
		flagConfig   string
	)

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Audit the host for security weaknesses and (optionally) fix them",
		Long: `xhelix doctor scans the host for hardening gaps across kernel,
SSH, accounts, filesystems, firewall, MAC layer, patches, audit
subsystem, and the xhelix daemon's own configuration.

By default it produces a text report. With --apply it walks the
findings interactively and offers to apply each fix after explaining
the impact. With --yes added, non-risky fixes are applied without
prompting (risky fixes always prompt).

Risky fixes include: any SSH config change, mount remounts, package
upgrades — the kind of change that can disrupt service if applied
without operator awareness.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			// Try to load the daemon config so xhelix self-checks can run.
			// If unavailable (running on a host without xhelix installed),
			// fall back to host-only checks.
			var checks []doctor.Check
			cfg, cfgErr := config.Load(flagConfig)
			if cfgErr == nil {
				checks = doctor.AllChecks(cfg)
			} else {
				checks = doctor.HostChecks()
			}

			runner := doctor.NewRunner(checks).Filter(flagCategory, flagCheck)
			if len(runner.Checks) == 0 {
				return fmt.Errorf("no checks match category=%q check=%q", flagCategory, flagCheck)
			}

			rep := runner.Run(ctx)
			rep.Hostname, _ = os.Hostname()

			// Output mode: JSON / HTML / text.
			if flagJSON {
				return doctor.FormatJSON(os.Stdout, rep)
			}
			useColor := !flagNoColor && isTTY(os.Stdout)
			doctor.FormatText(os.Stdout, rep, useColor)

			// Interactive fix runs BEFORE writing the HTML report so
			// the HTML reflects the post-fix state — otherwise an
			// operator saving the HTML as IR evidence would have a
			// pre-fix snapshot that no longer matches reality.
			if flagApply {
				if err := interactiveFix(ctx, rep, flagYes, useColor); err != nil {
					return err
				}
				if flagHTML != "" {
					// Re-run the audit so the HTML reflects what's now
					// on disk after the fixes. The first scan is in
					// `rep`; we discard it for the HTML output and
					// generate a fresh post-fix scan.
					rep = runner.Run(ctx)
					rep.Hostname, _ = os.Hostname()
				}
			}
			if flagHTML != "" {
				f, err := os.Create(flagHTML)
				if err != nil {
					return err
				}
				defer f.Close()
				if err := doctor.FormatHTML(f, rep); err != nil {
					return err
				}
				fmt.Printf("HTML report written to %s\n", flagHTML)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&flagJSON, "json", false, "Output JSON to stdout")
	cmd.Flags().StringVar(&flagHTML, "html", "", "Also write an HTML report to this path")
	cmd.Flags().BoolVar(&flagApply, "apply", false, "Interactively apply fixes for failed checks")
	cmd.Flags().BoolVar(&flagYes, "yes", false, "Auto-apply non-risky fixes without prompting (only with --apply)")
	cmd.Flags().StringVar(&flagCategory, "category", "", "Only run checks in this category (kernel, ssh, accounts, fs, firewall, mac, patches, audit, xhelix)")
	cmd.Flags().StringVar(&flagCheck, "check", "", "Only run checks whose ID contains this substring")
	cmd.Flags().BoolVar(&flagNoColor, "no-color", false, "Disable ANSI colour")
	cmd.Flags().StringVar(&flagConfig, "config", "/etc/xhelix/xhelix.yaml", "Path to xhelix config (for self-checks)")

	return cmd
}

func interactiveFix(ctx context.Context, rep doctor.Report, autoYes, useColor bool) error {
	failed := rep.FailedFindings()
	if len(failed) == 0 {
		fmt.Println("\nNo failures to fix.")
		return nil
	}

	fmt.Printf("\n--- Apply fixes (%d findings) ---\n", len(failed))
	fmt.Println("For each finding: [y]es apply / [n]o skip / [s]kip-all-of-this-severity / [q]uit")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	skipSeverities := map[doctor.Severity]bool{}
	applied, skipped, errored := 0, 0, 0

	for i, f := range failed {
		if skipSeverities[f.Check.Severity] {
			skipped++
			continue
		}
		fmt.Printf("[%d/%d] %s/%s — %s\n", i+1, len(failed),
			strings.ToUpper(f.Check.Severity.String()), f.Check.ID, f.Check.Title)
		if f.Check.Description != "" {
			fmt.Printf("  what: %s\n", f.Check.Description)
		}
		if f.Result.Evidence != "" {
			fmt.Printf("  found: %s\n", f.Result.Evidence)
		}
		if f.Check.Impact != "" {
			fmt.Printf("  impact: %s\n", f.Check.Impact)
		}
		if f.Check.Recommendation != "" {
			fmt.Printf("  fix: %s\n", f.Check.Recommendation)
		}
		if f.Check.FixCommand != "" {
			fmt.Printf("  cmd: %s\n", f.Check.FixCommand)
		}

		if f.Check.Apply == nil {
			fmt.Printf("  (no auto-apply available — manual fix only)\n\n")
			skipped++
			continue
		}

		// Decide prompt strategy.
		auto := autoYes && !f.Check.Risky
		var resp string
		if auto {
			fmt.Printf("  --yes mode: applying (non-risky)\n")
			resp = "y"
		} else {
			tag := "y/N/s/q"
			if f.Check.Risky {
				tag = "y/N/s/q (RISKY — confirm carefully)"
			}
			fmt.Printf("  apply? [%s]: ", tag)
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			resp = strings.TrimSpace(strings.ToLower(line))
		}

		switch resp {
		case "y", "yes":
			if err := f.Check.Apply(ctx); err != nil {
				fmt.Printf("  ✗ apply failed: %v\n", err)
				errored++
			} else {
				fmt.Printf("  ✓ applied\n")
				applied++
			}
		case "s":
			skipSeverities[f.Check.Severity] = true
			fmt.Printf("  skipping all %s findings\n", f.Check.Severity)
			skipped++
		case "q", "quit":
			fmt.Println("quit.")
			fmt.Printf("\nsummary: applied=%d skipped=%d errored=%d\n",
				applied, skipped+(len(failed)-i-1), errored)
			return nil
		default:
			skipped++
		}
		fmt.Println()
	}
	fmt.Printf("summary: applied=%d skipped=%d errored=%d\n", applied, skipped, errored)
	return nil
}

// isTTY reports whether f is connected to a terminal.
func isTTY(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return (st.Mode() & os.ModeCharDevice) != 0
}

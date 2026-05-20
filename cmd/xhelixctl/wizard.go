package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/wizard"
)

func newWizardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wizard",
		Short: "Operator wizards for catalog + crown-jewel onboarding",
	}
	cmd.AddCommand(newWizardScanCmd())
	return cmd
}

func newWizardScanCmd() *cobra.Command {
	var (
		roots       []string
		maxDepth    int
		maxFindings int
		jsonOut     bool
		outFile     string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan host for crown-jewel candidates and propose catalog entries",
		Long: `Walks the local filesystem looking for assets worth declaring as
crown jewels (DB-credential files, SSH keys, backups, cloud creds, etc.)
and emits a YAML patch proposal that the operator reviews and merges
into /etc/xhelix/dlcf/catalog.yaml.

NEVER auto-applies. The whole value of the wizard is operator review.

Examples:
  xhelixctl wizard scan                      # default roots
  xhelixctl wizard scan --root /var/www      # narrow scan
  xhelixctl wizard scan --json               # machine-readable findings
  xhelixctl wizard scan -o /tmp/patch.yaml   # write proposal to file`,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := wizard.Options{
				Roots:       roots,
				MaxDepth:    maxDepth,
				MaxFindings: maxFindings,
			}
			s := wizard.New(opts)
			findings, err := s.Scan()
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}

			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{
					"stats":    s.Stats(),
					"findings": findings,
				})
			}

			yamlOut := wizard.ProposedYAML(findings)

			if outFile != "" {
				if err := os.WriteFile(outFile, []byte(yamlOut), 0o600); err != nil {
					return fmt.Errorf("write %s: %w", outFile, err)
				}
				st := s.Stats()
				fmt.Fprintf(os.Stderr,
					"Wrote proposal to %s (%d findings, %d files visited, %d skipped)\n",
					outFile, st.Findings, st.FilesVisited, st.PathsSkipped)
				return nil
			}

			// Stderr gets human-readable summary; stdout is the YAML
			// so it pipes cleanly to a file or diff tool.
			st := s.Stats()
			fmt.Fprintf(os.Stderr, "Crown-jewel scan complete.\n")
			fmt.Fprintf(os.Stderr, "  visited:  %d files\n", st.FilesVisited)
			fmt.Fprintf(os.Stderr, "  skipped:  %d paths\n", st.PathsSkipped)
			fmt.Fprintf(os.Stderr, "  findings: %d\n", st.Findings)
			if st.Findings > 0 {
				high, med, low := countByConfidence(findings)
				fmt.Fprintf(os.Stderr,
					"            (%d high, %d medium, %d low confidence)\n",
					high, med, low)
			}
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr,
				"Review the YAML below, then merge any approved entries into")
			fmt.Fprintln(os.Stderr,
				"/etc/xhelix/dlcf/catalog.yaml. The wizard does not auto-apply.")
			fmt.Fprintln(os.Stderr, strings.Repeat("─", 60))

			fmt.Print(yamlOut)
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&roots, "root", nil,
		"directories to scan (repeatable; default: /etc, /var/www, /srv, /home, /root, /opt)")
	cmd.Flags().IntVar(&maxDepth, "max-depth", 8, "max walk depth")
	cmd.Flags().IntVar(&maxFindings, "max-findings", 500, "max findings to return")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON instead of YAML proposal")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "write proposal to file instead of stdout")
	return cmd
}

func countByConfidence(fs []wizard.Finding) (high, med, low int) {
	for _, f := range fs {
		switch f.Confidence {
		case wizard.ConfidenceHigh:
			high++
		case wizard.ConfidenceMedium:
			med++
		default:
			low++
		}
	}
	return
}

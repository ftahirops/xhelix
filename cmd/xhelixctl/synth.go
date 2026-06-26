// xhelixctl synth — propose / list / export candidate behavioral profiles.
//
//	xhelixctl synth propose <app>       synthesize a candidate profile from recorder data
//	xhelixctl synth list <app>          list existing proposals for an app
//	xhelixctl synth export <app> <id>   print a proposal's DeclarationJSON to stdout
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/contractpropose"
	"github.com/xhelix/xhelix/pkg/synth"

	_ "modernc.org/sqlite"
)

func newSynthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "synth",
		Short: "Manage synthesized behavioral profile proposals (SP-4)",
	}
	cmd.AddCommand(newSynthProposeCmd())
	cmd.AddCommand(newSynthListCmd())
	cmd.AddCommand(newSynthExportCmd())
	return cmd
}

func newSynthProposeCmd() *cobra.Command {
	var dbPath, stateDir string
	var globThreshold int
	cmd := &cobra.Command{
		Use:   "propose <app>",
		Short: "Synthesize a candidate profile from recorder data and file it for review",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			appID := args[0]

			// Open recorder DB read-only (mirrors recorder.go pattern).
			if _, err := os.Stat(dbPath); err != nil {
				return fmt.Errorf("recorder db not found at %s — has the recorder ever run?", dbPath)
			}
			rec, err := openRecorderReadOnly(dbPath)
			if err != nil {
				return err
			}
			defer rec.Close()

			// Open proposal store.
			propPath := filepath.Join(stateDir, "contract-propose.db")
			store, err := contractpropose.Open(propPath)
			if err != nil {
				return fmt.Errorf("open proposal store: %w", err)
			}
			defer store.Close()

			prop, err := synth.Propose(rec, store, appID, globThreshold)
			if err != nil {
				if errors.Is(err, synth.ErrNoData) {
					fmt.Fprintf(os.Stderr, "no recorded data for %s — run the recorder first\n", appID)
					return nil
				}
				return fmt.Errorf("synth propose: %w", err)
			}
			fmt.Printf("proposal filed: id=%s app=%s\n%s\n", prop.ID, prop.App, prop.Reason)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/xhelix/recorder.db", "path to recorder.db")
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/xhelix", "xhelix state directory (contains contract-propose.db)")
	cmd.Flags().IntVar(&globThreshold, "glob-threshold", 3, "minimum path count to trigger glob generalization")
	return cmd
}

func newSynthListCmd() *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "list <app>",
		Short: "List existing proposals for an app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			appID := args[0]
			propPath := filepath.Join(stateDir, "contract-propose.db")
			store, err := contractpropose.Open(propPath)
			if err != nil {
				return fmt.Errorf("open proposal store: %w", err)
			}
			defer store.Close()

			proposals, err := store.ListForApp(appID, 100)
			if err != nil {
				return fmt.Errorf("list proposals: %w", err)
			}
			fmt.Print(renderProposalList(proposals))
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/xhelix", "xhelix state directory (contains contract-propose.db)")
	return cmd
}

func newSynthExportCmd() *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "export <app> <id>",
		Short: "Print a proposal's DeclarationJSON to stdout (pipe into signing pipeline)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			appID, id := args[0], args[1]
			propPath := filepath.Join(stateDir, "contract-propose.db")
			store, err := contractpropose.Open(propPath)
			if err != nil {
				return fmt.Errorf("open proposal store: %w", err)
			}
			defer store.Close()

			prop, ok := store.Get(appID, id)
			if !ok {
				return fmt.Errorf("proposal %s not found for app %s", id, appID)
			}
			_, err = os.Stdout.Write(prop.DeclarationJSON)
			return err
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/xhelix", "xhelix state directory (contains contract-propose.db)")
	return cmd
}

// renderProposalList formats a slice of proposals for terminal display. Pure — tested.
func renderProposalList(ps []contractpropose.Proposal) string {
	var b strings.Builder
	for _, p := range ps {
		fmt.Fprintf(&b, "%s  app=%s  status=%s  %s  %s\n",
			p.ID, p.App, p.Status, p.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), p.Reason)
	}
	if b.Len() == 0 {
		return "(no proposals)\n"
	}
	return b.String()
}

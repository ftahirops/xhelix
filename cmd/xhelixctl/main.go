// Command xhelixctl is the operator's CLI helper.
//
// Phase-0 subcommands:
//
//	xhelixctl version         print build info
//	xhelixctl events tail     stream events as JSON-lines (stub)
//	xhelixctl rules lint DIR  validate rule files (stub)
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/version"
)

func main() {
	root := &cobra.Command{
		Use:   "xhelixctl",
		Short: "Operator helper for the xhelix daemon",
	}
	root.AddCommand(newVersionCmd())
	root.AddCommand(newEventsCmd())
	root.AddCommand(newRulesCmd())
	root.AddCommand(newPostureCmd())
	root.AddCommand(newHistoryCmd())
	root.AddCommand(newPassportCmd())
	root.AddCommand(newWizardCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("xhelixctl %s (commit %s)\n", version.Version, version.Commit)
			return nil
		},
	}
}

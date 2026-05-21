package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newEventsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Inspect the event stream",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "tail",
		Short: "Stream events as JSON-lines (alias of 'alerts tail')",
		Long: `P-PS.25: implemented by reading the daemon's
file-sink at /var/log/xhelix/alerts.jsonl. Use 'xhelixctl alerts'
for filtering, stats, and per-id show. This command exists for
backward-compat with the original 'events tail' name.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(os.Stderr, "note: 'events tail' is an alias of 'alerts tail'")
			tail := newAlertsTailCmd()
			tail.SetArgs(args)
			return tail.Execute()
		},
	})
	return cmd
}

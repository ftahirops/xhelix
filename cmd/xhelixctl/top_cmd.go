package main

import (
	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/cmd/xhelixctl/top"
)

// newTopCmd is the entry point for the htop-style TUI.
func newTopCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "top",
		Short: "Live TUI — apps, lineages, destinations, integrity",
		Long: `xhelixctl top is an htop-style live view of the daemon's
real-time state: per-app egress rollup, lineages, top destinations,
and integrity verifier stats. Refreshes every second.

Keys:
  tab / shift-tab    cycle views
  1 2 3 4 5          jump to view (Apps / Lineages / Destinations / Alerts / Integrity)
  ↑ ↓ / j k          move cursor
  p                  pause auto-refresh
  r                  force refresh now
  ?                  toggle help
  q / esc            quit

Requires the daemon's LocalAPI to be reachable.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return top.Run(sock)
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	return cmd
}

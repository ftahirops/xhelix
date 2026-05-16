package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newEventsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Inspect the event stream",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "tail",
		Short: "Stream events as JSON-lines",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Phase 0 stub: real implementation in Phase 1 reads
			// from the daemon's hot store via a Unix socket.
			fmt.Println(`{"phase":0,"msg":"events tail not implemented yet; daemon hot-store is the source"}`)
			return nil
		},
	})
	return cmd
}

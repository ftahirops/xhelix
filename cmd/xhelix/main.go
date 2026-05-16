// Command xhelix is the runtime-security agent's main binary.
//
// Subcommands:
//
//	xhelix run [--config PATH]   start the daemon
//	xhelix tui                   attach the terminal UI
//	xhelix doctor                audit the host for security weaknesses
//	xhelix version               print build info
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/version"
)

func main() {
	root := &cobra.Command{
		Use:   "xhelix",
		Short: "Real-time Linux runtime security agent",
		Long: "xhelix observes processes, files, network, and identity events " +
			"and produces real-time security alerts. See https://xhelix.dev for docs.",
	}

	root.AddCommand(newRunCmd())
	root.AddCommand(newTUICmd())
	root.AddCommand(newDoctorCmd())
	root.AddCommand(newVersionCmd())

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
			fmt.Printf("xhelix %s (commit %s)\n", version.Version, version.Commit)
			return nil
		},
	}
}

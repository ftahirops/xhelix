package main

import (
	"context"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/version"
	"github.com/xhelix/xhelix/ui/tui"
)

func newTUICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Attach the terminal UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTUI(cmd.Context())
		},
	}
}

func runTUI(ctx context.Context) error {
	hostname, _ := os.Hostname()
	state := tui.State{
		Hostname:         hostname,
		Version:          version.Version,
		StartedAt:        time.Now(),
		HeartbeatHealthy: true, // demo state for Phase 0
	}

	p := tea.NewProgram(tui.NewModel(state),
		tea.WithAltScreen(),
		tea.WithContext(ctx),
	)

	// Phase 0 demo: push a fake heartbeat counter every second so
	// the operator sees the UI live without a running daemon.
	// Phase 1+ will replace this with a real subscription.
	go demoFeed(p)

	_, err := p.Run()
	return err
}

func demoFeed(p *tea.Program) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var n uint64
	for now := range t.C {
		n++
		p.Send(tui.SnapshotMsg{
			Hostname:         must(os.Hostname()),
			Version:          version.Version,
			StartedAt:        now.Add(-time.Duration(n) * time.Second),
			HeartbeatCount:   n,
			HeartbeatHealthy: true,
			HeartbeatLast:    now,
		})
	}
}

func must(s string, _ error) string { return s }

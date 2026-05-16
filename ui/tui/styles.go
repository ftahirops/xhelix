// Package tui implements the agent's terminal user interface.
package tui

import "github.com/charmbracelet/lipgloss"

// palette holds the foreground colours used across the UI.
var palette = struct {
	Border    lipgloss.Color
	Title     lipgloss.Color
	Muted     lipgloss.Color
	Info      lipgloss.Color
	Notice    lipgloss.Color
	Warn      lipgloss.Color
	High      lipgloss.Color
	Critical  lipgloss.Color
	Healthy   lipgloss.Color
	Disabled  lipgloss.Color
}{
	Border:   lipgloss.Color("#6272a4"),
	Title:    lipgloss.Color("#bd93f9"),
	Muted:    lipgloss.Color("#6272a4"),
	Info:     lipgloss.Color("#8be9fd"),
	Notice:   lipgloss.Color("#50fa7b"),
	Warn:     lipgloss.Color("#f1fa8c"),
	High:     lipgloss.Color("#ffb86c"),
	Critical: lipgloss.Color("#ff5555"),
	Healthy:  lipgloss.Color("#50fa7b"),
	Disabled: lipgloss.Color("#44475a"),
}

var (
	titleStyle  = lipgloss.NewStyle().Foreground(palette.Title).Bold(true)
	mutedStyle  = lipgloss.NewStyle().Foreground(palette.Muted)
	healthyStyle = lipgloss.NewStyle().Foreground(palette.Healthy).Bold(true)
	disabledStyle = lipgloss.NewStyle().Foreground(palette.Disabled).Italic(true)

	boxStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(palette.Border).
		Padding(0, 1)
)

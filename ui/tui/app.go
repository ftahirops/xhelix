package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// State is the read-only snapshot the UI displays.
//
// Producers update it via the Snapshot channel; consumers should
// never mutate it directly.
type State struct {
	Hostname        string
	Version         string
	StartedAt       time.Time
	HeartbeatCount  uint64
	HeartbeatHealthy bool
	HeartbeatLast   time.Time
}

// SnapshotMsg is sent on the Bubble Tea event loop with a fresh state.
type SnapshotMsg State

// tickMsg is the periodic redraw trigger.
type tickMsg time.Time

// Model wraps the State plus terminal size for layout.
type Model struct {
	state  State
	width  int
	height int
}

// NewModel returns a Model seeded with state.
func NewModel(state State) Model {
	return Model{state: state}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return tick()
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.KeyMsg:
		switch v.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width, m.height = v.Width, v.Height
	case SnapshotMsg:
		m.state = State(v)
	case tickMsg:
		return m, tick()
	}
	return m, nil
}

// View implements tea.Model.
func (m Model) View() string {
	if m.width == 0 {
		// Initial render before WindowSizeMsg arrives.
		m.width = 80
	}
	uptime := "00:00:00"
	if !m.state.StartedAt.IsZero() {
		d := time.Since(m.state.StartedAt).Truncate(time.Second)
		uptime = formatDuration(d)
	}

	header := titleStyle.Render(fmt.Sprintf("xhelix %s", m.state.Version)) +
		mutedStyle.Render(fmt.Sprintf("  host=%s  uptime=%s", m.state.Hostname, uptime))

	hbStatus := healthyStyle.Render("healthy")
	if !m.state.HeartbeatHealthy {
		hbStatus = disabledStyle.Render("stopped")
	}

	sensors := []string{
		fmt.Sprintf("%-12s %s  events=%d", "heartbeat", hbStatus, m.state.HeartbeatCount),
		fmt.Sprintf("%-12s %s", "ebpf", disabledStyle.Render("[disabled - phase 1]")),
		fmt.Sprintf("%-12s %s", "fim", disabledStyle.Render("[disabled - phase 2]")),
		fmt.Sprintf("%-12s %s", "decoys", disabledStyle.Render("[disabled - phase 3]")),
		fmt.Sprintf("%-12s %s", "netids", disabledStyle.Render("[disabled - phase 4]")),
		fmt.Sprintf("%-12s %s", "identity", disabledStyle.Render("[disabled - phase 5]")),
		fmt.Sprintf("%-12s %s", "memory", disabledStyle.Render("[disabled - phase 6]")),
	}
	sensorPanel := boxStyle.Width(m.boxWidth()).Render(
		titleStyle.Render("Sensors") + "\n" + strings.Join(sensors, "\n"),
	)

	footer := mutedStyle.Render("  q quit  /  search   ?  help")

	return lipgloss.JoinVertical(lipgloss.Left, header, "", sensorPanel, "", footer)
}

func (m Model) boxWidth() int {
	if m.width <= 4 {
		return 60
	}
	return m.width - 4
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

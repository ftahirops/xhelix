// Package top is the htop-style live TUI for xhelix. Pulls from the
// daemon's LocalAPI on a 1-second tick and renders a color-coded
// view of running lineages, per-app rollups, top destinations, and
// recent alerts.
//
// Keys (v1 — task 26 of the TUI roadmap):
//
//	tab      cycle view: apps → lineages → dests → alerts
//	q / esc  quit
//	p        pause refresh
//	r        force refresh
//	↑ ↓      navigate the table
//	enter    drill (lineages view → process tree; not yet wired)
//	?        help overlay
//
// Design rule: every render must be reactive. The daemon does the
// work; the TUI is purely presentational. If a panel can't talk to
// LocalAPI, it shows the error in place — no silent blanks.
package top

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/xhelix/xhelix/pkg/localapi"
)

// ─── Styles ────────────────────────────────────────────────────────

var (
	styleHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("63")).
			Padding(0, 1)
	styleFooter = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Padding(0, 1)
	styleSelected = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("236"))
	styleGreen    = lipgloss.NewStyle().Foreground(lipgloss.Color("76"))
	styleYellow   = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	styleRed      = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("242"))
	styleTabActive = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("231")).
				Background(lipgloss.Color("63")).
				Padding(0, 2)
	styleTabIdle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Padding(0, 2)
)

// ─── View modes ────────────────────────────────────────────────────

type viewMode int

const (
	viewApps viewMode = iota
	viewLineages
	viewDests
	viewAlerts
	viewIntegrity
)

func (v viewMode) Name() string {
	switch v {
	case viewApps:
		return "Apps"
	case viewLineages:
		return "Lineages"
	case viewDests:
		return "Destinations"
	case viewAlerts:
		return "Alerts"
	case viewIntegrity:
		return "Integrity"
	}
	return "?"
}

var allViews = []viewMode{viewApps, viewLineages, viewDests, viewAlerts, viewIntegrity}

// ─── Per-view data ─────────────────────────────────────────────────

type appRow struct {
	App         string
	Connects    int
	BytesOut    uint64
	Unique      int
	Unknown     int
	Suspicion   int // 0=green, 1=yellow, 2=red
}

type lineageRow struct {
	Lineage  uint64
	App      string
	Connects int
	Unique   int
	Unknown  int
	IntelBad int
	BytesOut uint64
}

type destRow struct {
	IP       string
	BytesOut uint64
	BytesIn  uint64
}

type integrityRow struct {
	Mode             string
	TotalRows        int
	BaselineMatched  uint64
	HashMismatched   uint64
	TOFUAccepted     uint64
	UpgradeRecovers  uint64
	Errors           uint64
}

// ─── Model ─────────────────────────────────────────────────────────

// alertRow is one row in the Alerts table.
type alertRow struct {
	Time     time.Time
	Severity string
	RuleID   string
	Reason   string
	PID      uint32
	Comm     string
	Image    string
	Tags     map[string]string
}

// Model implements tea.Model.
type Model struct {
	sock string

	view     viewMode
	width    int
	height   int
	cursor   int
	paused   bool
	tickN    int
	lastErr  string
	help     bool

	// Drilldown overlay state: when non-nil, render takes over the
	// screen and shows detail for the selected row.
	drilldown *drilldownState

	apps      []appRow
	lineages  []lineageRow
	dests     []destRow
	alerts    []alertRow
	integrity integrityRow

	// Connect on first refresh; reused across ticks.
	client *localapi.Client
}

// drilldownState captures the kind + selection of the open detail
// overlay. `data` is filled in by the async fetch.
type drilldownState struct {
	kind   string // "lineage" | "dest" | "alert" | "app"
	key    string // lineage id (decimal) / IP / alert index / app name
	loaded bool
	data   map[string]any
	err    string
}

// New constructs an initialised Model.
func New(sock string) Model {
	return Model{sock: sock, view: viewApps}
}

// tickMsg fires every refresh interval.
type tickMsg time.Time

// dataMsg carries refreshed data for a view.
type dataMsg struct {
	apps      []appRow
	lineages  []lineageRow
	dests     []destRow
	alerts    []alertRow
	integrity integrityRow
	err       string
}

// drilldownMsg carries the loaded detail payload.
type drilldownMsg struct {
	kind string
	key  string
	data map[string]any
	err  string
}

const refreshInterval = time.Second

// Init is the bubbletea entry point.
func (m Model) Init() tea.Cmd {
	return tea.Batch(m.refreshCmd(), tickCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(refreshInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// refreshCmd fires a non-blocking data fetch. The fetch runs on a
// goroutine so the UI never stalls on a slow LocalAPI.
func (m Model) refreshCmd() tea.Cmd {
	sock := m.sock
	return func() tea.Msg {
		c, err := localapi.Dial(sock)
		if err != nil {
			return dataMsg{err: "dial daemon: " + err.Error()}
		}
		defer c.Close()
		msg := dataMsg{}

		// apps
		var ar struct {
			Enabled  bool `json:"enabled"`
			Lineages []struct {
				Lineage uint64 `json:"lineage"`
			} `json:"lineages"`
		}
		// Try the analytics endpoint (latest snapshot per lineage,
		// grouped by app). It's serialised on the daemon side from
		// the running observer state. We use egress.observe for live
		// lineages and assemble app rollup client-side.
		var obsResp struct {
			Enabled  bool `json:"enabled"`
			Lineages []struct {
				Lineage        uint64            `json:"lineage"`
				TotalConnects  int               `json:"total_connects"`
				ByClass        map[string]int    `json:"by_class"`
				UniqueDests    int               `json:"unique_dests"`
				UniqueUnknown  int               `json:"unique_unknown"`
				LastConnect    time.Time         `json:"last_connect"`
				FirstIntelBad  time.Time         `json:"first_intel_bad"`
			} `json:"lineages"`
		}
		_ = ar
		_ = c.Call("egress.observe", struct{}{}, &obsResp)
		// Lineages view
		for _, lg := range obsResp.Lineages {
			intelBad := lg.ByClass["intel_bad"]
			msg.lineages = append(msg.lineages, lineageRow{
				Lineage:  lg.Lineage,
				Connects: lg.TotalConnects,
				Unique:   lg.UniqueDests,
				Unknown:  lg.UniqueUnknown,
				IntelBad: intelBad,
			})
		}

		// dests view via top-ips
		var topResp struct {
			Enabled bool `json:"enabled"`
			Top     []struct {
				IP       string `json:"ip"`
				BytesOut uint64 `json:"bytes_out"`
				BytesIn  uint64 `json:"bytes_in"`
			} `json:"top"`
		}
		_ = c.Call("egress.top_ips", map[string]any{"hours": 1, "top": 50}, &topResp)
		for _, r := range topResp.Top {
			msg.dests = append(msg.dests, destRow{IP: r.IP, BytesOut: r.BytesOut, BytesIn: r.BytesIn})
		}

		// Alerts view
		var alertsResp struct {
			Alerts []struct {
				Time     int64             `json:"time"`
				Severity string            `json:"severity"`
				RuleID   string            `json:"rule_id"`
				Reason   string            `json:"reason"`
				PID      uint32            `json:"pid"`
				Comm     string            `json:"comm"`
				Image    string            `json:"image"`
				Tags     map[string]string `json:"tags"`
			} `json:"alerts"`
		}
		_ = c.Call("tui.alerts_recent", map[string]any{"limit": 200}, &alertsResp)
		for _, a := range alertsResp.Alerts {
			msg.alerts = append(msg.alerts, alertRow{
				Time:     time.Unix(a.Time, 0).UTC(),
				Severity: a.Severity,
				RuleID:   a.RuleID,
				Reason:   a.Reason,
				PID:      a.PID,
				Comm:     a.Comm,
				Image:    a.Image,
				Tags:     a.Tags,
			})
		}

		// Integrity view
		var iResp struct {
			Enabled      bool   `json:"enabled"`
			Mode         string `json:"mode"`
			TotalRows    int    `json:"total_rows"`
			VerifierStat struct {
				BaselineMatched uint64 `json:"baseline_matched"`
				HashMismatched  uint64 `json:"hash_mismatched"`
				TOFUAccepted    uint64 `json:"tofu_accepted"`
				UpgradeRecovers uint64 `json:"upgrade_recovers"`
				Errors          uint64 `json:"errors"`
			} `json:"verifier"`
		}
		_ = c.Call("integrity.status", struct{}{}, &iResp)
		msg.integrity = integrityRow{
			Mode:            iResp.Mode,
			TotalRows:       iResp.TotalRows,
			BaselineMatched: iResp.VerifierStat.BaselineMatched,
			HashMismatched:  iResp.VerifierStat.HashMismatched,
			TOFUAccepted:    iResp.VerifierStat.TOFUAccepted,
			UpgradeRecovers: iResp.VerifierStat.UpgradeRecovers,
			Errors:          iResp.VerifierStat.Errors,
		}

		// Apps view: read today's rollup file directly (cheap, no
		// new LocalAPI). We aggregate the latest snapshot per lineage.
		apps, errStr := loadAppsFromRollup()
		msg.apps = apps
		if errStr != "" && len(msg.lineages) == 0 {
			msg.err = errStr
		}
		return msg
	}
}

// Update handles incoming messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			i := 0
			for k, v := range allViews {
				if v == m.view {
					i = (k + 1) % len(allViews)
					break
				}
			}
			m.view = allViews[i]
			m.cursor = 0
			return m, nil
		case "shift+tab":
			i := 0
			for k, v := range allViews {
				if v == m.view {
					i = (k - 1 + len(allViews)) % len(allViews)
					break
				}
			}
			m.view = allViews[i]
			m.cursor = 0
			return m, nil
		case "p":
			m.paused = !m.paused
			return m, nil
		case "r":
			return m, m.refreshCmd()
		case "?":
			m.help = !m.help
			return m, nil
		case "down", "j":
			m.cursor++
			return m, nil
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "g", "home":
			m.cursor = 0
			return m, nil
		case "1":
			m.view = viewApps
			return m, nil
		case "2":
			m.view = viewLineages
			return m, nil
		case "3":
			m.view = viewDests
			return m, nil
		case "4":
			m.view = viewAlerts
			return m, nil
		case "5":
			m.view = viewIntegrity
			return m, nil
		case "enter":
			return m, m.openDrilldown()
		case "esc":
			if m.drilldown != nil {
				m.drilldown = nil
				return m, nil
			}
			return m, tea.Quit
		}
	case tickMsg:
		m.tickN++
		if m.paused {
			return m, tickCmd()
		}
		return m, tea.Batch(m.refreshCmd(), tickCmd())
	case dataMsg:
		m.lastErr = msg.err
		if len(msg.apps) > 0 {
			m.apps = msg.apps
		}
		if len(msg.lineages) > 0 {
			m.lineages = msg.lineages
		}
		if len(msg.dests) > 0 {
			m.dests = msg.dests
		}
		if len(msg.alerts) > 0 {
			m.alerts = msg.alerts
		}
		if msg.integrity.Mode != "" {
			m.integrity = msg.integrity
		}
		return m, nil
	case drilldownMsg:
		if m.drilldown != nil && m.drilldown.kind == msg.kind && m.drilldown.key == msg.key {
			m.drilldown.loaded = true
			m.drilldown.data = msg.data
			m.drilldown.err = msg.err
		}
		return m, nil
	}
	return m, nil
}

// openDrilldown opens the detail overlay for the currently-selected row.
func (m *Model) openDrilldown() tea.Cmd {
	switch m.view {
	case viewLineages:
		if m.cursor >= 0 && m.cursor < len(m.lineages) {
			l := m.lineages[m.cursor]
			m.drilldown = &drilldownState{kind: "lineage", key: fmt.Sprintf("%d", l.Lineage)}
			return m.fetchLineageDetail(l.Lineage)
		}
	case viewDests:
		if m.cursor >= 0 && m.cursor < len(m.dests) {
			d := m.dests[m.cursor]
			m.drilldown = &drilldownState{kind: "dest", key: d.IP}
			return m.fetchDestDetail(d.IP)
		}
	case viewAlerts:
		if m.cursor >= 0 && m.cursor < len(m.alerts) {
			m.drilldown = &drilldownState{kind: "alert", key: fmt.Sprintf("%d", m.cursor)}
			return m.fetchAlertDetail(m.cursor)
		}
	case viewApps:
		if m.cursor >= 0 && m.cursor < len(m.apps) {
			a := m.apps[m.cursor]
			m.drilldown = &drilldownState{kind: "app", key: a.App, loaded: true,
				data: map[string]any{"app": a.App, "connects": a.Connects, "bytes_out": a.BytesOut,
					"unique": a.Unique, "unknown": a.Unknown}}
		}
	}
	return nil
}

func (m Model) fetchLineageDetail(lid uint64) tea.Cmd {
	sock := m.sock
	return func() tea.Msg {
		c, err := localapi.Dial(sock)
		if err != nil {
			return drilldownMsg{kind: "lineage", key: fmt.Sprintf("%d", lid), err: err.Error()}
		}
		defer c.Close()
		var resp map[string]any
		if err := c.Call("tui.lineage_detail", map[string]any{"lineage": lid}, &resp); err != nil {
			return drilldownMsg{kind: "lineage", key: fmt.Sprintf("%d", lid), err: err.Error()}
		}
		return drilldownMsg{kind: "lineage", key: fmt.Sprintf("%d", lid), data: resp}
	}
}

func (m Model) fetchDestDetail(ip string) tea.Cmd {
	sock := m.sock
	return func() tea.Msg {
		c, err := localapi.Dial(sock)
		if err != nil {
			return drilldownMsg{kind: "dest", key: ip, err: err.Error()}
		}
		defer c.Close()
		var resp map[string]any
		if err := c.Call("tui.dest_detail", map[string]any{"ip": ip, "hours": 24}, &resp); err != nil {
			return drilldownMsg{kind: "dest", key: ip, err: err.Error()}
		}
		return drilldownMsg{kind: "dest", key: ip, data: resp}
	}
}

func (m Model) fetchAlertDetail(idx int) tea.Cmd {
	sock := m.sock
	return func() tea.Msg {
		c, err := localapi.Dial(sock)
		if err != nil {
			return drilldownMsg{kind: "alert", key: fmt.Sprintf("%d", idx), err: err.Error()}
		}
		defer c.Close()
		var resp map[string]any
		if err := c.Call("tui.alert_detail", map[string]any{"index": idx}, &resp); err != nil {
			return drilldownMsg{kind: "alert", key: fmt.Sprintf("%d", idx), err: err.Error()}
		}
		return drilldownMsg{kind: "alert", key: fmt.Sprintf("%d", idx), data: resp}
	}
}

// View renders the screen.
func (m Model) View() string {
	if m.help {
		return m.renderHelp()
	}
	if m.drilldown != nil {
		return m.renderDrilldown()
	}
	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteString("\n")
	b.WriteString(m.renderTabs())
	b.WriteString("\n\n")
	switch m.view {
	case viewApps:
		b.WriteString(m.renderApps())
	case viewLineages:
		b.WriteString(m.renderLineages())
	case viewDests:
		b.WriteString(m.renderDests())
	case viewAlerts:
		b.WriteString(m.renderAlerts())
	case viewIntegrity:
		b.WriteString(m.renderIntegrity())
	}
	b.WriteString("\n")
	b.WriteString(m.renderFooter())
	return b.String()
}

// renderDrilldown renders the detail overlay for whichever row the
// user pressed Enter on. esc returns to the list.
func (m Model) renderDrilldown() string {
	d := m.drilldown
	var b strings.Builder
	header := fmt.Sprintf("xhelix top — %s detail — esc to return", d.kind)
	pad := m.width - len(header) - 2
	if pad < 1 {
		pad = 1
	}
	b.WriteString(styleHeader.Render(header + strings.Repeat(" ", pad)))
	b.WriteString("\n\n")
	if d.err != "" {
		b.WriteString(styleRed.Render("error: " + d.err))
		return b.String()
	}
	if !d.loaded {
		b.WriteString(styleDim.Render("loading…"))
		return b.String()
	}
	switch d.kind {
	case "lineage":
		b.WriteString(m.renderLineageDetail(d.data))
	case "dest":
		b.WriteString(m.renderDestDetail(d.data))
	case "alert":
		b.WriteString(m.renderAlertDetail(d.data))
	case "app":
		b.WriteString(m.renderAppDetail(d.data))
	}
	return b.String()
}

func (m Model) renderLineageDetail(d map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  lineage:         %v\n", d["lineage"])
	fmt.Fprintf(&b, "  app:             %v  (kind=%v)\n", d["app_id"], d["app_kind"])
	fmt.Fprintf(&b, "  total_connects:  %v\n", d["total_connects"])
	fmt.Fprintf(&b, "  total_bytes_out: %v\n", humanBytesAny(d["total_bytes_out"]))
	fmt.Fprintf(&b, "  unique_dests:    %v  unique_unknown: %v\n", d["unique_dests"], d["unique_unknown"])
	if ts, ok := d["first_unknown_at"].(float64); ok && ts > 0 {
		fmt.Fprintf(&b, "  first_unknown_at: %s\n", time.Unix(int64(ts), 0).UTC().Format(time.RFC3339))
	}
	if ts, ok := d["first_intel_bad"].(float64); ok && ts > 0 {
		fmt.Fprintf(&b, "  first_intel_bad:  %s\n", styleRed.Render(time.Unix(int64(ts), 0).UTC().Format(time.RFC3339)))
	}
	b.WriteString("\n")
	b.WriteString(styleHeader.Render(" class breakdown "))
	b.WriteString("\n")
	if bc, ok := d["by_class"].(map[string]any); ok {
		for k, v := range bc {
			fmt.Fprintf(&b, "  %-15s %d\n", k, intOf(v))
		}
	}
	b.WriteString("\n")
	b.WriteString(styleHeader.Render(" top destinations (bytes out) "))
	b.WriteString("\n")
	if dests, ok := d["top_dests"].([]any); ok {
		for _, di := range dests {
			row, _ := di.(map[string]any)
			fmt.Fprintf(&b, "  %-30s %s\n", row["dest"], humanBytesAny(row["bytes_out"]))
		}
	}
	b.WriteString("\n")
	b.WriteString(styleHeader.Render(" recent observations "))
	b.WriteString("\n")
	if sample, ok := d["recent_sample"].([]any); ok {
		// Show last 25.
		start := 0
		if len(sample) > 25 {
			start = len(sample) - 25
		}
		for _, s := range sample[start:] {
			row, _ := s.(map[string]any)
			ts := time.Unix(int64Of(row["at"]), 0).UTC().Format("15:04:05")
			cls := fmt.Sprintf("%v", row["class"])
			fmt.Fprintf(&b, "  %s  %-15s :%-5v %-10s %s\n",
				ts, row["ip"], row["port"], cls, strOf(row["sni"]))
		}
	}
	return b.String()
}

func (m Model) renderDestDetail(d map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  ip:        %v\n", d["ip"])
	if bad, ok := d["intel_bad"].(bool); ok && bad {
		fmt.Fprintf(&b, "  intel:     %s\n", styleRed.Render("BAD (threat-intel hit)"))
	} else {
		fmt.Fprintf(&b, "  intel:     %s\n", styleDim.Render("clean (no threat-intel match)"))
	}
	b.WriteString("\n")
	b.WriteString(styleHeader.Render(" talkers (lineages that have sent bytes to this IP) "))
	b.WriteString("\n")
	if t, ok := d["talkers"].([]any); ok && len(t) > 0 {
		for _, ti := range t {
			row, _ := ti.(map[string]any)
			app := strOf(row["app_id"])
			if app == "" {
				app = "(unidentified)"
			}
			fmt.Fprintf(&b, "  lineage=%v  app=%-30s  bytes_out=%s\n",
				row["lineage"], app, humanBytesAny(row["bytes_out"]))
		}
	} else {
		b.WriteString(styleDim.Render("  (no talkers recorded)"))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(styleHeader.Render(" bytes-in/out timeline (1h) "))
	b.WriteString("\n")
	if pts, ok := d["points"].([]any); ok && len(pts) > 0 {
		var maxV uint64
		outs := make([]uint64, len(pts))
		ins := make([]uint64, len(pts))
		for i, p := range pts {
			row, _ := p.(map[string]any)
			outs[i] = uint64(int64Of(row["bytes_out"]))
			ins[i] = uint64(int64Of(row["bytes_in"]))
			if outs[i] > maxV {
				maxV = outs[i]
			}
			if ins[i] > maxV {
				maxV = ins[i]
			}
		}
		fmt.Fprintf(&b, "  out  %s\n", sparkLine(outs, maxV))
		fmt.Fprintf(&b, "  in   %s\n", sparkLine(ins, maxV))
		fmt.Fprintf(&b, "       peak=%s   buckets=%d\n", humanBytes(maxV), len(pts))
	} else {
		b.WriteString(styleDim.Render("  (no timeseries data)"))
		b.WriteString("\n")
	}
	return b.String()
}

func (m Model) renderAlertDetail(d map[string]any) string {
	var b strings.Builder
	sev := strOf(d["severity"])
	rule := strOf(d["rule_id"])
	fmt.Fprintf(&b, "  %s  %s\n", colorSeverity(sev), styleHeader.Render(" "+rule+" "))
	fmt.Fprintf(&b, "  time:     %s\n", time.Unix(int64Of(d["time"]), 0).UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "  sensor:   %v\n", d["sensor"])
	fmt.Fprintf(&b, "  pid:      %v   comm:    %v\n", d["pid"], d["comm"])
	fmt.Fprintf(&b, "  image:    %v\n", d["image"])
	if act := strOf(d["action"]); act != "" {
		fmt.Fprintf(&b, "  action:   %v\n", act)
	}
	fmt.Fprintf(&b, "\n  reason:\n    %s\n\n", strOf(d["reason"]))
	if chain, ok := d["chain"].([]any); ok && len(chain) > 0 {
		b.WriteString(styleHeader.Render(" causal chain (most-recent → root) "))
		b.WriteString("\n")
		for i, n := range chain {
			row, _ := n.(map[string]any)
			arrow := "└─"
			if i == 0 {
				arrow = "* "
			}
			argv := ""
			if av, ok := row["argv"].([]any); ok && len(av) > 0 {
				argv = "  argv=[" + joinAny(av) + "]"
			}
			fmt.Fprintf(&b, "  %s pid=%v uid=%v comm=%v image=%v%s\n",
				arrow, row["pid"], row["uid"], row["comm"], row["image"], argv)
		}
		b.WriteString("\n")
	}
	if tags, ok := d["all_tags"].(map[string]any); ok && len(tags) > 0 {
		b.WriteString(styleHeader.Render(" event tags "))
		b.WriteString("\n")
		keys := make([]string, 0, len(tags))
		for k := range tags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := fmt.Sprintf("%v", tags[k])
			if len(v) > 200 {
				v = v[:200] + "…"
			}
			fmt.Fprintf(&b, "  %-22s = %s\n", k, v)
		}
	}
	return b.String()
}

func (m Model) renderAppDetail(d map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  app:           %v\n", d["app"])
	fmt.Fprintf(&b, "  connects:      %v\n", d["connects"])
	fmt.Fprintf(&b, "  bytes_out:     %s\n", humanBytesAny(d["bytes_out"]))
	fmt.Fprintf(&b, "  unique_dests:  %v\n", d["unique"])
	fmt.Fprintf(&b, "  unique_unknown: %v\n", d["unknown"])
	b.WriteString("\n")
	b.WriteString(styleDim.Render("  (Tip: switch to view 2 (Lineages) and Enter on a row\n   that matches this app for full process + destination detail.)"))
	return b.String()
}

func (m Model) renderAlerts() string {
	if len(m.alerts) == 0 {
		return styleDim.Render("(no alerts in ring — daemon may be quiet, or alerts predate this session)")
	}
	headers := []string{"TIME", "SEV", "RULE", "PID", "COMM", "REASON"}
	rows := [][]string{}
	for _, a := range m.alerts {
		reason := a.Reason
		if len(reason) > 60 {
			reason = reason[:60] + "…"
		}
		rows = append(rows, []string{
			a.Time.Format("15:04:05"),
			colorSeverity(a.Severity),
			a.RuleID,
			fmt.Sprintf("%d", a.PID),
			a.Comm,
			reason,
		})
	}
	return renderTable(headers, rows, m.cursor)
}

func colorSeverity(sev string) string {
	switch sev {
	case "critical":
		return styleRed.Render("CRIT ")
	case "high":
		return styleRed.Render("HIGH ")
	case "warn":
		return styleYellow.Render("WARN ")
	case "notice":
		return styleDim.Render("notice")
	}
	return styleDim.Render(sev)
}

func sparkLine(vals []uint64, max uint64) string {
	if max == 0 {
		return strings.Repeat(" ", len(vals))
	}
	runes := []rune("▁▂▃▄▅▆▇█")
	out := make([]rune, len(vals))
	for i, v := range vals {
		if v == 0 {
			out[i] = ' '
			continue
		}
		idx := int(float64(v) / float64(max) * float64(len(runes)-1))
		if idx >= len(runes) {
			idx = len(runes) - 1
		}
		out[i] = runes[idx]
	}
	return string(out)
}

func humanBytesAny(v any) string {
	switch n := v.(type) {
	case float64:
		return humanBytes(uint64(n))
	case int64:
		return humanBytes(uint64(n))
	case int:
		return humanBytes(uint64(n))
	case uint64:
		return humanBytes(n)
	}
	return fmt.Sprintf("%v", v)
}

func intOf(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}

func int64Of(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int:
		return int64(n)
	case int64:
		return n
	}
	return 0
}

func strOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func joinAny(v []any) string {
	parts := make([]string, 0, len(v))
	for _, x := range v {
		parts = append(parts, fmt.Sprintf("%v", x))
	}
	out := strings.Join(parts, " ")
	if len(out) > 120 {
		out = out[:120] + "…"
	}
	return out
}

func (m Model) renderHeader() string {
	status := "live"
	if m.paused {
		status = "paused"
	}
	right := fmt.Sprintf("tick=%d  status=%s", m.tickN, status)
	if m.lastErr != "" {
		right = "ERR: " + m.lastErr
	}
	left := "xhelix top"
	pad := m.width - len(left) - len(right) - 2
	if pad < 1 {
		pad = 1
	}
	return styleHeader.Render(left + strings.Repeat(" ", pad) + right)
}

func (m Model) renderTabs() string {
	var parts []string
	for i, v := range allViews {
		label := fmt.Sprintf(" %d %s ", i+1, v.Name())
		if v == m.view {
			parts = append(parts, styleTabActive.Render(label))
		} else {
			parts = append(parts, styleTabIdle.Render(label))
		}
	}
	return strings.Join(parts, "")
}

func (m Model) renderApps() string {
	if len(m.apps) == 0 {
		return styleDim.Render("(no app data — rollup file empty or daemon not running)")
	}
	headers := []string{"  ", "APP", "CONNECTS", "BYTES_OUT", "UNIQUE", "UNKNOWN"}
	rows := [][]string{}
	for _, a := range m.apps {
		mark := dot(a.Suspicion)
		rows = append(rows, []string{
			mark, a.App, fmt.Sprintf("%d", a.Connects), humanBytes(a.BytesOut),
			fmt.Sprintf("%d", a.Unique), fmt.Sprintf("%d", a.Unknown),
		})
	}
	return renderTable(headers, rows, m.cursor)
}

func (m Model) renderLineages() string {
	if len(m.lineages) == 0 {
		return styleDim.Render("(no lineage data — egress.observe disabled?)")
	}
	headers := []string{"  ", "LINEAGE", "CONNECTS", "UNIQUE", "UNKNOWN", "INTEL_BAD"}
	rows := [][]string{}
	for _, l := range m.lineages {
		sus := 0
		if l.IntelBad > 0 || l.Unknown >= 10 {
			sus = 2
		} else if l.Unknown >= 3 {
			sus = 1
		}
		ib := fmt.Sprintf("%d", l.IntelBad)
		if l.IntelBad > 0 {
			ib = styleRed.Render("!" + ib)
		}
		rows = append(rows, []string{
			dot(sus),
			fmt.Sprintf("%d", l.Lineage),
			fmt.Sprintf("%d", l.Connects),
			fmt.Sprintf("%d", l.Unique),
			fmt.Sprintf("%d", l.Unknown),
			ib,
		})
	}
	return renderTable(headers, rows, m.cursor)
}

func (m Model) renderDests() string {
	if len(m.dests) == 0 {
		return styleDim.Render("(no destination data)")
	}
	headers := []string{"IP", "BYTES_OUT", "BYTES_IN", "TOTAL"}
	rows := [][]string{}
	for _, d := range m.dests {
		rows = append(rows, []string{
			d.IP, humanBytes(d.BytesOut), humanBytes(d.BytesIn),
			humanBytes(d.BytesOut + d.BytesIn),
		})
	}
	return renderTable(headers, rows, m.cursor)
}

// (renderAlerts implementation lives in the drilldown section)

func (m Model) renderIntegrity() string {
	if m.integrity.Mode == "" {
		return styleDim.Render("(integrity disabled — set integrity.enabled=true in /etc/xhelix/xhelix.yaml)")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  Mode:               %s\n", m.integrity.Mode)
	fmt.Fprintf(&b, "  Baseline rows:      %d\n", m.integrity.TotalRows)
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "  Verifier stats:\n")
	fmt.Fprintf(&b, "    baseline_matched  %d\n", m.integrity.BaselineMatched)
	mismatchStr := fmt.Sprintf("%d", m.integrity.HashMismatched)
	if m.integrity.HashMismatched > 0 {
		mismatchStr = styleRed.Render(mismatchStr + " ⚠")
	}
	fmt.Fprintf(&b, "    hash_mismatched   %s\n", mismatchStr)
	fmt.Fprintf(&b, "    tofu_accepted     %d\n", m.integrity.TOFUAccepted)
	fmt.Fprintf(&b, "    upgrade_recovers  %d\n", m.integrity.UpgradeRecovers)
	fmt.Fprintf(&b, "    errors            %d\n", m.integrity.Errors)
	return b.String()
}

func (m Model) renderFooter() string {
	keys := "  [tab] cycle  [1-5] view  [p] pause  [r] refresh  [↑↓] nav  [?] help  [q] quit"
	return styleFooter.Render(keys)
}

func (m Model) renderHelp() string {
	return styleHeader.Render("xhelix top — help") + "\n\n" +
		"  tab / shift-tab    cycle views\n" +
		"  1 2 3 4 5          jump to view (Apps / Lineages / Destinations / Alerts / Integrity)\n" +
		"  ↑ ↓ / j k          move cursor\n" +
		"  g                  jump to top\n" +
		"  p                  pause auto-refresh\n" +
		"  r                  force refresh now\n" +
		"  ?                  toggle this help\n" +
		"  q / esc            quit\n\n" +
		styleDim.Render("Refresh: 1s.  Source: LocalAPI on the running daemon.") + "\n\n" +
		styleFooter.Render("press ? again to return")
}

// ─── Table renderer ───────────────────────────────────────────────

func renderTable(headers []string, rows [][]string, cursor int) string {
	if len(rows) == 0 {
		return styleDim.Render("(no rows)")
	}
	cols := len(headers)
	widths := make([]int, cols)
	for i, h := range headers {
		widths[i] = lipgloss.Width(h)
	}
	for _, r := range rows {
		for i := 0; i < cols && i < len(r); i++ {
			if w := lipgloss.Width(r[i]); w > widths[i] {
				widths[i] = w
			}
		}
	}
	var b strings.Builder
	// header
	for i, h := range headers {
		b.WriteString(styleHeader.Render(padRight(h, widths[i])))
		if i < cols-1 {
			b.WriteString("  ")
		}
	}
	b.WriteString("\n")
	if cursor >= len(rows) {
		cursor = len(rows) - 1
	}
	for ri, r := range rows {
		var rowB strings.Builder
		for i := 0; i < cols && i < len(r); i++ {
			rowB.WriteString(padRight(r[i], widths[i]))
			if i < cols-1 {
				rowB.WriteString("  ")
			}
		}
		line := rowB.String()
		if ri == cursor {
			line = styleSelected.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func padRight(s string, w int) string {
	pad := w - lipgloss.Width(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

func dot(sus int) string {
	switch sus {
	case 2:
		return styleRed.Render("●")
	case 1:
		return styleYellow.Render("●")
	}
	return styleGreen.Render("●")
}

func humanBytes(n uint64) string {
	const k, m, g uint64 = 1024, 1024 * 1024, 1024 * 1024 * 1024
	switch {
	case n >= g:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(g))
	case n >= m:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(m))
	case n >= k:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(k))
	}
	return fmt.Sprintf("%d B", n)
}

// ─── Apps rollup loader ───────────────────────────────────────────

// loadAppsFromRollup reads /var/lib/xhelix/egress-analytics/today.jsonl
// and aggregates the latest snapshot per lineage into per-app rows.
// This is exactly what `xhelixctl egress analytics --group-by app` does
// — duplicated here so the TUI doesn't shell out.
func loadAppsFromRollup() ([]appRow, string) {
	const dir = "/var/lib/xhelix/egress-analytics"
	today := time.Now().UTC().Format("2006-01-02")
	path := dir + "/" + today + ".jsonl"
	data, err := readFileLimited(path, 64<<20)
	if err != nil {
		return nil, "rollup file unavailable: " + err.Error()
	}
	// Parse line by line; keep latest per lineage.
	type pls struct {
		At    time.Time `json:"at"`
		Stats struct {
			LineageID       uint64         `json:"LineageID"`
			AppID           string         `json:"AppID"`
			TotalConnects   int            `json:"TotalConnects"`
			ByClass         map[string]int `json:"ByClass"`
			BytesOutByClass map[string]uint64 `json:"BytesOutByClass"`
			TotalBytesOut   uint64         `json:"TotalBytesOut"`
			UniqueDests     int            `json:"UniqueDests"`
			UniqueUnknown   int            `json:"UniqueUnknown"`
		} `json:"stats"`
	}
	latest := map[uint64]pls{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		var rec pls
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		cur, ok := latest[rec.Stats.LineageID]
		if !ok || rec.At.After(cur.At) {
			latest[rec.Stats.LineageID] = rec
		}
	}
	// Aggregate per app.
	type acc struct {
		connects, unique, unknown int
		bytes                     uint64
	}
	byApp := map[string]*acc{}
	for _, rec := range latest {
		k := rec.Stats.AppID
		if k == "" {
			k = "(unidentified)"
		}
		a := byApp[k]
		if a == nil {
			a = &acc{}
			byApp[k] = a
		}
		a.connects += rec.Stats.TotalConnects
		a.bytes += rec.Stats.TotalBytesOut
		a.unique += rec.Stats.UniqueDests
		a.unknown += rec.Stats.UniqueUnknown
	}
	rows := make([]appRow, 0, len(byApp))
	for app, a := range byApp {
		sus := 0
		if isShellApp(app) && a.unknown > 0 {
			sus = 2
		} else if a.unknown >= 10 {
			sus = 2
		} else if a.unknown >= 3 || (app == "(unidentified)" && a.unknown > 0) {
			sus = 1
		}
		rows = append(rows, appRow{
			App: app, Connects: a.connects, BytesOut: a.bytes,
			Unique: a.unique, Unknown: a.unknown, Suspicion: sus,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].BytesOut > rows[j].BytesOut })
	return rows, ""
}

func isShellApp(app string) bool {
	for _, s := range []string{"bash", "sh", "zsh", "dash", "fish", "ksh"} {
		if app == s || strings.HasPrefix(app, s+":") {
			return true
		}
	}
	return false
}

// Run starts the bubbletea program. Used by xhelixctl's `top` command.
func Run(sock string) error {
	p := tea.NewProgram(New(sock), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// Enterprise-grade dashboard pages. Server-side rendered HTML,
// vanilla CSS, no JS framework. Real-time via Server-Sent Events.
//
// Design constraints:
//   - Static binary still ~10MB
//   - Memory footprint <10MB at idle, <50MB under load
//   - Sub-second page loads on 100ms RTT
//   - Works without JavaScript (graceful degradation)
//   - Tamper-evident: every action emits an audit event
//   - No external CSS/JS — single binary deploy
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// EnterpriseConfig adds the views' data sources.
type EnterpriseConfig struct {
	SessionLister SessionLister
	BansLister    BansLister
	RuleLister    RuleLister
	StatsProvider StatsProvider
	DoctorRunner  DoctorRunner
}

// SessionLister surfaces SSH sessions for the timeline view.
type SessionLister interface {
	List() []SessionView
}

// SessionView is the read-only projection the UI consumes.
type SessionView struct {
	ID       string
	User     string
	SrcIP    string
	SrcGeo   string
	Method   string
	LoginAt  time.Time
	LogoutAt time.Time
	Active   bool
	Commands []string
	Events   int
	Alerts   int
}

// BansLister surfaces active IP bans.
type BansLister interface {
	ListBans() []BanView
}

// BanView is the dashboard representation of one ban.
type BanView struct {
	IP      string
	Reason  string
	AddedAt time.Time
	Expires time.Time
}

// RuleLister surfaces rule metadata for the rules view.
type RuleLister interface {
	ListRules() []RuleView
}

// RuleView captures rule + soak status.
type RuleView struct {
	ID                   string
	Severity             string
	Mode                 string
	FireCount            uint64
	FPCount              uint64
	ConsecutiveCleanDays uint
	Promotable           bool
	Mitre                []string
	Description          string
	Muted                bool
}

// StatsProvider returns the dashboard's headline metrics.
type StatsProvider interface {
	Stats() DashboardStats
}

// DashboardStats are the headline tiles.
type DashboardStats struct {
	EventsTotal      uint64
	AlertsTotal      uint64
	AlertsCritical   uint64
	AlertsHigh       uint64
	SensorsHealthy   int
	SensorsDegraded  int
	SessionsActive   int
	BansActive       int
	RemediatedTotal  uint64
	WebhookDelivered uint64
	UptimeSeconds    int64
	FPMarkedTotal    uint64
}

// EnterprisePages adds the enterprise UI on top of the existing
// server. Call after NewServer; before Start.
func (s *Server) EnterprisePages(cfg EnterpriseConfig, mux *http.ServeMux) {
	pages := &enterprisePages{
		server:        s,
		sessionLister: cfg.SessionLister,
		bansLister:    cfg.BansLister,
		ruleLister:    cfg.RuleLister,
		statsProvider: cfg.StatsProvider,
		doctorRunner:  cfg.DoctorRunner,
		subscribers:   map[chan model.Alert]struct{}{},
		recentAlerts:  ringbuf{cap: 1000},
	}
	tpl := template.Must(template.New("ent").Funcs(funcs()).Parse(entTemplates))
	pages.tpl = tpl

	mux.HandleFunc("/ui", pages.dashboard)
	mux.HandleFunc("/ui/alerts", pages.alerts)
	mux.HandleFunc("/ui/sessions", pages.sessions)
	mux.HandleFunc("/ui/bans", pages.bans)
	mux.HandleFunc("/ui/rules", pages.rules)
	mux.HandleFunc("/ui/doctor", pages.doctor)
	mux.HandleFunc("/ui/sse", pages.sse)
	mux.HandleFunc("/ui/css", pages.css)

	s.entPages = pages
}

// EmitToUI is invoked by the daemon's dispatch loop on every alert
// so the SSE stream stays live.
func (s *Server) EmitToUI(a model.Alert) {
	if s.entPages != nil {
		s.entPages.publish(a)
	}
}

type enterprisePages struct {
	server        *Server
	tpl           *template.Template
	sessionLister SessionLister
	bansLister    BansLister
	ruleLister    RuleLister
	statsProvider StatsProvider
	doctorRunner  DoctorRunner
	doctorState   doctorState

	mu           sync.Mutex
	subscribers  map[chan model.Alert]struct{}
	recentAlerts ringbuf
}

// publish fans out an alert to every SSE subscriber and the recent
// ring. Non-blocking.
func (p *enterprisePages) publish(a model.Alert) {
	p.mu.Lock()
	p.recentAlerts.push(a)
	subs := make([]chan model.Alert, 0, len(p.subscribers))
	for ch := range p.subscribers {
		subs = append(subs, ch)
	}
	p.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- a:
		default: // slow subscriber — drop
		}
	}
}

func (p *enterprisePages) dashboard(w http.ResponseWriter, r *http.Request) {
	stats := DashboardStats{}
	if p.statsProvider != nil {
		stats = p.statsProvider.Stats()
	}
	sessions := []SessionView{}
	if p.sessionLister != nil {
		sessions = p.sessionLister.List()
		if len(sessions) > 5 {
			sessions = sessions[:5]
		}
	}
	bans := []BanView{}
	if p.bansLister != nil {
		bans = p.bansLister.ListBans()
		if len(bans) > 10 {
			bans = bans[:10]
		}
	}
	recent := p.recentAlerts.snapshot()
	if len(recent) > 10 {
		recent = recent[:10]
	}

	data := map[string]any{
		"Title":    "Dashboard",
		"Active":   "dashboard",
		"Stats":    stats,
		"Sessions": sessions,
		"Bans":     bans,
		"Alerts":   recent,
	}
	p.render(w, "dashboard", data)
}

func (p *enterprisePages) alerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := alertFilter{
		ruleID:   q.Get("rule"),
		severity: q.Get("severity"),
		host:     q.Get("host"),
		comm:     q.Get("comm"),
		srcIP:    q.Get("src"),
		limit:    parseInt(q.Get("limit"), 100),
	}
	alerts := p.recentAlerts.snapshot()
	alerts = filter.apply(alerts)

	// Aggregate stats for the filter sidebar
	rulesAgg := map[string]int{}
	sevAgg := map[string]int{}
	for _, a := range alerts {
		rulesAgg[a.RuleID]++
		sevAgg[a.Event.Severity.String()]++
	}

	data := map[string]any{
		"Title":  "Alerts",
		"Active": "alerts",
		"Alerts": alerts,
		"Filter": filter,
		"Rules":  topByCount(rulesAgg, 20),
		"Sevs":   sevAgg,
	}
	p.render(w, "alerts", data)
}

func (p *enterprisePages) sessions(w http.ResponseWriter, r *http.Request) {
	sessions := []SessionView{}
	if p.sessionLister != nil {
		sessions = p.sessionLister.List()
	}
	data := map[string]any{
		"Title":    "Sessions",
		"Active":   "sessions",
		"Sessions": sessions,
	}
	p.render(w, "sessions", data)
}

func (p *enterprisePages) bans(w http.ResponseWriter, r *http.Request) {
	bans := []BanView{}
	if p.bansLister != nil {
		bans = p.bansLister.ListBans()
	}
	data := map[string]any{
		"Title":  "Bans",
		"Active": "bans",
		"Bans":   bans,
	}
	p.render(w, "bans", data)
}

func (p *enterprisePages) rules(w http.ResponseWriter, r *http.Request) {
	rules := []RuleView{}
	if p.ruleLister != nil {
		rules = p.ruleLister.ListRules()
	}
	// Sort by severity desc, then fire count desc
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Severity != rules[j].Severity {
			return sevRank(rules[i].Severity) > sevRank(rules[j].Severity)
		}
		return rules[i].FireCount > rules[j].FireCount
	})
	data := map[string]any{
		"Title":  "Rules",
		"Active": "rules",
		"Rules":  rules,
	}
	p.render(w, "rules", data)
}

// sse streams alerts as Server-Sent Events. The browser auto-
// reconnects on disconnect.
func (p *enterprisePages) sse(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan model.Alert, 32)
	p.mu.Lock()
	p.subscribers[ch] = struct{}{}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.subscribers, ch)
		p.mu.Unlock()
		close(ch)
	}()

	// Initial backlog
	backlog := p.recentAlerts.snapshot()
	if len(backlog) > 20 {
		backlog = backlog[:20]
	}
	for _, a := range backlog {
		writeSSE(w, "alert", a)
	}
	flusher.Flush()

	ctx := r.Context()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-ch:
			writeSSE(w, "alert", a)
			flusher.Flush()
		case <-tick.C:
			fmt.Fprintf(w, ": keepalive %d\n\n", time.Now().Unix())
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, event string, payload any) {
	body, _ := json.Marshal(payload)
	fmt.Fprintf(w, "event: %s\n", event)
	fmt.Fprintf(w, "data: %s\n\n", body)
}

func (p *enterprisePages) css(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(stylesheet))
}

// renderToHTTP applies the named template into w with a layout wrapper.
func (p *enterprisePages) render(w http.ResponseWriter, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := p.tpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// =============================================================
// Helpers — filter, ringbuf, formatting
// =============================================================

type alertFilter struct {
	ruleID, severity, host, comm, srcIP string
	limit                               int
}

func (f alertFilter) apply(alerts []model.Alert) []model.Alert {
	out := make([]model.Alert, 0, len(alerts))
	for _, a := range alerts {
		if f.ruleID != "" && a.RuleID != f.ruleID {
			continue
		}
		if f.severity != "" && a.Event.Severity.String() != f.severity {
			continue
		}
		if f.host != "" && a.Event.Host != f.host {
			continue
		}
		if f.comm != "" && a.Event.Comm != f.comm {
			continue
		}
		if f.srcIP != "" {
			s := a.Event.Tags["src_ip"]
			if s == "" {
				s = a.Event.Tags["src"]
			}
			if !strings.Contains(s, f.srcIP) {
				continue
			}
		}
		out = append(out, a)
		if f.limit > 0 && len(out) >= f.limit {
			break
		}
	}
	return out
}

// ringbuf is a fixed-cap newest-first alert ring used by the SSE
// backlog and the alerts list view.
type ringbuf struct {
	mu    sync.Mutex
	cap   int
	items []model.Alert
}

func (r *ringbuf) push(a model.Alert) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cap == 0 {
		r.cap = 1000
	}
	r.items = append([]model.Alert{a}, r.items...)
	if len(r.items) > r.cap {
		r.items = r.items[:r.cap]
	}
}

func (r *ringbuf) snapshot() []model.Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]model.Alert, len(r.items))
	copy(out, r.items)
	return out
}

func parseInt(s string, def int) int {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func topByCount(m map[string]int, n int) []ruleCount {
	out := make([]ruleCount, 0, len(m))
	for k, v := range m {
		out = append(out, ruleCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

type ruleCount struct {
	Name  string
	Count int
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "warn":
		return 3
	case "notice":
		return 2
	case "info":
		return 1
	}
	return 0
}

func funcs() template.FuncMap {
	return template.FuncMap{
		"sevClass": func(s any) string {
			str := fmt.Sprintf("%v", s)
			return "sev-" + strings.ToLower(str)
		},
		"shortTime": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.UTC().Format("15:04:05")
		},
		"sinceHuman": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			d := time.Since(t).Round(time.Second)
			return d.String() + " ago"
		},
		"truncate": func(n int, s string) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "…"
		},
		"hasContent": func(s any) bool { return fmt.Sprintf("%v", s) != "" && fmt.Sprintf("%v", s) != "0" },
		"jsonPretty": func(v any) template.HTML {
			b, _ := json.MarshalIndent(v, "", "  ")
			return template.HTML(template.HTMLEscapeString(string(b)))
		},
	}
}

// _ context import marker
var _ = context.Background

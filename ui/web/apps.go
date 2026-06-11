package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// AppRegistryProvider is the interface the daemon wires to connect
// pkg/appregistry into the web layer. The web package does not import
// pkg/appregistry directly — this keeps the dependency one-directional.
type AppRegistryProvider interface {
	// List returns all declared apps.
	List() ([]AppView, error)
	// Get returns a single app, or nil if not found.
	Get(name string) (*AppView, error)
	// Create declares a new app.
	Create(req AppCreateReq) (*AppView, error)
	// SetMode changes the enforcement mode.
	SetMode(name, mode string) error
	// Delete removes an app.
	Delete(name string) error
	// Discover scans the running system for candidate services.
	Discover() ([]DiscoveredServiceView, error)
}

// AppView is the web-layer representation of an app.
type AppView struct {
	Name        string        `json:"name"`
	DisplayName string        `json:"display_name"`
	Description string        `json:"description,omitempty"`
	Mode        string        `json:"mode"`
	Services    []ServiceView `json:"services"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// ServiceView is one service within an app.
type ServiceView struct {
	Name        string `json:"name"`
	CgroupMatch string `json:"cgroup_match"`
	BinaryPath  string `json:"binary_path,omitempty"`
	ServiceType string `json:"service_type"`
	UnitName    string `json:"unit_name,omitempty"`
}

// AppCreateReq is the payload for POST /api/apps.
type AppCreateReq struct {
	Name        string        `json:"name"`
	DisplayName string        `json:"display_name"`
	Description string        `json:"description"`
	Mode        string        `json:"mode"`
	Services    []ServiceView `json:"services"`
}

// DiscoveredServiceView is a running process group surfaced by Discover().
type DiscoveredServiceView struct {
	CgroupPath  string `json:"cgroup_path"`
	UnitName    string `json:"unit_name"`
	BinaryPath  string `json:"binary_path"`
	ServiceType string `json:"service_type"`
	PIDs        []int32 `json:"pids"`
	SampleComm  string `json:"sample_comm"`
}

// AppHealthProvider supplies per-app deny/block health (P4). Wired by the
// daemon via SetAppHealth. Nil-safe — the /health endpoint returns a
// clean zero-state when unwired.
type AppHealthProvider interface {
	// AppHealth returns the deny stats for one app, or nil if no denies
	// have been recorded for it.
	AppHealth(name string) *AppHealthView
}

// AppHealthView is the per-app deny/block summary.
type AppHealthView struct {
	App         string            `json:"app"`
	Status      string            `json:"status"` // clean|active|noisy
	TotalDenies uint64            `json:"total_denies"`
	ByRule      map[string]uint64 `json:"by_rule"`
	ByBinary    map[string]uint64 `json:"by_binary"`
	FirstDeny   time.Time         `json:"first_deny,omitempty"`
	LastDeny    time.Time         `json:"last_deny,omitempty"`
	Recent      []DenyEventView   `json:"recent"`
}

// DenyEventView is one recorded deny in the recent ring.
type DenyEventView struct {
	Time       time.Time `json:"time"`
	Binary     string    `json:"binary"`
	RuleID     string    `json:"rule_id"`
	Reason     string    `json:"reason"`
	CgroupPath string    `json:"cgroup_path,omitempty"`
}

// SetAppHealth wires an AppHealthProvider into the server.
func (s *Server) SetAppHealth(p AppHealthProvider) {
	s.appHealth = p
}

// CompiledPolicyProvider supplies the compiled contract for an app (P5a)
// and the arm/disarm/restart lifecycle (P5a.2). Wired by the daemon via
// SetCompiledPolicy. Nil-safe.
type CompiledPolicyProvider interface {
	// Policy returns the cached compiled policy, or nil if none.
	Policy(name string) (*CompiledPolicyView, error)
	// Recompile re-runs the compiler and returns the fresh policy.
	Recompile(name string) (*CompiledPolicyView, error)
	// ArmStatus reports whether each service's staged profiles are armed.
	ArmStatus(name string) (*ArmStatusView, error)
	// Arm installs the systemd drop-ins (write + daemon-reload, no
	// restart). Returns an error string in the result on a gate failure
	// (e.g. sealed app without a maintenance grant).
	Arm(name string) (*ArmStatusView, error)
	// Disarm removes the drop-ins.
	Disarm(name string) (*ArmStatusView, error)
	// Restart issues try-restart for the app's services — the disruptive
	// step that applies armed policy to the live process.
	Restart(name string) error
}

// ArmStatusView is the arm lifecycle state for an app.
type ArmStatusView struct {
	App            string          `json:"app"`
	Mode           string          `json:"mode"`
	PendingRestart bool            `json:"pending_restart"`
	Services       []ArmServiceView `json:"services"`
}

// ArmServiceView is the arm state of one service.
type ArmServiceView struct {
	Unit     string `json:"unit"`
	Armed    bool   `json:"armed"`
	Seccomp  bool   `json:"seccomp"`
	AppArmor bool   `json:"apparmor"`
	Warning  string `json:"warning,omitempty"`
}

// CompiledPolicyView is the web view of a compiled contract.
type CompiledPolicyView struct {
	App         string                `json:"app"`
	Mode        string                `json:"mode"`
	Source      string                `json:"source"`
	CompiledAt  time.Time             `json:"compiled_at"`
	ShadowCount uint64                `json:"shadow_count"`
	Warnings    []string              `json:"warnings,omitempty"`
	Services    []CompiledServiceView `json:"services"`
}

// CompiledServiceView is the web view of one compiled service.
type CompiledServiceView struct {
	Unit         string   `json:"unit"`
	Kind         string   `json:"kind"`
	CgroupMatch  string   `json:"cgroup_match"`
	ExecAllow    []string `json:"exec_allow"`
	ExecDeny     []string `json:"exec_deny"`
	DenySyscalls []string `json:"deny_syscalls"`
	WriteDeny    []string `json:"write_deny"`
	SeccompText  string   `json:"seccomp_text,omitempty"`
	AppArmorText string   `json:"apparmor_text,omitempty"`
}

// SetCompiledPolicy wires a CompiledPolicyProvider into the server.
func (s *Server) SetCompiledPolicy(p CompiledPolicyProvider) {
	s.compiledPolicy = p
}

// SetAppRegistry wires an AppRegistryProvider into the server.
// All /apps/* and /api/apps/* handlers return 503 until this is called.
func (s *Server) SetAppRegistry(p AppRegistryProvider) {
	s.appRegistry = p
}

// RegisterAppRoutes mounts the app registry HTML and API routes on mux.
// Called by the daemon's enterprise UI setup after auth is in place.
func (s *Server) RegisterAppRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/apps", s.handleAppsPage)
	mux.HandleFunc("/apps/", s.handleAppSubPage)
	mux.HandleFunc("/api/apps", s.handleAPIApps)
	mux.HandleFunc("/api/apps/", s.handleAPIAppsPath)
}

// =============================================================================
// HTML pages
// =============================================================================

func (s *Server) handleAppsPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/apps" {
		http.Redirect(w, r, "/apps", http.StatusFound)
		return
	}
	p := s.appRegistry
	if p == nil {
		http.Error(w, "app registry not configured", http.StatusServiceUnavailable)
		return
	}
	apps, err := p.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(appsPageHeader))
	if len(apps) == 0 {
		w.Write([]byte(`<div class="empty"><p>No apps declared yet.</p>
<a href="/apps/new" class="btn">Discover &amp; Declare First App →</a></div>`))
	} else {
		w.Write([]byte(`<div class="cards">`))
		for _, a := range apps {
			svcCount := len(a.Services)
			svcNames := make([]string, 0, svcCount)
			for _, svc := range a.Services {
				svcNames = append(svcNames, svc.Name)
			}
			displayName := a.DisplayName
			if displayName == "" {
				displayName = a.Name
			}
			w.Write([]byte(`<div class="card"><div class="card-top">` +
				`<span class="app-name">` + htmlEscape(displayName) + `</span>` +
				`<span class="mode-badge mode-` + htmlEscape(a.Mode) + `">` + htmlEscape(a.Mode) + `</span>` +
				`</div><div class="card-body">` +
				`<span class="svc-count">` + itoa(svcCount) + ` service` + plural(svcCount) + `</span>` +
				`<span class="svc-names muted">` + htmlEscape(strings.Join(svcNames, " · ")) + `</span>` +
				`</div><div class="card-foot">` +
				`<a href="/apps/` + htmlEscape(a.Name) + `" class="btn-sm">View Details</a>` +
				`</div></div>`))
		}
		w.Write([]byte(`</div>`))
		w.Write([]byte(`<div class="actions"><a href="/apps/new" class="btn">+ Declare Another App</a></div>`))
	}
	w.Write([]byte(appsPageFooter))
}

func (s *Server) handleAppSubPage(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/apps/")
	switch {
	case path == "new":
		s.handleAppsNewPage(w, r)
	case path != "":
		s.handleAppDetailPage(w, r, path)
	default:
		http.Redirect(w, r, "/apps", http.StatusFound)
	}
}

func (s *Server) handleAppsNewPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(appsNewHTML))
}

func (s *Server) handleAppDetailPage(w http.ResponseWriter, r *http.Request, name string) {
	p := s.appRegistry
	if p == nil {
		http.Error(w, "app registry not configured", http.StatusServiceUnavailable)
		return
	}
	app, err := p.Get(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if app == nil {
		http.NotFound(w, r)
		return
	}
	displayName := app.DisplayName
	if displayName == "" {
		displayName = app.Name
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Build service rows
	rows := ""
	for _, svc := range app.Services {
		rows += `<tr><td>` + htmlEscape(svc.Name) + `</td>` +
			`<td><span class="stype stype-` + htmlEscape(svc.ServiceType) + `">` + htmlEscape(svc.ServiceType) + `</span></td>` +
			`<td class="mono">` + htmlEscape(svc.CgroupMatch) + `</td>` +
			`<td class="mono muted">` + htmlEscape(svc.BinaryPath) + `</td></tr>`
	}
	page := strings.NewReplacer(
		"{{APP_NAME}}", htmlEscape(app.Name),
		"{{APP_DISPLAY}}", htmlEscape(displayName),
		"{{APP_MODE}}", htmlEscape(string(app.Mode)),
		"{{APP_DESC}}", htmlEscape(app.Description),
		"{{SVC_ROWS}}", rows,
		"{{SVC_COUNT}}", itoa(len(app.Services)),
	).Replace(appsDetailHTML)
	w.Write([]byte(page))
}

// =============================================================================
// API handlers
// =============================================================================

func (s *Server) handleAPIApps(w http.ResponseWriter, r *http.Request) {
	p := s.appRegistry
	if p == nil {
		http.Error(w, `{"error":"app registry not configured"}`, http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		apps, err := p.List()
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, apps)
	case http.MethodPost:
		var req AppCreateReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apiErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		app, err := p.Create(req)
		if err != nil {
			apiErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, app)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAPIAppsPath(w http.ResponseWriter, r *http.Request) {
	p := s.appRegistry
	if p == nil {
		http.Error(w, `{"error":"app registry not configured"}`, http.StatusServiceUnavailable)
		return
	}

	// Strip /api/apps/ prefix and parse the rest.
	rest := strings.TrimPrefix(r.URL.Path, "/api/apps/")

	// Special case: /api/apps/discover
	if rest == "discover" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		svcs, err := p.Discover()
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if svcs == nil {
			svcs = []DiscoveredServiceView{}
		}
		writeJSON(w, svcs)
		return
	}

	// /api/apps/:name or /api/apps/:name/mode
	parts := strings.SplitN(rest, "/", 2)
	name := parts[0]
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}

	if name == "" {
		http.NotFound(w, r)
		return
	}

	switch {
	case sub == "policy" && r.Method == http.MethodGet:
		if s.compiledPolicy == nil {
			writeJSON(w, &CompiledPolicyView{App: name, Mode: "unknown", Services: []CompiledServiceView{}})
			return
		}
		pol, err := s.compiledPolicy.Policy(name)
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if pol == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, pol)

	case sub == "recompile" && r.Method == http.MethodPost:
		if s.compiledPolicy == nil {
			apiErr(w, "compiler not configured", http.StatusServiceUnavailable)
			return
		}
		pol, err := s.compiledPolicy.Recompile(name)
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if pol == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, pol)

	case sub == "arm-status" && r.Method == http.MethodGet:
		if s.compiledPolicy == nil {
			writeJSON(w, &ArmStatusView{App: name, Services: []ArmServiceView{}})
			return
		}
		st, err := s.compiledPolicy.ArmStatus(name)
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if st == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, st)

	case sub == "arm" && r.Method == http.MethodPost:
		if s.compiledPolicy == nil {
			apiErr(w, "compiler not configured", http.StatusServiceUnavailable)
			return
		}
		st, err := s.compiledPolicy.Arm(name)
		if err != nil {
			apiErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, st)

	case sub == "disarm" && r.Method == http.MethodPost:
		if s.compiledPolicy == nil {
			apiErr(w, "compiler not configured", http.StatusServiceUnavailable)
			return
		}
		st, err := s.compiledPolicy.Disarm(name)
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, st)

	case sub == "restart" && r.Method == http.MethodPost:
		if s.compiledPolicy == nil {
			apiErr(w, "compiler not configured", http.StatusServiceUnavailable)
			return
		}
		if err := s.compiledPolicy.Restart(name); err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]bool{"restarted": true})

	case sub == "health" && r.Method == http.MethodGet:
		// Confirm the app exists first so a typo returns 404, not a
		// misleading clean health card.
		app, err := p.Get(name)
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if app == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, s.appHealthFor(name))

	case sub == "mode" && r.Method == http.MethodPatch:
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apiErr(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := p.SetMode(name, req.Mode); err != nil {
			apiErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		app, _ := p.Get(name)
		writeJSON(w, app)

	case sub == "" && r.Method == http.MethodGet:
		app, err := p.Get(name)
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if app == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, app)

	case sub == "" && r.Method == http.MethodDelete:
		if err := p.Delete(name); err != nil {
			apiErr(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// appHealthFor returns the deny health for an app, or a clean zero-state
// when no provider is wired or the app has recorded no denies.
func (s *Server) appHealthFor(name string) AppHealthView {
	if s.appHealth != nil {
		if h := s.appHealth.AppHealth(name); h != nil {
			return *h
		}
	}
	return AppHealthView{
		App:      name,
		Status:   "clean",
		ByRule:   map[string]uint64{},
		ByBinary: map[string]uint64{},
		Recent:   []DenyEventView{},
	}
}

func apiErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	data, _ := json.Marshal(map[string]string{"error": msg})
	w.Write(data)
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// =============================================================================
// HTML templates
// =============================================================================

const appsPageHeader = `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><title>App Registry · xhelix</title>
<style>` + appsCSS + `</style></head><body>
<header>
  <h1>xhelix<span class="tag">v0.0.5</span></h1>
  <nav class="tabs">
    <a href="/ui">Dashboard</a>
    <a href="/ui/alerts">Alerts</a>
    <a href="/ui/sessions">Sessions</a>
    <a href="/ui/bans">Bans</a>
    <a href="/ui/rules">Rules</a>
    <a href="/ui/doctor">Doctor</a>
    <a href="/apps" class="active">Apps</a>
  </nav>
  <div class="right"><span class="live">live</span></div>
</header>
<main>
<div class="page-head">
  <h2>App Registry</h2>
  <a href="/apps/new" class="btn">+ Declare App</a>
</div>
`

const appsPageFooter = `</main></body></html>`

const appsDetailHTML = `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><title>{{APP_DISPLAY}} · App Registry · xhelix</title>
<style>` + appsCSS + `</style></head><body>
<header>
  <h1>xhelix<span class="tag">v0.0.5</span></h1>
  <nav class="tabs">
    <a href="/ui">Dashboard</a>
    <a href="/ui/alerts">Alerts</a>
    <a href="/ui/sessions">Sessions</a>
    <a href="/ui/bans">Bans</a>
    <a href="/ui/rules">Rules</a>
    <a href="/ui/doctor">Doctor</a>
    <a href="/apps" class="active">Apps</a>
  </nav>
  <div class="right"><span class="live">live</span></div>
</header>
<main>
<div class="page-head">
  <div><a href="/apps" class="back">← App Registry</a>
  <h2>{{APP_DISPLAY}}</h2></div>
  <button class="btn btn-danger" onclick="deleteApp()">Delete App</button>
</div>
<div class="detail-meta">
  <span class="label">Mode:</span>
  <select id="modeSelect" onchange="setMode(this.value)">
    <option value="observe"  {{if eq "{{APP_MODE}}" "observe"}}selected{{end}}>Observe — record only</option>
    <option value="shadow"   {{if eq "{{APP_MODE}}" "shadow"}}selected{{end}}>Shadow — log would-blocks</option>
    <option value="guarded"  {{if eq "{{APP_MODE}}" "guarded"}}selected{{end}}>Guarded — red zones blocked</option>
    <option value="locked"   {{if eq "{{APP_MODE}}" "locked"}}selected{{end}}>Locked — all undeclared blocked</option>
    <option value="sealed"   {{if eq "{{APP_MODE}}" "sealed"}}selected{{end}}>Sealed — unsigned drift blocked</option>
  </select>
  <span id="modeStatus" class="mode-badge mode-{{APP_MODE}}">{{APP_MODE}}</span>
</div>
<section>
  <h3>Services <span class="count">{{SVC_COUNT}}</span></h3>
  <table>
    <thead><tr><th>Name</th><th>Type</th><th>Cgroup Match</th><th>Binary</th></tr></thead>
    <tbody>{{SVC_ROWS}}</tbody>
  </table>
</section>
<section>
  <h3>Deny Health <span id="healthStatus" class="mode-badge mode-observe">–</span></h3>
  <div class="health-summary">
    <div class="hstat"><div class="hlabel">Total Denies</div><div id="hTotal" class="hvalue">–</div></div>
    <div class="hstat"><div class="hlabel">Last Deny</div><div id="hLast" class="hvalue muted">–</div></div>
  </div>
  <div id="healthBody" style="display:none">
    <div class="health-cols">
      <div>
        <h4>By Rule</h4>
        <table><tbody id="byRuleBody"></tbody></table>
      </div>
      <div>
        <h4>By Binary</h4>
        <table><tbody id="byBinaryBody"></tbody></table>
      </div>
    </div>
    <h4 style="margin-top:16px">Recent Blocks</h4>
    <table>
      <thead><tr><th>Time</th><th>Binary</th><th>Rule</th><th>Reason</th></tr></thead>
      <tbody id="recentDenyBody"></tbody>
    </table>
  </div>
  <div id="healthClean" class="muted" style="font-size:13px">No denies recorded — app is running clean.</div>
</section>
<section>
  <h3>Compiled Profile <span id="polMode" class="mode-badge mode-observe">–</span>
    <button class="btn-sm" style="float:right" onclick="recompile()">Recompile</button></h3>
  <div id="polMeta" class="muted" style="font-size:12px;margin-bottom:10px"></div>
  <div id="polStaged" class="staged-note" style="display:none">
    Seccomp / AppArmor profiles below are <strong>staged</strong>. Use <em>Arm</em> to
    install systemd drop-ins (non-disruptive — writes the policy + reloads systemd).
    Enforcement applies on the next service start; click <em>Restart services</em> to
    apply now. Live exec allowlisting via execguard is already active for locked/sealed.
  </div>
  <div id="armBar" class="arm-bar" style="display:none">
    <span id="armState" class="arm-state">–</span>
    <div class="arm-actions">
      <button class="btn-sm" id="armBtn" onclick="armApp()">Arm</button>
      <button class="btn-sm btn-ghost" id="disarmBtn" onclick="disarmApp()">Disarm</button>
      <button class="btn-sm btn-danger" id="restartBtn" onclick="restartApp()">Restart services</button>
    </div>
  </div>
  <div id="armServices" class="arm-svcs"></div>
  <div id="polServices"></div>
</section>
<section>
  <h3>Live Egress <span id="flowCount" class="count">–</span></h3>
  <div id="egressStatus" class="muted" style="margin-bottom:12px;font-size:12px"></div>
  <table id="egressTable" style="display:none">
    <thead><tr>
      <th>Binary</th><th>Dest</th><th>Port</th><th>Proto</th>
      <th>SNI / DNS</th><th>Bytes Out</th><th>Conns</th><th>Class</th>
    </tr></thead>
    <tbody id="egressBody"></tbody>
  </table>
  <div id="egressEmpty" class="muted" style="font-size:13px">No egress flows recorded yet for this app.</div>
</section>
<script>
const appName = "{{APP_NAME}}";
async function setMode(mode) {
  const r = await fetch("/api/apps/" + appName + "/mode", {
    method:"PATCH",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({mode})
  });
  const badge = document.getElementById("modeStatus");
  if (r.ok) {
    badge.textContent = mode;
    badge.className = "mode-badge mode-" + mode;
  } else {
    badge.textContent = "error";
  }
}
async function deleteApp() {
  if (!confirm("Delete app '" + appName + "'? This cannot be undone.")) return;
  const r = await fetch("/api/apps/" + appName, {method:"DELETE"});
  if (r.ok || r.status === 204) { window.location = "/apps"; }
  else { alert("Delete failed"); }
}

async function loadEgress() {
  const status = document.getElementById("egressStatus");
  status.textContent = "Loading…";
  try {
    const r = await fetch("/api/egress/live?app=" + encodeURIComponent(appName) + "&visibility=all");
    if (!r.ok) { status.textContent = "Egress unavailable (" + r.status + ")"; return; }
    const flows = await r.json();
    document.getElementById("flowCount").textContent = flows ? flows.length : 0;
    if (!flows || flows.length === 0) {
      document.getElementById("egressTable").style.display = "none";
      document.getElementById("egressEmpty").style.display = "";
      status.textContent = "";
      return;
    }
    document.getElementById("egressEmpty").style.display = "none";
    const tbody = document.getElementById("egressBody");
    tbody.innerHTML = "";
    flows.forEach(f => {
      const k = f.key || {}, m = f.metrics || {};
      const tr = document.createElement("tr");
      tr.innerHTML =
        '<td class="mono">' + esc(k.binary || "") + '</td>' +
        '<td class="mono">' + esc(k.dest_cidr || "") + '</td>' +
        '<td>' + (k.dest_port || "") + '</td>' +
        '<td>' + esc(k.protocol || "") + '</td>' +
        '<td class="muted">' + esc(k.sni || k.dns_name || "") + '</td>' +
        '<td>' + fmtBytes(m.bytes_out || 0) + '</td>' +
        '<td>' + (m.connects || 0) + '</td>' +
        '<td><span class="stype stype-' + esc(k.dest_class||"custom") + '">' + esc(k.dest_class || "–") + '</span></td>';
      tbody.appendChild(tr);
    });
    document.getElementById("egressTable").style.display = "";
    status.textContent = "Last updated: " + new Date().toLocaleTimeString();
  } catch(e) {
    status.textContent = "Error: " + e;
  }
}

function fmtBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n/1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n/1048576).toFixed(1) + " MB";
  return (n/1073741824).toFixed(2) + " GB";
}

function esc(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

async function loadHealth() {
  try {
    const r = await fetch("/api/apps/" + appName + "/health");
    if (!r.ok) return;
    const h = await r.json();
    const badge = document.getElementById("healthStatus");
    badge.textContent = h.status;
    badge.className = "mode-badge " + statusClass(h.status);
    document.getElementById("hTotal").textContent = h.total_denies || 0;
    document.getElementById("hLast").textContent =
      h.last_deny && h.total_denies ? new Date(h.last_deny).toLocaleString() : "never";
    if (!h.total_denies) {
      document.getElementById("healthBody").style.display = "none";
      document.getElementById("healthClean").style.display = "";
      return;
    }
    document.getElementById("healthClean").style.display = "none";
    document.getElementById("healthBody").style.display = "";
    fillCounts("byRuleBody", h.by_rule);
    fillCounts("byBinaryBody", h.by_binary);
    const tbody = document.getElementById("recentDenyBody");
    tbody.innerHTML = "";
    (h.recent || []).forEach(e => {
      const tr = document.createElement("tr");
      tr.innerHTML =
        '<td class="muted">' + new Date(e.time).toLocaleTimeString() + '</td>' +
        '<td class="mono">' + esc(e.binary) + '</td>' +
        '<td><span class="stype stype-php-fpm">' + esc(e.rule_id) + '</span></td>' +
        '<td class="muted">' + esc(e.reason) + '</td>';
      tbody.appendChild(tr);
    });
  } catch(e) { /* leave placeholder */ }
}

function fillCounts(id, m) {
  const tbody = document.getElementById(id);
  tbody.innerHTML = "";
  const entries = Object.entries(m || {}).sort((a,b) => b[1] - a[1]);
  if (entries.length === 0) {
    tbody.innerHTML = '<tr><td class="muted">none</td></tr>';
    return;
  }
  entries.forEach(([k, v]) => {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td class="mono">' + esc(k) + '</td><td style="text-align:right">' + v + '</td>';
    tbody.appendChild(tr);
  });
}

function statusClass(s) {
  if (s === "noisy") return "mode-locked";
  if (s === "active") return "mode-guarded";
  return "mode-shadow"; // clean
}

async function loadPolicy() {
  try {
    const r = await fetch("/api/apps/" + appName + "/policy");
    if (!r.ok) { renderPolicyMissing(); return; }
    renderPolicy(await r.json());
  } catch(e) { renderPolicyMissing(); }
}

async function recompile() {
  const r = await fetch("/api/apps/" + appName + "/recompile", {method:"POST"});
  if (r.ok) renderPolicy(await r.json());
  else alert("Recompile failed (" + r.status + ")");
}

function renderPolicyMissing() {
  document.getElementById("polMeta").textContent = "No compiled contract yet.";
  document.getElementById("polServices").innerHTML = "";
}

function renderPolicy(p) {
  const badge = document.getElementById("polMode");
  badge.textContent = p.mode;
  badge.className = "mode-badge mode-" + esc(p.mode);
  let meta = "source: " + esc(p.source) +
    " · compiled " + (p.compiled_at ? new Date(p.compiled_at).toLocaleString() : "–");
  if (p.mode === "shadow") meta += " · would-block count: " + (p.shadow_count || 0);
  if (p.warnings && p.warnings.length) meta += " · ⚠ " + p.warnings.map(esc).join("; ");
  document.getElementById("polMeta").innerHTML = meta;

  // Staged note + arm controls only matter in locked/sealed.
  const armable = (p.mode === "locked" || p.mode === "sealed");
  document.getElementById("polStaged").style.display = armable ? "" : "none";
  document.getElementById("armBar").style.display = armable ? "" : "none";
  if (armable) loadArmStatus();
  else { document.getElementById("armServices").innerHTML = ""; }

  const host = document.getElementById("polServices");
  host.innerHTML = "";
  (p.services || []).forEach(s => {
    const div = document.createElement("div");
    div.className = "pol-svc";
    div.innerHTML =
      '<div class="pol-svc-head"><span class="mono">' + esc(s.unit) + '</span>' +
      '<span class="stype stype-' + esc(s.kind || "custom") + '">' + esc(s.kind || "custom") + '</span></div>' +
      '<div class="pol-grid">' +
        polList("Exec Allow (live, scoped to cgroup)", s.exec_allow) +
        polList("Exec Deny (red-zone floor)", s.exec_deny) +
        polList("Deny Syscalls (staged)", s.deny_syscalls) +
        polList("Write Deny (staged)", s.write_deny) +
      '</div>';
    host.appendChild(div);
  });
}

async function loadArmStatus() {
  try {
    const r = await fetch("/api/apps/" + appName + "/arm-status");
    if (r.ok) renderArm(await r.json(), false);
  } catch(e) { /* leave as-is */ }
}

function renderArm(st, pending) {
  const anyArmed = (st.services || []).some(s => s.armed);
  const stateEl = document.getElementById("armState");
  if (st.pending_restart || pending) {
    stateEl.textContent = "armed · restart pending";
    stateEl.className = "arm-state arm-pending";
  } else if (anyArmed) {
    stateEl.textContent = "armed";
    stateEl.className = "arm-state arm-on";
  } else {
    stateEl.textContent = "not armed";
    stateEl.className = "arm-state arm-off";
  }
  const host = document.getElementById("armServices");
  host.innerHTML = "";
  (st.services || []).forEach(s => {
    const bits = [];
    if (s.seccomp) bits.push("seccomp");
    if (s.apparmor) bits.push("apparmor");
    const tag = s.armed ? '<span class="arm-on">armed</span>' : '<span class="arm-off">staged</span>';
    const warn = s.warning ? ' <span class="muted">⚠ ' + esc(s.warning) + '</span>' : '';
    const div = document.createElement("div");
    div.className = "arm-svc-row";
    div.innerHTML = '<span class="mono">' + esc(s.unit) + '</span> ' + tag +
      ' <span class="muted">' + esc(bits.join("+") || "—") + '</span>' + warn;
    host.appendChild(div);
  });
}

async function armApp() {
  if (!confirm("Arm '" + appName + "'? Writes systemd drop-ins and reloads systemd " +
    "(non-disruptive). Enforcement applies on next service start.")) return;
  const r = await fetch("/api/apps/" + appName + "/arm", {method:"POST"});
  const data = await r.json();
  if (!r.ok) { alert("Arm failed: " + (data.error || r.status)); return; }
  renderArm(data, data.pending_restart);
}

async function disarmApp() {
  if (!confirm("Disarm '" + appName + "'? Removes the systemd drop-ins. The running " +
    "service keeps the old policy until its next restart.")) return;
  const r = await fetch("/api/apps/" + appName + "/disarm", {method:"POST"});
  const data = await r.json();
  if (!r.ok) { alert("Disarm failed: " + (data.error || r.status)); return; }
  renderArm(data, data.pending_restart);
}

async function restartApp() {
  if (!confirm("RESTART this app's services now to apply the armed policy?\n\n" +
    "This is disruptive — the services will briefly stop. Continue?")) return;
  const r = await fetch("/api/apps/" + appName + "/restart", {method:"POST"});
  const data = await r.json();
  if (!r.ok) { alert("Restart failed: " + (data.error || r.status)); return; }
  alert("Restart issued.");
  loadArmStatus();
}

function polList(label, items) {
  items = items || [];
  const shown = items.slice(0, 12).map(esc).join("<br>");
  const more = items.length > 12 ? '<div class="muted">+' + (items.length - 12) + ' more</div>' : '';
  return '<div class="pol-col"><div class="pol-label">' + esc(label) +
    ' <span class="muted">(' + items.length + ')</span></div>' +
    '<div class="pol-items mono">' + (shown || '<span class="muted">none</span>') + '</div>' + more + '</div>';
}

// Load on page open and refresh every 30s.
loadEgress();
loadHealth();
loadPolicy();
setInterval(loadEgress, 30000);
setInterval(loadHealth, 30000);
</script>
</main></body></html>`

const appsNewHTML = `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><title>New App · xhelix</title>
<style>` + appsCSS + `</style></head><body>
<header>
  <h1>xhelix<span class="tag">v0.0.5</span></h1>
  <nav class="tabs">
    <a href="/ui">Dashboard</a>
    <a href="/ui/alerts">Alerts</a>
    <a href="/ui/sessions">Sessions</a>
    <a href="/ui/bans">Bans</a>
    <a href="/ui/rules">Rules</a>
    <a href="/ui/doctor">Doctor</a>
    <a href="/apps" class="active">Apps</a>
  </nav>
  <div class="right"><span class="live">live</span></div>
</header>
<main>
<div class="page-head">
  <div><a href="/apps" class="back">← App Registry</a>
  <h2>Declare New App</h2></div>
</div>

<section>
  <h3>Step 1 — Discover Running Services</h3>
  <button class="btn" id="scanBtn" onclick="scan()">Scan System</button>
  <div id="scanStatus" class="muted" style="margin-top:8px"></div>
  <table id="svcTable" style="display:none;margin-top:16px">
    <thead><tr>
      <th style="width:32px"></th>
      <th>Unit</th>
      <th>Type</th>
      <th>Cgroup</th>
      <th>Binary</th>
      <th>PIDs</th>
    </tr></thead>
    <tbody id="svcBody"></tbody>
  </table>
</section>

<section id="step2" style="display:none">
  <h3>Step 2 — Name Your App</h3>
  <div class="form-row">
    <label>App Name (slug)</label>
    <input type="text" id="appName" placeholder="wordpress" pattern="[a-z0-9_-]+"
           oninput="updateName(this.value)">
  </div>
  <div class="form-row">
    <label>Display Name</label>
    <input type="text" id="displayName" placeholder="WordPress">
  </div>
  <div class="form-row">
    <label>Description</label>
    <input type="text" id="description" placeholder="Main PHP app stack">
  </div>
  <div class="form-row">
    <label>Starting Mode</label>
    <select id="appMode">
      <option value="observe" selected>Observe — record only (recommended to start)</option>
      <option value="shadow">Shadow — log would-blocks</option>
      <option value="guarded">Guarded — red zones blocked</option>
    </select>
  </div>
  <div id="selectedServices" class="selected-svcs"></div>
  <button class="btn" id="declareBtn" onclick="declare()">Declare App</button>
  <div id="declareStatus" class="muted" style="margin-top:8px"></div>
</section>

<script>
let discovered = [];
let selected = new Set();

async function scan() {
  const btn = document.getElementById("scanBtn");
  const status = document.getElementById("scanStatus");
  btn.disabled = true;
  status.textContent = "Scanning…";
  try {
    const r = await fetch("/api/apps/discover");
    if (!r.ok) { status.textContent = "Scan failed: " + r.status; btn.disabled = false; return; }
    discovered = await r.json();
    renderTable();
    status.textContent = discovered.length + " service" + (discovered.length === 1 ? "" : "s") + " found";
  } catch(e) {
    status.textContent = "Error: " + e;
  }
  btn.disabled = false;
}

function renderTable() {
  const tbody = document.getElementById("svcBody");
  tbody.innerHTML = "";
  discovered.forEach((svc, i) => {
    const tr = document.createElement("tr");
    tr.innerHTML =
      '<td><input type="checkbox" onchange="toggleSvc(' + i + ', this.checked)"></td>' +
      '<td>' + esc(svc.unit_name || svc.sample_comm) + '</td>' +
      '<td><span class="stype stype-' + esc(svc.service_type) + '">' + esc(svc.service_type) + '</span></td>' +
      '<td class="mono">' + esc(svc.cgroup_path) + '</td>' +
      '<td class="mono muted">' + esc(svc.binary_path) + '</td>' +
      '<td class="muted">' + (svc.pids || []).length + '</td>';
    tbody.appendChild(tr);
  });
  document.getElementById("svcTable").style.display = "";
  document.getElementById("step2").style.display = "";
}

function toggleSvc(i, checked) {
  if (checked) selected.add(i);
  else selected.delete(i);
  renderSelected();
}

function renderSelected() {
  const div = document.getElementById("selectedServices");
  if (selected.size === 0) { div.innerHTML = ""; return; }
  let html = '<div class="sel-chips">';
  selected.forEach(i => {
    const s = discovered[i];
    html += '<span class="chip">' + esc(s.unit_name || s.sample_comm) + '</span>';
  });
  html += '</div>';
  div.innerHTML = html;
}

function updateName(v) {
  if (!document.getElementById("displayName").value) {
    document.getElementById("displayName").value =
      v.charAt(0).toUpperCase() + v.slice(1).replace(/[-_]/g, ' ');
  }
}

async function declare() {
  const name = document.getElementById("appName").value.trim();
  if (!name) { alert("App name required"); return; }
  if (selected.size === 0) { alert("Select at least one service"); return; }
  const services = [];
  selected.forEach(i => {
    const s = discovered[i];
    services.push({
      name: s.unit_name || s.sample_comm,
      cgroup_match: s.cgroup_path,
      binary_path: s.binary_path,
      service_type: s.service_type,
      unit_name: s.unit_name
    });
  });
  const payload = {
    name,
    display_name: document.getElementById("displayName").value || name,
    description: document.getElementById("description").value,
    mode: document.getElementById("appMode").value,
    services
  };
  const btn = document.getElementById("declareBtn");
  const status = document.getElementById("declareStatus");
  btn.disabled = true;
  status.textContent = "Saving…";
  try {
    const r = await fetch("/api/apps", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    });
    const data = await r.json();
    if (!r.ok) { status.textContent = "Error: " + (data.error || r.status); btn.disabled = false; return; }
    window.location = "/apps/" + name;
  } catch(e) {
    status.textContent = "Error: " + e;
    btn.disabled = false;
  }
}

function esc(s) {
  if (!s) return "";
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
</script>
</main></body></html>`

const appsCSS = `
:root{--bg:#0f1117;--card:#1a1d27;--border:#2a2d3a;--fg:#e2e8f0;--mut:#64748b;
      --accent:#6366f1;--ok:#22c55e;--warn:#f59e0b;--danger:#ef4444;--tag:#334155}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:14px/1.6 ui-monospace,monospace;min-height:100vh}
header{display:flex;align-items:center;gap:16px;padding:12px 24px;
       border-bottom:1px solid var(--border);background:var(--card)}
h1{font-size:18px;letter-spacing:-.5px}
.tag{font-size:10px;background:var(--tag);border-radius:4px;padding:2px 6px;margin-left:8px;
     vertical-align:middle;color:var(--mut)}
nav.tabs{display:flex;gap:4px;flex:1}
nav.tabs a{padding:6px 12px;border-radius:6px;color:var(--mut);text-decoration:none;font-size:13px}
nav.tabs a:hover,nav.tabs a.active{background:var(--border);color:var(--fg)}
.right{margin-left:auto}
.live{font-size:11px;color:var(--ok);text-transform:uppercase;letter-spacing:1px}
main{padding:24px;max-width:1200px;margin:0 auto}
.page-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
.page-head h2{font-size:20px;font-weight:600}
.back{color:var(--mut);text-decoration:none;font-size:13px;display:block;margin-bottom:4px}
.back:hover{color:var(--fg)}
.btn{padding:8px 16px;background:var(--accent);color:#fff;border:none;border-radius:6px;
     cursor:pointer;font:inherit;text-decoration:none;display:inline-block}
.btn:hover{opacity:.9}
.btn-sm{padding:5px 10px;background:var(--accent);color:#fff;border:none;border-radius:5px;
        cursor:pointer;font:12px/1 inherit;text-decoration:none;display:inline-block}
.btn-danger{background:var(--danger)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;
      display:flex;flex-direction:column;gap:10px}
.card-top{display:flex;align-items:center;justify-content:space-between}
.app-name{font-weight:600;font-size:15px}
.card-body{display:flex;flex-direction:column;gap:4px}
.svc-count{font-size:13px}
.svc-names{font-size:12px}
.muted{color:var(--mut)}
.card-foot{margin-top:auto}
.mode-badge{font-size:11px;padding:3px 8px;border-radius:4px;font-weight:600;text-transform:uppercase}
.mode-observe{background:#1e293b;color:var(--mut)}
.mode-shadow{background:#1e2a1e;color:var(--ok)}
.mode-guarded{background:#2a2010;color:var(--warn)}
.mode-locked{background:#2a1010;color:var(--danger)}
.mode-sealed{background:#1a1030;color:#a78bfa}
.empty{text-align:center;padding:64px 24px;color:var(--mut)}
.empty p{margin-bottom:16px;font-size:15px}
.actions{margin-top:24px}
section{background:var(--card);border:1px solid var(--border);border-radius:8px;
        padding:20px;margin-bottom:20px}
section h3{font-size:15px;font-weight:600;margin-bottom:16px}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);
   color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
td{padding:8px 10px;border-bottom:1px solid var(--border);font-size:13px}
tr:last-child td{border-bottom:none}
.mono{font-family:ui-monospace,monospace;font-size:12px}
.count{font-size:12px;background:var(--border);border-radius:4px;padding:2px 7px;
       margin-left:6px;color:var(--mut)}
.detail-meta{display:flex;align-items:center;gap:12px;padding:16px 20px;
             background:var(--card);border:1px solid var(--border);
             border-radius:8px;margin-bottom:20px}
.label{color:var(--mut);font-size:13px}
select{background:var(--border);color:var(--fg);border:1px solid var(--border);
       padding:6px 10px;border-radius:5px;font:inherit;cursor:pointer}
.stype{font-size:11px;padding:2px 7px;border-radius:4px;background:var(--border)}
.stype-nginx,.stype-apache{color:#38bdf8}
.stype-php-fpm{color:#a78bfa}
.stype-mysql,.stype-postgres{color:#fb923c}
.stype-redis{color:#f87171}
.stype-node{color:#4ade80}
.stype-python{color:#facc15}
.stype-custom{color:var(--mut)}
.form-row{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
.form-row label{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px}
.form-row input[type=text],.form-row select{background:var(--bg);border:1px solid var(--border);
  color:var(--fg);padding:8px 12px;border-radius:6px;font:inherit;width:100%;max-width:480px}
.sel-chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
.chip{background:var(--border);border-radius:4px;padding:3px 10px;font-size:12px}
.selected-svcs{margin-bottom:12px}
.health-summary{display:flex;gap:32px;margin-bottom:16px}
.hstat{display:flex;flex-direction:column;gap:4px}
.hlabel{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px}
.hvalue{font-size:22px;font-weight:600}
.health-cols{display:grid;grid-template-columns:1fr 1fr;gap:24px}
.health-cols h4,section h4{font-size:12px;color:var(--mut);text-transform:uppercase;
  letter-spacing:.5px;margin-bottom:8px}
.staged-note{background:#2a2010;border:1px solid var(--warn);border-radius:6px;
  padding:10px 12px;font-size:12px;color:#fbbf24;margin-bottom:14px}
.pol-svc{border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:12px}
.pol-svc-head{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.pol-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}
.pol-label{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.pol-items{font-size:12px;line-height:1.5;max-height:200px;overflow-y:auto}
.arm-bar{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:10px 12px;background:var(--bg);border:1px solid var(--border);
  border-radius:6px;margin-bottom:12px}
.arm-state{font-size:13px;font-weight:600}
.arm-on{color:var(--ok)}
.arm-off{color:var(--mut)}
.arm-pending{color:var(--warn)}
.arm-actions{display:flex;gap:8px}
.btn-ghost{background:var(--border)}
.arm-svcs{margin-bottom:12px}
.arm-svc-row{font-size:12px;padding:4px 0;border-bottom:1px solid var(--border)}
.arm-svc-row:last-child{border-bottom:none}
`

package web

import (
	"encoding/json"
	"fmt"
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
	// Restart restarts the app's services and verifies they come back
	// active. Any service that fails to start is auto-rolled-back; the
	// result lists which (empty RolledBack = all healthy).
	Restart(name string) (*RestartResultView, error)
	// BreakerReset clears a latched deny-storm alert for the app.
	BreakerReset(name string) error
	// SelfSign signs the current compiled-contract version with the
	// daemon's UI key (signer "ui"). For sealed-mode approval without
	// external CI. Returns the signed ArtifactSHA.
	SelfSign(name string) (string, error)
	// SubmitSignature stores an externally-produced (CI) signature over a
	// contract version. Verified against the trust root before storage.
	SubmitSignature(name, signer, artifactSHA, sigB64 string) error
	// Diff returns the behavioral diff of the current compiled version vs
	// the last-signed (approved) version. HasBaseline=false when nothing
	// has been signed yet (everything reads as new).
	Diff(name string) (*ContractDiffView, error)
	// Versions returns the signed version history for an app, newest first.
	Versions(name string) ([]ContractVersionView, error)
}

// ContractDiffView is the behavioral diff current-vs-last-signed.
type ContractDiffView struct {
	App         string           `json:"app"`
	FromSHA     string           `json:"from_sha"`
	ToSHA       string           `json:"to_sha"`
	HasBaseline bool             `json:"has_baseline"`
	Unchanged   int              `json:"unchanged"`
	Changes     []DiffChangeView `json:"changes"`
}

// DiffChangeView is one added/removed behavior.
type DiffChangeView struct {
	Kind  string `json:"kind"`
	Unit  string `json:"unit,omitempty"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// ContractVersionView is one entry in the signed version history.
type ContractVersionView struct {
	ArtifactSHA string    `json:"artifact_sha"`
	Signer      string    `json:"signer"`
	SignedAt    time.Time `json:"signed_at"`
	Active      bool      `json:"active"` // matches the current compiled version
}

// RestartResultView reports the outcome of an apply-restart, including any
// services auto-reverted because they failed to start under the policy.
type RestartResultView struct {
	App        string             `json:"app"`
	RolledBack []RolledBackView   `json:"rolled_back"`
}

// RolledBackView names a service whose arm was auto-reverted.
type RolledBackView struct {
	Unit   string `json:"unit"`
	Reason string `json:"reason"`
}

// ArmStatusView is the arm lifecycle state for an app, plus the
// deny-storm breaker state (alert-only).
type ArmStatusView struct {
	App            string          `json:"app"`
	Mode           string          `json:"mode"`
	PendingRestart bool            `json:"pending_restart"`
	Services       []ArmServiceView `json:"services"`
	// BreakerTripped latches when policy denies spiked past the threshold.
	// Alert-only — enforcement is NOT auto-disabled.
	BreakerTripped  bool `json:"breaker_tripped"`
	BreakerDenies   int  `json:"breaker_denies"`
	BreakerThreshold int `json:"breaker_threshold"`
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
	// ArtifactSHA is the content-addressed version of this contract (P7).
	// Signed/SignedBy report whether a trusted signature covers it — the
	// sealed-mode arm requirement.
	ArtifactSHA string `json:"artifact_sha"`
	Signed      bool   `json:"signed"`
	SignedBy    string `json:"signed_by,omitempty"`
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

// ProposalProvider handles the CI deploy-proposal flow (P7): CI proposes a
// new declaration, an admin approves (applies it) or rejects, CI polls
// status. Wired by the daemon via SetProposalProvider. Nil-safe.
type ProposalProvider interface {
	// Propose stores a CI-submitted declaration as pending and returns it.
	Propose(app string, req ProposeReq, submitter, sourceIP string) (*ProposalView, error)
	// List returns proposals for an app, newest first.
	List(app string) ([]ProposalView, error)
	// Diff returns the behavioral diff of a proposal vs the live version.
	Diff(app, id string) (*ContractDiffView, error)
	// Approve applies the proposal's declaration to the registry + recompiles.
	Approve(app, id, by string) error
	// Reject marks the proposal rejected.
	Reject(app, id, by string) error
	// Status returns one proposal (for CI polling).
	Status(app, id string) (*ProposalView, error)
}

// ProposeReq is the CI deploy-proposal payload.
type ProposeReq struct {
	Reason   string        `json:"reason"`
	Mode     string        `json:"mode"`
	Services []ServiceView `json:"services"`
}

// ProposalView is the web representation of a deploy proposal.
type ProposalView struct {
	ID        string    `json:"id"`
	App       string    `json:"app"`
	Status    string    `json:"status"`
	Submitter string    `json:"submitter"`
	SourceIP  string    `json:"source_ip,omitempty"`
	Reason    string    `json:"reason"`
	TargetSHA string    `json:"target_sha"`
	CreatedAt time.Time `json:"created_at"`
	DecidedAt time.Time `json:"decided_at,omitempty"`
	DecidedBy string    `json:"decided_by,omitempty"`
}

// SetProposalProvider wires the deploy-proposal flow into the server.
func (s *Server) SetProposalProvider(p ProposalProvider) { s.proposalProvider = p }

// AuditProvider records and reads the control-action audit trail (RBAC +
// who/when/what). Wired by the daemon via SetAuditProvider. Nil-safe.
type AuditProvider interface {
	Record(rec AuditRecord)
	ListForApp(app string, limit int) ([]AuditEntryView, error)
}

// AuditRecord is one control action to be appended to the trail.
type AuditRecord struct {
	Role      string
	TokenName string
	SourceIP  string
	Action    string // arm|disarm|restart|mode_change|delete|create|breaker_reset
	App       string
	Detail    string
	Outcome   string // ok | error: …
}

// AuditEntryView is one stored audit record returned to the UI.
type AuditEntryView struct {
	Seq      int64     `json:"seq"`
	Time     time.Time `json:"time"`
	Role     string    `json:"role"`
	Actor    string    `json:"actor"`
	SourceIP string    `json:"source_ip"`
	Action   string    `json:"action"`
	App      string    `json:"app"`
	Detail   string    `json:"detail,omitempty"`
	Outcome  string    `json:"outcome"`
}

// SetAuditProvider wires the audit trail into the server.
func (s *Server) SetAuditProvider(a AuditProvider) { s.auditProvider = a }

// audit appends a control action to the trail, attributed to the request's
// authenticated identity. No-op when no provider is wired.
func (s *Server) audit(r *http.Request, action, app, detail, outcome string) {
	if s.auditProvider == nil {
		return
	}
	id := IdentityFrom(r.Context())
	s.auditProvider.Record(AuditRecord{
		Role: id.Role.String(), TokenName: id.TokenName, SourceIP: id.SourceIP,
		Action: action, App: app, Detail: detail, Outcome: outcome,
	})
}

// outcome renders an audit outcome string from an error (nil = "ok").
func outcome(err error) string {
	if err == nil {
		return "ok"
	}
	return "error: " + err.Error()
}

// shortHash returns the first 12 chars of a content hash for log/audit use.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
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
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var req AppCreateReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apiErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		app, err := p.Create(req)
		s.audit(r, "create", req.Name, fmt.Sprintf("%d services, mode=%s", len(req.Services), req.Mode), outcome(err))
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
		if !requireRole(w, r, RoleOperator) {
			return
		}
		pol, err := s.compiledPolicy.Recompile(name)
		s.audit(r, "recompile", name, "", outcome(err))
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if pol == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, pol)

	case sub == "sign" && r.Method == http.MethodPost:
		// Self-sign the current contract version with the daemon key.
		if s.compiledPolicy == nil {
			apiErr(w, "compiler not configured", http.StatusServiceUnavailable)
			return
		}
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		hash, err := s.compiledPolicy.SelfSign(name)
		s.audit(r, "sign", name, "self-sign "+shortHash(hash), outcome(err))
		if err != nil {
			apiErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]string{"signed_artifact_sha": hash, "signer": "ui"})

	case sub == "signature" && r.Method == http.MethodPost:
		// Accept an externally-produced (CI) signature.
		if s.compiledPolicy == nil {
			apiErr(w, "compiler not configured", http.StatusServiceUnavailable)
			return
		}
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var req struct {
			Signer      string `json:"signer"`
			ArtifactSHA string `json:"artifact_sha"`
			SignatureB64 string `json:"signature_b64"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apiErr(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		err := s.compiledPolicy.SubmitSignature(name, req.Signer, req.ArtifactSHA, req.SignatureB64)
		s.audit(r, "sign", name, "ci-signature by "+req.Signer+" "+shortHash(req.ArtifactSHA), outcome(err))
		if err != nil {
			apiErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]bool{"accepted": true})

	case sub == "propose" && r.Method == http.MethodPost:
		if s.proposalProvider == nil {
			apiErr(w, "proposals not configured", http.StatusServiceUnavailable)
			return
		}
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var req ProposeReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apiErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		id := IdentityFrom(r.Context())
		pv, err := s.proposalProvider.Propose(name, req, id.TokenName, id.SourceIP)
		detail := "reason=" + req.Reason
		if pv != nil {
			detail += " id=" + pv.ID
		}
		s.audit(r, "propose", name, detail, outcome(err))
		if err != nil {
			apiErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, pv)

	case sub == "proposals" && r.Method == http.MethodGet:
		if s.proposalProvider == nil {
			writeJSON(w, []ProposalView{})
			return
		}
		ps, err := s.proposalProvider.List(name)
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if ps == nil {
			ps = []ProposalView{}
		}
		writeJSON(w, ps)

	case strings.HasPrefix(sub, "proposals/"):
		s.handleProposalSub(w, r, name, strings.TrimPrefix(sub, "proposals/"))

	case sub == "diff" && r.Method == http.MethodGet:
		if s.compiledPolicy == nil {
			writeJSON(w, &ContractDiffView{App: name, Changes: []DiffChangeView{}})
			return
		}
		dv, err := s.compiledPolicy.Diff(name)
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if dv == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, dv)

	case sub == "versions" && r.Method == http.MethodGet:
		if s.compiledPolicy == nil {
			writeJSON(w, []ContractVersionView{})
			return
		}
		vs, err := s.compiledPolicy.Versions(name)
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if vs == nil {
			vs = []ContractVersionView{}
		}
		writeJSON(w, vs)

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
		// Arming a sealed app is a higher-privilege action than a routine
		// locked arm — it requires admin (in addition to the break-glass
		// maintenance grant enforced by the provider).
		minRole := RoleOperator
		if app, _ := p.Get(name); app != nil && app.Mode == "sealed" {
			minRole = RoleAdmin
		}
		if !requireRole(w, r, minRole) {
			return
		}
		st, err := s.compiledPolicy.Arm(name)
		s.audit(r, "arm", name, "", outcome(err))
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
		if !requireRole(w, r, RoleOperator) {
			return
		}
		st, err := s.compiledPolicy.Disarm(name)
		s.audit(r, "disarm", name, "", outcome(err))
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
		// Restart is disruptive to a live production service → admin only.
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		res, err := s.compiledPolicy.Restart(name)
		detail := ""
		if res != nil && len(res.RolledBack) > 0 {
			detail = fmt.Sprintf("%d service(s) auto-rolled-back", len(res.RolledBack))
		}
		s.audit(r, "restart", name, detail, outcome(err))
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, res)

	case sub == "breaker/reset" && r.Method == http.MethodPost:
		if s.compiledPolicy == nil {
			apiErr(w, "compiler not configured", http.StatusServiceUnavailable)
			return
		}
		if !requireRole(w, r, RoleOperator) {
			return
		}
		err := s.compiledPolicy.BreakerReset(name)
		s.audit(r, "breaker_reset", name, "", outcome(err))
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]bool{"reset": true})

	case sub == "audit" && r.Method == http.MethodGet:
		if s.auditProvider == nil {
			writeJSON(w, []AuditEntryView{})
			return
		}
		entries, err := s.auditProvider.ListForApp(name, 100)
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if entries == nil {
			entries = []AuditEntryView{}
		}
		writeJSON(w, entries)

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
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apiErr(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Promoting INTO sealed mode is an admin-level action.
		if req.Mode == "sealed" && !requireRole(w, r, RoleAdmin) {
			return
		}
		err := p.SetMode(name, req.Mode)
		s.audit(r, "mode_change", name, "→ "+req.Mode, outcome(err))
		if err != nil {
			apiErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		app, err := p.Get(name)
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
		// Deleting an app is destructive (and disarms its enforcement) → admin.
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		err := p.Delete(name)
		s.audit(r, "delete", name, "", outcome(err))
		if err != nil {
			apiErr(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProposalSub routes /api/apps/:name/proposals/<id>[/action].
func (s *Server) handleProposalSub(w http.ResponseWriter, r *http.Request, app, rest string) {
	if s.proposalProvider == nil {
		apiErr(w, "proposals not configured", http.StatusServiceUnavailable)
		return
	}
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}
	if id == "" {
		http.NotFound(w, r)
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet,
		action == "status" && r.Method == http.MethodGet:
		pv, err := s.proposalProvider.Status(app, id)
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if pv == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, pv)

	case action == "diff" && r.Method == http.MethodGet:
		dv, err := s.proposalProvider.Diff(app, id)
		if err != nil {
			apiErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if dv == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, dv)

	case action == "approve" && r.Method == http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		by := IdentityFrom(r.Context()).TokenName
		err := s.proposalProvider.Approve(app, id, by)
		s.audit(r, "approve_proposal", app, "id="+id, outcome(err))
		if err != nil {
			apiErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]bool{"approved": true})

	case action == "reject" && r.Method == http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		by := IdentityFrom(r.Context()).TokenName
		err := s.proposalProvider.Reject(app, id, by)
		s.audit(r, "reject_proposal", app, "id="+id, outcome(err))
		if err != nil {
			apiErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]bool{"rejected": true})

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
    <button class="btn-sm" style="float:right" onclick="recompile()">Recompile</button>
    <button class="btn-sm btn-ghost" id="signBtn" style="float:right;margin-right:8px;display:none" onclick="signApp()">Sign version</button></h3>
  <div id="polMeta" class="muted" style="font-size:12px;margin-bottom:10px"></div>
  <div id="polStaged" class="staged-note" style="display:none">
    Seccomp / AppArmor profiles below are <strong>staged</strong>. Use <em>Arm</em> to
    install systemd drop-ins (non-disruptive — writes the policy + reloads systemd).
    Enforcement applies on the next service start; click <em>Restart services</em> to
    apply now. Live exec allowlisting via execguard is already active for locked/sealed.
  </div>
  <div id="breakerBanner" class="breaker-banner" style="display:none"></div>
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
  <h3>Pending Deploys <span id="propCount" class="count">–</span></h3>
  <div class="muted" style="font-size:12px;margin-bottom:8px">
    CI-proposed declaration changes awaiting review. Approve applies the new
    declaration (sealed apps still need a Sign before they can arm).
  </div>
  <div id="proposalsBody"></div>
  <div id="proposalsEmpty" class="muted" style="font-size:13px">No pending deploys.</div>
</section>
<section>
  <h3>Pending Changes <span id="diffCount" class="count">–</span></h3>
  <div id="diffMeta" class="muted" style="font-size:12px;margin-bottom:8px"></div>
  <div id="diffBody"></div>
  <h4 style="margin-top:16px">Version History</h4>
  <table id="versionsTable" style="display:none">
    <thead><tr><th>Version</th><th>Signed By</th><th>When</th><th>State</th></tr></thead>
    <tbody id="versionsBody"></tbody>
  </table>
  <div id="versionsEmpty" class="muted" style="font-size:13px">No signed versions yet.</div>
</section>
<section>
  <h3>Recent Activity <span class="count">audit</span></h3>
  <div class="muted" style="font-size:12px;margin-bottom:8px">
    Tamper-evident, hash-chained control-action log (who / when / what / outcome).
  </div>
  <table id="auditTable" style="display:none">
    <thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Source</th><th>Detail</th><th>Outcome</th></tr></thead>
    <tbody id="auditBody"></tbody>
  </table>
  <div id="auditEmpty" class="muted" style="font-size:13px">No control actions recorded yet.</div>
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
  if (p.artifact_sha) meta += " · version " + esc(p.artifact_sha.slice(0,12));
  if (p.signed) meta += " · ✓ signed by " + esc(p.signed_by || "?");
  else meta += " · ✗ unsigned";
  if (p.mode === "shadow") meta += " · would-block count: " + (p.shadow_count || 0);
  if (p.warnings && p.warnings.length) meta += " · ⚠ " + p.warnings.map(esc).join("; ");
  document.getElementById("polMeta").innerHTML = meta;

  // Sign button: relevant for sealed (required to arm) and locked (optional).
  const signBtn = document.getElementById("signBtn");
  if (signBtn) {
    signBtn.style.display = (p.mode === "sealed" || p.mode === "locked") ? "" : "none";
    signBtn.textContent = p.signed ? "Re-sign version" : "Sign version";
  }

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
  // Deny-storm breaker banner (alert-only — enforcement stays on).
  const bz = document.getElementById("breakerBanner");
  if (st.breaker_tripped) {
    bz.style.display = "";
    bz.innerHTML = "⚠ Deny-storm breaker TRIPPED — " + (st.breaker_denies || 0) +
      " policy denies in the window (threshold " + (st.breaker_threshold || 0) + "). " +
      "Enforcement is still ON (deny volume is attacker-controllable, so it is never " +
      "auto-disabled). Review the contract; if these are false positives, downgrade to " +
      "shadow. <button class='btn-sm btn-ghost' onclick='resetBreaker()'>Acknowledge</button>";
  } else {
    bz.style.display = "none";
  }
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
    "This is disruptive — the services will briefly stop. Any service that " +
    "fails to come back under the policy is auto-reverted and restored. Continue?")) return;
  const r = await fetch("/api/apps/" + appName + "/restart", {method:"POST"});
  const data = await r.json();
  if (!r.ok) { alert("Restart failed: " + (data.error || r.status)); return; }
  const rolled = data.rolled_back || [];
  if (rolled.length) {
    alert("Restart applied, but " + rolled.length + " service(s) FAILED to start " +
      "under the policy and were auto-rolled-back:\n\n" +
      rolled.map(x => "• " + x.unit + ": " + x.reason).join("\n"));
  } else {
    alert("Restart applied — all services healthy under the policy.");
  }
  loadArmStatus();
}

async function resetBreaker() {
  const r = await fetch("/api/apps/" + appName + "/breaker/reset", {method:"POST"});
  if (r.ok) loadArmStatus(); else alert("Reset failed");
}

async function signApp() {
  if (!confirm("Sign the current compiled-contract version with the daemon key?\n\n" +
    "This pins approval to this exact version — any later change to the declaration " +
    "(drift) invalidates it and, for sealed apps, blocks arming until re-signed.")) return;
  const r = await fetch("/api/apps/" + appName + "/sign", {method:"POST"});
  const data = await r.json();
  if (!r.ok) { alert("Sign failed: " + (data.error || r.status)); return; }
  loadPolicy(); loadDiff(); loadVersions();
}

function polList(label, items) {
  items = items || [];
  const shown = items.slice(0, 12).map(esc).join("<br>");
  const more = items.length > 12 ? '<div class="muted">+' + (items.length - 12) + ' more</div>' : '';
  return '<div class="pol-col"><div class="pol-label">' + esc(label) +
    ' <span class="muted">(' + items.length + ')</span></div>' +
    '<div class="pol-items mono">' + (shown || '<span class="muted">none</span>') + '</div>' + more + '</div>';
}

async function loadAudit() {
  try {
    const r = await fetch("/api/apps/" + appName + "/audit");
    if (!r.ok) return;
    const rows = await r.json();
    if (!rows || rows.length === 0) {
      document.getElementById("auditTable").style.display = "none";
      document.getElementById("auditEmpty").style.display = "";
      return;
    }
    document.getElementById("auditEmpty").style.display = "none";
    const tbody = document.getElementById("auditBody");
    tbody.innerHTML = "";
    rows.forEach(e => {
      const okp = (e.outcome === "ok");
      const tr = document.createElement("tr");
      tr.innerHTML =
        '<td class="muted">' + new Date(e.time).toLocaleString() + '</td>' +
        '<td><span class="stype stype-php-fpm">' + esc(e.action) + '</span></td>' +
        '<td>' + esc(e.role) + '</td>' +
        '<td class="mono muted">' + esc(e.source_ip) + '</td>' +
        '<td class="muted">' + esc(e.detail || "") + '</td>' +
        '<td class="' + (okp ? "arm-on" : "arm-off") + '">' + esc(e.outcome) + '</td>';
      tbody.appendChild(tr);
    });
    document.getElementById("auditTable").style.display = "";
  } catch(e) { /* leave placeholder */ }
}

async function loadDiff() {
  try {
    const r = await fetch("/api/apps/" + appName + "/diff");
    if (!r.ok) return;
    const d = await r.json();
    const meta = document.getElementById("diffMeta");
    const body = document.getElementById("diffBody");
    document.getElementById("diffCount").textContent = (d.changes||[]).length;
    if (!d.has_baseline) {
      meta.textContent = "No signed baseline yet — sign the current version to establish one.";
      body.innerHTML = "";
      return;
    }
    if (!d.changes || d.changes.length === 0) {
      meta.innerHTML = "✓ Current version matches the last signed version (" +
        esc((d.to_sha||"").slice(0,12)) + "). No drift.";
      body.innerHTML = "";
      return;
    }
    meta.innerHTML = "⚠ Current version (" + esc((d.to_sha||"").slice(0,12)) +
      ") DRIFTED from last signed (" + esc((d.from_sha||"").slice(0,12)) +
      "). " + d.changes.length + " change(s), " + (d.unchanged||0) + " unchanged. " +
      "Review, then Sign to approve.";
    let html = '<div class="diff-list">';
    d.changes.forEach(c => {
      const sym = c.op === "added" ? '<span class="arm-on">+</span>' : '<span class="arm-off">−</span>';
      html += '<div class="diff-row">' + sym + ' <span class="muted">' + esc(c.kind) +
        (c.unit ? " · " + esc(c.unit) : "") + '</span> <span class="mono">' + esc(c.value) + '</span></div>';
    });
    html += '</div>';
    body.innerHTML = html;
  } catch(e) { /* leave */ }
}

async function loadVersions() {
  try {
    const r = await fetch("/api/apps/" + appName + "/versions");
    if (!r.ok) return;
    const rows = await r.json();
    if (!rows || rows.length === 0) {
      document.getElementById("versionsTable").style.display = "none";
      document.getElementById("versionsEmpty").style.display = "";
      return;
    }
    document.getElementById("versionsEmpty").style.display = "none";
    const tbody = document.getElementById("versionsBody");
    tbody.innerHTML = "";
    rows.forEach(v => {
      const tr = document.createElement("tr");
      tr.innerHTML =
        '<td class="mono">' + esc((v.artifact_sha||"").slice(0,12)) + '</td>' +
        '<td>' + esc(v.signer) + '</td>' +
        '<td class="muted">' + new Date(v.signed_at).toLocaleString() + '</td>' +
        '<td>' + (v.active ? '<span class="arm-on">● active</span>' : '<span class="muted">previous</span>') + '</td>';
      tbody.appendChild(tr);
    });
    document.getElementById("versionsTable").style.display = "";
  } catch(e) { /* leave */ }
}

async function loadProposals() {
  try {
    const r = await fetch("/api/apps/" + appName + "/proposals");
    if (!r.ok) return;
    const rows = await r.json();
    const pending = (rows || []).filter(p => p.status === "pending");
    document.getElementById("propCount").textContent = pending.length;
    const host = document.getElementById("proposalsBody");
    const empty = document.getElementById("proposalsEmpty");
    if (pending.length === 0) { host.innerHTML = ""; empty.style.display = ""; return; }
    empty.style.display = "none";
    host.innerHTML = "";
    for (const p of pending) {
      const div = document.createElement("div");
      div.className = "pol-svc";
      div.innerHTML =
        '<div class="pol-svc-head"><span class="mono">' + esc(p.id) + '</span>' +
        '<span class="muted">' + esc(p.reason || "(no reason)") + '</span></div>' +
        '<div class="muted" style="font-size:12px">by ' + esc(p.submitter) +
        ' · ' + new Date(p.created_at).toLocaleString() +
        ' · target ' + esc((p.target_sha||"").slice(0,12)) + '</div>' +
        '<div id="pdiff-' + esc(p.id) + '" class="diff-list" style="margin:8px 0"></div>' +
        '<div><button class="btn-sm" onclick="approveProp(\'' + esc(p.id) + '\')">Approve</button> ' +
        '<button class="btn-sm btn-ghost" onclick="rejectProp(\'' + esc(p.id) + '\')">Reject</button></div>';
      host.appendChild(div);
      loadProposalDiff(p.id);
    }
  } catch(e) { /* leave */ }
}

async function loadProposalDiff(id) {
  try {
    const r = await fetch("/api/apps/" + appName + "/proposals/" + id + "/diff");
    if (!r.ok) return;
    const d = await r.json();
    const el = document.getElementById("pdiff-" + id);
    if (!el) return;
    if (!d.changes || d.changes.length === 0) { el.innerHTML = '<span class="muted">no behavioral change</span>'; return; }
    el.innerHTML = d.changes.map(c => {
      const sym = c.op === "added" ? '<span class="arm-on">+</span>' : '<span class="arm-off">−</span>';
      return '<div class="diff-row">' + sym + ' <span class="muted">' + esc(c.kind) +
        (c.unit ? " · " + esc(c.unit) : "") + '</span> <span class="mono">' + esc(c.value) + '</span></div>';
    }).join("");
  } catch(e) { /* leave */ }
}

async function approveProp(id) {
  if (!confirm("Approve this deploy? Applies the proposed declaration and recompiles.")) return;
  const r = await fetch("/api/apps/" + appName + "/proposals/" + id + "/approve", {method:"POST"});
  const data = await r.json();
  if (!r.ok) { alert("Approve failed: " + (data.error || r.status)); return; }
  loadProposals(); loadPolicy(); loadDiff(); loadVersions();
}

async function rejectProp(id) {
  if (!confirm("Reject this deploy proposal?")) return;
  const r = await fetch("/api/apps/" + appName + "/proposals/" + id + "/reject", {method:"POST"});
  const data = await r.json();
  if (!r.ok) { alert("Reject failed: " + (data.error || r.status)); return; }
  loadProposals();
}

// Load on page open and refresh every 30s.
loadEgress();
loadHealth();
loadPolicy();
loadAudit();
loadDiff();
loadVersions();
loadProposals();
setInterval(loadEgress, 30000);
setInterval(loadHealth, 30000);
setInterval(loadAudit, 30000);
setInterval(loadDiff, 30000);
setInterval(loadVersions, 30000);
setInterval(loadProposals, 30000);
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
.breaker-banner{background:#2a1010;border:1px solid var(--danger);border-radius:6px;
  padding:10px 12px;font-size:12px;color:#fca5a5;margin-bottom:12px;line-height:1.5}
.diff-list{display:flex;flex-direction:column;gap:3px}
.diff-row{font-size:12px;padding:3px 6px;border-radius:4px;background:var(--bg)}
.diff-row .mono{font-size:12px}
`

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/alert"
	"github.com/xhelix/xhelix/pkg/config"
	"github.com/xhelix/xhelix/pkg/doctor"
	"github.com/xhelix/xhelix/pkg/enforce"
	"github.com/xhelix/xhelix/pkg/incidentgraph"
	"github.com/xhelix/xhelix/pkg/appregistry"
	"github.com/xhelix/xhelix/pkg/contractarm"
	"github.com/xhelix/xhelix/pkg/contractaudit"
	"github.com/xhelix/xhelix/pkg/contractcompiler"
	"github.com/xhelix/xhelix/pkg/contractdiff"
	"github.com/xhelix/xhelix/pkg/contracthealth"
	"github.com/xhelix/xhelix/pkg/contractsign"
	"github.com/xhelix/xhelix/pkg/denyledger"
	"github.com/xhelix/xhelix/pkg/maintenancechain"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/netban"
	"github.com/xhelix/xhelix/pkg/rules"
	"github.com/xhelix/xhelix/pkg/session"
	"github.com/xhelix/xhelix/pkg/store"
	"github.com/xhelix/xhelix/ui/web"
)

// webBindAddr resolves the daemon's UI listen address. Defaults to
// 127.0.0.1:18443 when UI is enabled (HTTPS) or :18080 (HTTP) when
// not — never 0.0.0.0 by default; operator must opt in.
func webBindAddr(cfg config.Config) string {
	if cfg.UI.Enabled && cfg.UI.Bind != "" {
		return cfg.UI.Bind
	}
	if cfg.UI.Enabled {
		return "127.0.0.1:18443"
	}
	return "127.0.0.1:18080"
}

// startWebServer launches the dashboard. When cfg.UI.Enabled, the
// server is wrapped in AuthGuard with optional TLS. When disabled,
// the legacy unprotected dashboard runs on loopback only.
//
// Returns a *http.Server pointer for the enterprise listener so the
// caller can Shutdown() on daemon stop. Returns nil for the legacy
// path (web.Server handles its own lifecycle there).
func startWebServer(
	ctx context.Context,
	log *slog.Logger,
	cfg config.Config,
	webSrv *web.Server,
	sessionTracker *session.Tracker,
	banner *netban.Banner,
	ruleEngine *rules.Engine,
	soak *enforce.Soak,
	st *uiStats,
	incidentEng incidentgraph.Engine,
) *http.Server {
	if !cfg.UI.Enabled {
		// Legacy path — loopback, no auth, no TLS. Keeps upgrades
		// from older configs working.
		go func() {
			log.Info("web dashboard starting (legacy, loopback only)",
				"addr", webSrv.Addr)
			if err := webSrv.Start(); err != nil {
				log.Warn("web dashboard error", "err", err)
			}
		}()
		return nil
	}

	// Build the protected enterprise UI.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui", http.StatusFound)
	})

	// Adapters that bridge daemon state into the UI's required
	// interfaces. Defined in this file because they're tied to the
	// daemon's concrete types.
	webSrv.EnterprisePages(web.EnterpriseConfig{
		SessionLister: &daemonSessionLister{t: sessionTracker},
		BansLister:    &daemonBansLister{b: banner},
		RuleLister:    &daemonRuleLister{rules: ruleEngine, soak: soak},
		StatsProvider: st,
		DoctorRunner: func(c context.Context) doctor.Report {
			r := doctor.NewRunner(doctor.AllChecks(cfg)).Run(c)
			r.Hostname, _ = os.Hostname()
			return r
		},
	}, mux)

	// Incident graph HTTP surface (Phase D.2). Registered before
	// AuthGuard wraps the mux so requests are auth-checked alongside
	// every other UI route.
	registerIncidentRoutes(mux, incidentEng)

	// Egress dashboard (Option A — Week 2). Mount the same routes on
	// the auth-guarded mux so /egress works when cfg.UI.Enabled=true.
	webSrv.RegisterEgressRoutes(mux)
	webSrv.RegisterSafetyRoutes(mux)
	webSrv.RegisterZoneRoutes(mux)
	webSrv.RegisterMaintenanceRoutes(mux)
	webSrv.RegisterAppRoutes(mux)

	// AuthGuard — bearer token + IP allow-list + rate limit + audit.
	tokenFile := cfg.UI.TokenFile
	if tokenFile == "" {
		tokenFile = filepath.Join(cfg.Agent.StateDir, "ui-token")
	}
	auditLog := cfg.UI.AuditLog
	if auditLog == "" {
		auditLog = filepath.Join(cfg.Agent.LogDir, "ui-audit.log")
	}
	trustedProxies, err := parseProxyCIDRs(cfg.UI.TrustedProxies)
	if err != nil {
		log.Error("ui trusted_proxies invalid; falling back to loopback", "err", err)
		go func() { _ = webSrv.Start() }()
		return nil
	}
	guard, err := web.NewAuthGuard(web.AuthConfig{
		NoAuth:             cfg.UI.NoAuth,
		AllowIPs:           cfg.UI.AllowIPs,
		AutoDetectSSH:      cfg.UI.AutoDetectSSH,
		TokenFile:          tokenFile,
		RoleTokenFiles:     cfg.UI.RoleTokens,
		AuditLogPath:       auditLog,
		RateLimitPerSecond: cfg.UI.RateLimit,
		TrustForwardedFor:  cfg.UI.TrustForwarded,
		TrustedProxies:     trustedProxies,
		Logger:             log,
	})
	if err != nil {
		log.Error("auth guard init failed; falling back to loopback", "err", err)
		go func() { _ = webSrv.Start() }()
		return nil
	}
	log.Info("ui auth guard ready",
		"token_file", tokenFile,
		"audit_log", auditLog,
		"allow_ips", cfg.UI.AllowIPs,
		"auto_ssh", cfg.UI.AutoDetectSSH,
	)
	protected := guard.Wrap(mux)

	// HTTP→HTTPS redirect
	if cfg.UI.HTTPRedirect && cfg.UI.HTTPRedirectAddr != "" && cfg.UI.TLSEnabled {
		go func() {
			redirSrv := &http.Server{
				Addr: cfg.UI.HTTPRedirectAddr,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					host := r.Host
					if i := strings.IndexByte(host, ':'); i > 0 {
						host = host[:i]
					}
					// Best-effort: rewrite to HTTPS on the configured bind port
					target := "https://" + host
					if _, port, ok := splitHostPort(cfg.UI.Bind); ok {
						target += ":" + port
					}
					http.Redirect(w, r, target+r.URL.Path, http.StatusMovedPermanently)
				}),
				ReadHeaderTimeout: 5 * time.Second,
			}
			log.Info("http→https redirect listening", "addr", cfg.UI.HTTPRedirectAddr)
			_ = redirSrv.ListenAndServe()
		}()
	}

	// HTTPS or HTTP server
	bindAddr := cfg.UI.Bind
	if bindAddr == "" {
		bindAddr = "127.0.0.1:18443"
	}
	httpsSrv := &http.Server{
		Addr:              bindAddr,
		Handler:           protected,
		ReadHeaderTimeout: 5 * time.Second,
	}

	if cfg.UI.TLSEnabled {
		certPath := cfg.UI.TLSCert
		keyPath := cfg.UI.TLSKey
		if certPath == "" {
			certPath = filepath.Join(cfg.Agent.StateDir, "ui.crt")
		}
		if keyPath == "" {
			keyPath = filepath.Join(cfg.Agent.StateDir, "ui.key")
		}
		// Generate self-signed cert if missing — first-run convenience.
		if err := web.EnsureSelfSignedCert(certPath, keyPath, cfg.UI.AllowIPs); err != nil {
			log.Error("ui tls cert setup failed", "err", err)
			return nil
		}
		fp, _ := web.CertFingerprint(certPath)
		log.Info("ui tls ready", "cert", certPath, "key", keyPath,
			"fingerprint", fp)

		go func() {
			log.Info("web dashboard starting (HTTPS, protected)",
				"addr", bindAddr)
			err := httpsSrv.ListenAndServeTLS(certPath, keyPath)
			if err != nil && err != http.ErrServerClosed {
				log.Warn("https serve error", "err", err)
			}
		}()
	} else {
		go func() {
			log.Info("web dashboard starting (HTTP, protected)",
				"addr", bindAddr,
				"warning", "TLS disabled — token sniffable on the wire")
			err := httpsSrv.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				log.Warn("http serve error", "err", err)
			}
		}()
	}
	return httpsSrv
}

func splitHostPort(s string) (host, port string, ok bool) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func parseProxyCIDRs(raws []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(raws))
	for _, raw := range raws {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			if strings.Contains(raw, ":") {
				raw += "/128"
			} else {
				raw += "/32"
			}
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", raw, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// =====================================================================
// uiStats — DashboardStats provider that aggregates from the live
// daemon state. Counters stay simple; the UI just renders them.
// =====================================================================

type uiStats struct {
	hot            *store.HotStore
	bus            *alert.Bus
	sessionTracker *session.Tracker
	banner         *netban.Banner
}

func (u *uiStats) Stats() web.DashboardStats {
	out := web.DashboardStats{}
	if u.hot != nil {
		if n, err := u.hot.Count(context.Background()); err == nil {
			out.EventsTotal = uint64(n)
		}
	}
	if u.sessionTracker != nil {
		out.SessionsActive = len(u.sessionTracker.List())
	}
	if u.banner != nil {
		out.BansActive = int(u.banner.Stats().Active)
	}
	return out
}

// =====================================================================
// Adapters — bridge daemon types into the UI's listing interfaces.
// =====================================================================

type daemonSessionLister struct{ t *session.Tracker }

func (d *daemonSessionLister) List() []web.SessionView {
	if d.t == nil {
		return nil
	}
	out := []web.SessionView{}
	for _, s := range d.t.List() {
		snap := s.Snapshot()
		out = append(out, web.SessionView{
			ID:       snap.Session.ID,
			User:     snap.Session.User,
			SrcIP:    snap.Session.SrcIP,
			Method:   snap.Session.Method,
			LoginAt:  snap.Session.LoginAt,
			LogoutAt: snap.Session.LogoutAt,
			Active:   snap.Session.Active,
			Commands: snap.Commands,
			Events:   len(snap.Events),
			Alerts:   len(snap.Alerts),
		})
	}
	return out
}

type daemonBansLister struct{ b *netban.Banner }

func (d *daemonBansLister) ListBans() []web.BanView {
	if d.b == nil {
		return nil
	}
	out := []web.BanView{}
	if list, err := d.b.List(); err == nil {
		now := time.Now()
		for _, ip := range list {
			out = append(out, web.BanView{
				IP:      ip,
				Reason:  "auto-banned",
				AddedAt: now,
				Expires: now.Add(time.Hour),
			})
		}
	}
	return out
}

type daemonRuleLister struct {
	rules *rules.Engine
	soak  *enforce.Soak
}

func (d *daemonRuleLister) ListRules() []web.RuleView {
	// The rule engine doesn't expose its compiled list publicly,
	// so for now we surface an empty rules list — operators see
	// rule firings via the alerts page. Future work: extend
	// rules.Engine with a Rules() accessor.
	return nil
}

// daemonMaintenanceProvider adapts *maintenancechain.Store to
// web.MaintenanceProvider, translating between the two Grant shapes
// and applying the TTL/trust root from the existing key file.
type daemonMaintenanceProvider struct {
	store *maintenancechain.Store
}

func (d *daemonMaintenanceProvider) ListAll() ([]web.MaintenanceGrant, error) {
	raw, err := d.store.ListAll()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]web.MaintenanceGrant, 0, len(raw))
	for _, g := range raw {
		rem := g.Remaining()
		out = append(out, web.MaintenanceGrant{
			ID:          g.ID,
			AppName:     g.AppName,
			CgroupMatch: g.CgroupMatch,
			Scope:       string(g.Scope),
			AllowExec:   g.AllowExec,
			AllowWrite:  g.AllowWrite,
			Reason:      g.Reason,
			CreatedBy:   g.CreatedBy,
			CreatedAt:   g.CreatedAt,
			ExpiresAt:   g.ExpiresAt,
			SignedBy:     g.SignedBy,
			Remaining:   formatDuration(rem),
			Expired:     now.After(g.ExpiresAt),
		})
	}
	return out, nil
}

func (d *daemonMaintenanceProvider) Create(req web.MaintenanceCreateReq) (*web.MaintenanceGrant, error) {
	ttl := time.Duration(req.TTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	// The daemon's own signing key for UI-originated grants. If no BRP
	// key is configured the store still opens with an empty trust root,
	// and Mint will fail signature validation — surface the error clearly.
	signerKey, signerName, err := loadDaemonSigningKey()
	if err != nil {
		return nil, fmt.Errorf("no signing key available: operator must place an Ed25519 key at /etc/xhelix/brp/trusted-keys.d/ui.priv: %w", err)
	}
	g, err := d.store.Add(maintenancechain.MintParams{
		AppName:     req.AppName,
		CgroupMatch: req.CgroupMatch,
		Scope:       maintenancechain.Scope(req.Scope),
		AllowExec:   req.AllowExec,
		AllowWrite:  req.AllowWrite,
		Reason:      req.Reason,
		CreatedBy:   req.CreatedBy,
		TTL:         ttl,
		SignerName:  signerName,
		SignerKey:   signerKey,
	})
	if err != nil {
		return nil, err
	}
	rem := g.Remaining()
	out := &web.MaintenanceGrant{
		ID:          g.ID,
		AppName:     g.AppName,
		CgroupMatch: g.CgroupMatch,
		Scope:       string(g.Scope),
		AllowExec:   g.AllowExec,
		AllowWrite:  g.AllowWrite,
		Reason:      g.Reason,
		CreatedBy:   g.CreatedBy,
		CreatedAt:   g.CreatedAt,
		ExpiresAt:   g.ExpiresAt,
		SignedBy:    g.SignedBy,
		Remaining:  formatDuration(rem),
	}
	return out, nil
}

func (d *daemonMaintenanceProvider) Revoke(id string) error {
	return d.store.Revoke(id)
}

// loadDaemonSigningKey loads or generates the UI signing key used for
// maintenance grants created via the web interface. The key is stored at
// /var/lib/xhelix/ui-signing.key (raw Ed25519 private key bytes) and its
// public key is automatically trusted under the signer name "ui". This
// means operators get a working setup on first run without manual key
// management; security comes from the UI's own AuthGuard layer.
func loadDaemonSigningKey() (ed25519.PrivateKey, string, error) {
	const keyPath = "/var/lib/xhelix/ui-signing.key"
	priv, err := loadOrGenerateEd25519Key(keyPath)
	if err != nil {
		return nil, "", err
	}
	return priv, "ui", nil
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	return fmt.Sprintf("%dm", int(d.Minutes())+1)
}

// daemonAppRegistryProvider adapts *appregistry.Registry to
// web.AppRegistryProvider, translating between the two type shapes.
type daemonAppRegistryProvider struct {
	reg      *appregistry.Registry
	compiler *contractcompiler.Manager
}

// recompile re-runs the compiler for one app after a registry mutation.
// Best-effort — a compile failure never blocks the registry write.
func (d *daemonAppRegistryProvider) recompile(name string) {
	if d.compiler == nil {
		return
	}
	if app, err := d.reg.Get(name); err == nil && app != nil {
		d.compiler.Recompile(*app)
	}
}

func (d *daemonAppRegistryProvider) List() ([]web.AppView, error) {
	apps, err := d.reg.List()
	if err != nil {
		return nil, err
	}
	return toWebApps(apps), nil
}

func (d *daemonAppRegistryProvider) Get(name string) (*web.AppView, error) {
	a, err := d.reg.Get(name)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, nil
	}
	views := toWebApps([]appregistry.App{*a})
	return &views[0], nil
}

func (d *daemonAppRegistryProvider) Create(req web.AppCreateReq) (*web.AppView, error) {
	svcs := make([]appregistry.Service, 0, len(req.Services))
	for _, s := range req.Services {
		svcs = append(svcs, appregistry.Service{
			Name:        s.Name,
			CgroupMatch: s.CgroupMatch,
			BinaryPath:  s.BinaryPath,
			ServiceType: appregistry.ServiceType(s.ServiceType),
			UnitName:    s.UnitName,
		})
	}
	app := appregistry.App{
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Mode:        appregistry.EnforcementMode(req.Mode),
		Services:    svcs,
	}
	if err := d.reg.Create(app); err != nil {
		return nil, err
	}
	d.recompile(req.Name)
	created, err := d.reg.Get(req.Name)
	if err != nil {
		return nil, err
	}
	views := toWebApps([]appregistry.App{*created})
	return &views[0], nil
}

func (d *daemonAppRegistryProvider) SetMode(name, mode string) error {
	if err := d.reg.SetMode(name, appregistry.EnforcementMode(mode)); err != nil {
		return err
	}
	d.recompile(name) // mode change → recompile (arms/disarms the policy hook)
	return nil
}

func (d *daemonAppRegistryProvider) Delete(name string) error {
	if err := d.reg.Delete(name); err != nil {
		return err
	}
	if d.compiler != nil {
		d.compiler.Remove(name)
	}
	return nil
}

func (d *daemonAppRegistryProvider) Discover() ([]web.DiscoveredServiceView, error) {
	svcs, err := appregistry.Discover()
	if err != nil {
		return nil, err
	}
	out := make([]web.DiscoveredServiceView, 0, len(svcs))
	for _, s := range svcs {
		pids := make([]int32, len(s.PIDs))
		copy(pids, s.PIDs)
		out = append(out, web.DiscoveredServiceView{
			CgroupPath:  s.CgroupPath,
			UnitName:    s.UnitName,
			BinaryPath:  s.BinaryPath,
			ServiceType: string(s.ServiceType),
			PIDs:        pids,
			SampleComm:  s.SampleComm,
		})
	}
	return out, nil
}

func toWebApps(apps []appregistry.App) []web.AppView {
	out := make([]web.AppView, 0, len(apps))
	for _, a := range apps {
		svcs := make([]web.ServiceView, 0, len(a.Services))
		for _, s := range a.Services {
			svcs = append(svcs, web.ServiceView{
				Name:        s.Name,
				CgroupMatch: s.CgroupMatch,
				BinaryPath:  s.BinaryPath,
				ServiceType: string(s.ServiceType),
				UnitName:    s.UnitName,
			})
		}
		out = append(out, web.AppView{
			Name:        a.Name,
			DisplayName: a.DisplayName,
			Description: a.Description,
			Mode:        string(a.Mode),
			Services:    svcs,
			CreatedAt:   a.CreatedAt,
			UpdatedAt:   a.UpdatedAt,
		})
	}
	return out
}

// daemonAppHealthProvider adapts *denyledger.Ledger to web.AppHealthProvider.
type daemonAppHealthProvider struct {
	ledger *denyledger.Ledger
}

func (d *daemonAppHealthProvider) AppHealth(name string) *web.AppHealthView {
	h := d.ledger.AppHealth(name)
	if h == nil {
		return nil
	}
	recent := make([]web.DenyEventView, 0, len(h.Recent))
	for _, e := range h.Recent {
		recent = append(recent, web.DenyEventView{
			Time:       e.Time,
			Binary:     e.Binary,
			RuleID:     e.RuleID,
			Reason:     e.Reason,
			CgroupPath: e.CgroupPath,
		})
	}
	return &web.AppHealthView{
		App:         h.AppName,
		Status:      h.Status,
		TotalDenies: h.TotalDenies,
		ByRule:      h.ByRule,
		ByBinary:    h.ByBinary,
		FirstDeny:   h.FirstDeny,
		LastDeny:    h.LastDeny,
		Recent:      recent,
	}
}

// daemonCompiledPolicyProvider adapts the contract compiler manager to
// web.CompiledPolicyProvider (P5a). Recompile fetches the current app
// from the registry so the view reflects edits made since startup.
type daemonCompiledPolicyProvider struct {
	compiler *contractcompiler.Manager
	reg      *appregistry.Registry
	armorer  *contractarm.Armorer
	mc       *maintenancechain.Store    // sealed-mode break-glass
	breaker  *contracthealth.Breaker    // deny-storm state (alert-only)
	sign     *contractsign.Store        // sealed-mode signature gate (P7)
}

func (d *daemonCompiledPolicyProvider) Policy(name string) (*web.CompiledPolicyView, error) {
	cc := d.compiler.Get(name)
	if cc == nil {
		return nil, nil
	}
	return d.viewWithSig(cc), nil
}

func (d *daemonCompiledPolicyProvider) Recompile(name string) (*web.CompiledPolicyView, error) {
	if d.reg == nil {
		return nil, fmt.Errorf("registry unavailable")
	}
	app, err := d.reg.Get(name)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}
	cc := d.compiler.Recompile(*app)
	return d.viewWithSig(cc), nil
}

// viewWithSig builds the policy view and annotates signature status (P7).
func (d *daemonCompiledPolicyProvider) viewWithSig(cc *contractcompiler.CompiledContract) *web.CompiledPolicyView {
	v := toCompiledPolicyView(cc, d.compiler.ShadowCount(cc.App))
	v.ArtifactSHA = cc.ArtifactSHA
	if d.sign != nil {
		v.Signed, v.SignedBy = d.sign.HasValid(cc.App, cc.ArtifactSHA)
	}
	return v
}

// specsFor maps a compiled contract's services into arm specs.
func specsFor(cc *contractcompiler.CompiledContract) []contractarm.ServiceSpec {
	specs := make([]contractarm.ServiceSpec, 0, len(cc.Services))
	for i := range cc.Services {
		cs := &cc.Services[i]
		spec := contractarm.ServiceSpec{
			Unit:             cs.Unit,
			SeccompDirective: cs.SeccompSystemdDirective,
		}
		if cs.AppArmorText != "" {
			spec.AppArmor = &cs.AppArmor
		}
		specs = append(specs, spec)
	}
	return specs
}

func unitsFor(cc *contractcompiler.CompiledContract) []string {
	out := make([]string, 0, len(cc.Services))
	for _, cs := range cc.Services {
		out = append(out, cs.Unit)
	}
	return out
}

// sealedGateOK returns true when at least one of the app's service
// cgroups has an active maintenance-chain grant — the break-glass
// authority required to arm a sealed app.
func (d *daemonCompiledPolicyProvider) sealedGateOK(cc *contractcompiler.CompiledContract) bool {
	if d.mc == nil {
		return false
	}
	for _, cs := range cc.Services {
		if len(d.mc.ActiveFor(cs.CgroupMatch)) > 0 {
			return true
		}
	}
	return false
}

func (d *daemonCompiledPolicyProvider) ArmStatus(name string) (*web.ArmStatusView, error) {
	cc := d.compiler.Get(name)
	if cc == nil {
		return nil, nil
	}
	if d.armorer == nil {
		return &web.ArmStatusView{App: name, Mode: string(cc.Mode)}, nil
	}
	v := armStatusView(name, string(cc.Mode), false, d.armorer.Status(name, unitsFor(cc)))
	d.fillBreaker(name, v)
	return v, nil
}

// fillBreaker annotates an ArmStatusView with the deny-storm breaker state.
func (d *daemonCompiledPolicyProvider) fillBreaker(name string, v *web.ArmStatusView) {
	if d.breaker == nil || v == nil {
		return
	}
	v.BreakerTripped = d.breaker.Tripped(name)
	v.BreakerDenies = d.breaker.RecentDenies(name, time.Now())
	v.BreakerThreshold = d.breaker.Threshold()
}

func (d *daemonCompiledPolicyProvider) Arm(name string) (*web.ArmStatusView, error) {
	if d.armorer == nil {
		return nil, fmt.Errorf("armorer unavailable")
	}
	cc := d.compiler.Get(name)
	if cc == nil {
		return nil, fmt.Errorf("app %q has no compiled contract", name)
	}
	switch cc.Mode {
	case appregistry.ModeLocked, appregistry.ModeSealed:
		// armable
	default:
		return nil, fmt.Errorf("app must be in locked or sealed mode to arm (current: %s)", cc.Mode)
	}
	if cc.Mode == appregistry.ModeSealed {
		// Sealed = unsigned drift blocked. Arming requires EITHER a valid
		// trusted signature over the current contract version (the normal
		// path), OR an active maintenance grant (documented break-glass).
		signed := false
		if d.sign != nil {
			signed, _ = d.sign.HasValid(cc.App, cc.ArtifactSHA)
		}
		if !signed && !d.sealedGateOK(cc) {
			return nil, fmt.Errorf("sealed app: arming requires a valid signature over the current contract version (%s) or an active maintenance grant (break-glass)", shortSHA(cc.ArtifactSHA))
		}
	}
	res, err := d.armorer.Arm(cc.App, string(cc.Mode), specsFor(cc))
	if err != nil {
		return nil, err
	}
	return armResultView(name, string(cc.Mode), res), nil
}

// SelfSign signs the current compiled-contract version with the daemon UI
// key (signer "ui") and stores it.
func (d *daemonCompiledPolicyProvider) SelfSign(name string) (string, error) {
	if d.sign == nil {
		return "", fmt.Errorf("signing unavailable")
	}
	cc := d.compiler.Get(name)
	if cc == nil {
		return "", fmt.Errorf("app %q has no compiled contract", name)
	}
	priv, _, err := loadDaemonSigningKey()
	if err != nil {
		return "", fmt.Errorf("daemon signing key unavailable: %w", err)
	}
	sig := contractsign.Sign(cc.App, cc.ArtifactSHA, priv)
	snapshot, _ := json.Marshal(cc) // baseline for future behavioral diffs
	if _, err := d.sign.AddWithSnapshot(cc.App, cc.ArtifactSHA, "ui",
		base64.StdEncoding.EncodeToString(sig), snapshot); err != nil {
		return "", err
	}
	return cc.ArtifactSHA, nil
}

// SubmitSignature verifies + stores an external (CI) signature. The
// artifactSHA must match what CI signed; the store verifies the signature
// against the trust root before persisting.
func (d *daemonCompiledPolicyProvider) SubmitSignature(name, signer, artifactSHA, sigB64 string) error {
	if d.sign == nil {
		return fmt.Errorf("signing unavailable")
	}
	var snapshot []byte
	if artifactSHA == "" {
		// Default to the current version if CI didn't specify.
		if cc := d.compiler.Get(name); cc != nil {
			artifactSHA = cc.ArtifactSHA
		}
	}
	// Snapshot the contract content only when CI signed the CURRENT version
	// (we have that content to compare against in future diffs).
	if cc := d.compiler.Get(name); cc != nil && cc.ArtifactSHA == artifactSHA {
		snapshot, _ = json.Marshal(cc)
	}
	_, err := d.sign.AddWithSnapshot(name, artifactSHA, signer, sigB64, snapshot)
	return err
}

// Diff compares the current compiled version against the last-signed one.
func (d *daemonCompiledPolicyProvider) Diff(name string) (*web.ContractDiffView, error) {
	cc := d.compiler.Get(name)
	if cc == nil {
		return nil, nil
	}
	var baseline *contractcompiler.CompiledContract
	if d.sign != nil {
		if sha, _, _, ok := d.sign.LatestSigned(name); ok {
			if js, ok := d.sign.SnapshotJSON(name, sha); ok {
				var prev contractcompiler.CompiledContract
				if json.Unmarshal(js, &prev) == nil {
					baseline = &prev
				}
			}
		}
	}
	df := contractdiff.Compute(baseline, cc)
	out := &web.ContractDiffView{
		App: df.App, FromSHA: df.FromSHA, ToSHA: df.ToSHA,
		HasBaseline: baseline != nil, Unchanged: df.Unchanged,
	}
	for _, c := range df.Changes {
		out.Changes = append(out.Changes, web.DiffChangeView{
			Kind: string(c.Kind), Unit: c.Unit, Op: string(c.Op), Value: c.Value,
		})
	}
	return out, nil
}

// Versions returns the signed version history, marking the active one.
func (d *daemonCompiledPolicyProvider) Versions(name string) ([]web.ContractVersionView, error) {
	if d.sign == nil {
		return nil, nil
	}
	sigs, err := d.sign.ListForApp(name)
	if err != nil {
		return nil, err
	}
	currentSHA := ""
	if cc := d.compiler.Get(name); cc != nil {
		currentSHA = cc.ArtifactSHA
	}
	out := make([]web.ContractVersionView, 0, len(sigs))
	for _, sg := range sigs {
		out = append(out, web.ContractVersionView{
			ArtifactSHA: sg.ArtifactSHA, Signer: sg.Signer,
			SignedAt: sg.AddedAt, Active: sg.ArtifactSHA == currentSHA,
		})
	}
	return out, nil
}

func shortSHA(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func (d *daemonCompiledPolicyProvider) Disarm(name string) (*web.ArmStatusView, error) {
	if d.armorer == nil {
		return nil, fmt.Errorf("armorer unavailable")
	}
	cc := d.compiler.Get(name)
	if cc == nil {
		return nil, fmt.Errorf("app %q has no compiled contract", name)
	}
	res, err := d.armorer.Disarm(cc.App, specsFor(cc))
	if err != nil {
		return nil, err
	}
	return armResultView(name, string(cc.Mode), res), nil
}

func (d *daemonCompiledPolicyProvider) Restart(name string) (*web.RestartResultView, error) {
	if d.armorer == nil {
		return nil, fmt.Errorf("armorer unavailable")
	}
	cc := d.compiler.Get(name)
	if cc == nil {
		return nil, fmt.Errorf("app %q has no compiled contract", name)
	}
	rolled, err := d.armorer.RestartAndVerify(cc.App, unitsFor(cc))
	if err != nil {
		return nil, err
	}
	out := &web.RestartResultView{App: name}
	for _, r := range rolled {
		out.RolledBack = append(out.RolledBack, web.RolledBackView{Unit: r.Unit, Reason: r.Reason})
	}
	return out, nil
}

func (d *daemonCompiledPolicyProvider) BreakerReset(name string) error {
	if d.breaker == nil {
		return fmt.Errorf("breaker unavailable")
	}
	d.breaker.Reset(name)
	return nil
}

func armResultView(app, mode string, res contractarm.ArmResult) *web.ArmStatusView {
	v := &web.ArmStatusView{App: app, Mode: mode, PendingRestart: res.PendingRestart}
	for _, s := range res.Services {
		v.Services = append(v.Services, web.ArmServiceView{
			Unit: s.Unit, Armed: s.Armed, Seccomp: s.Seccomp,
			AppArmor: s.AppArmor, Warning: s.Warning,
		})
	}
	return v
}

func armStatusView(app, mode string, pending bool, sts []contractarm.ServiceStatus) *web.ArmStatusView {
	v := &web.ArmStatusView{App: app, Mode: mode, PendingRestart: pending}
	for _, s := range sts {
		v.Services = append(v.Services, web.ArmServiceView{
			Unit: s.Unit, Armed: s.Armed, Seccomp: s.Seccomp,
			AppArmor: s.AppArmor, Warning: s.Warning,
		})
	}
	return v
}

func toCompiledPolicyView(cc *contractcompiler.CompiledContract, shadow uint64) *web.CompiledPolicyView {
	v := &web.CompiledPolicyView{
		App:         cc.App,
		Mode:        string(cc.Mode),
		Source:      cc.Source,
		CompiledAt:  cc.CompiledAt,
		Warnings:    cc.Warnings,
		ShadowCount: shadow,
	}
	for _, s := range cc.Services {
		v.Services = append(v.Services, web.CompiledServiceView{
			Unit:         s.Unit,
			Kind:         s.Kind,
			CgroupMatch:  s.CgroupMatch,
			ExecAllow:    s.ExecAllow,
			ExecDeny:     s.ExecDeny,
			DenySyscalls: s.DenySyscalls,
			WriteDeny:    s.WriteDeny,
			SeccompText:  s.SeccompText,
			AppArmorText: s.AppArmorText,
		})
	}
	return v
}

// daemonAuditProvider adapts *contractaudit.Store to web.AuditProvider.
type daemonAuditProvider struct {
	store *contractaudit.Store
	log   *slog.Logger
}

func (d *daemonAuditProvider) Record(rec web.AuditRecord) {
	if _, err := d.store.Record(contractaudit.Entry{
		Role: rec.Role, TokenName: rec.TokenName, SourceIP: rec.SourceIP,
		Action: rec.Action, App: rec.App, Detail: rec.Detail, Outcome: rec.Outcome,
	}); err != nil && d.log != nil {
		d.log.Warn("contractaudit: record failed", "action", rec.Action, "app", rec.App, "err", err)
	}
}

func (d *daemonAuditProvider) ListForApp(app string, limit int) ([]web.AuditEntryView, error) {
	entries, err := d.store.ListForApp(app, limit)
	if err != nil {
		return nil, err
	}
	out := make([]web.AuditEntryView, 0, len(entries))
	for _, e := range entries {
		out = append(out, web.AuditEntryView{
			Seq: e.Seq, Time: e.Time, Role: e.Role, Actor: e.TokenName,
			SourceIP: e.SourceIP, Action: e.Action, App: e.App,
			Detail: e.Detail, Outcome: e.Outcome,
		})
	}
	return out, nil
}

// hush unused imports if a particular config branch isn't taken.
var _ = fmt.Sprintf
var _ = model.SeverityCritical

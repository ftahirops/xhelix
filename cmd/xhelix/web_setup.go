package main

import (
	"context"
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
		AllowIPs:           cfg.UI.AllowIPs,
		AutoDetectSSH:      cfg.UI.AutoDetectSSH,
		TokenFile:          tokenFile,
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

// hush unused imports if a particular config branch isn't taken.
var _ = fmt.Sprintf
var _ = model.SeverityCritical

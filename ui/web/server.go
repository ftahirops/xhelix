// Package web implements a lightweight HTTP dashboard for xhelix.
//
// It exposes real-time sensor health, alert feeds, quarantine status,
// rule status, and soak metrics via a minimal HTML interface.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/alert"
	"github.com/xhelix/xhelix/pkg/enforce"
	"github.com/xhelix/xhelix/pkg/incidentgraph"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/rules"
	"github.com/xhelix/xhelix/pkg/store"
	"github.com/xhelix/xhelix/sensors"
)

//go:embed static/*
var staticFS embed.FS

// Config holds the dependencies the web server needs.
type Config struct {
	Addr        string
	Log         *slog.Logger
	Store       *store.HotStore
	Bus         *alert.Bus
	Sensors     []sensors.Sensor
	Rules       *rules.Engine
	Quarantine  *enforce.Quarantine
	Soak        *enforce.Soak
	PanicSwitch *enforce.PanicSwitch
	// IncidentStore is the audit-trail backing for Phase D.1. When
	// non-nil, the web UI exposes /api/incidents and a basic
	// browser view. Nil-safe — read endpoints return [] when absent.
	IncidentStore *incidentgraph.Store
}

// Server is the HTTP dashboard.
type Server struct {
	Config
	XDP      XDPAdmin
	Addr     string
	srv      *http.Server
	mux      *http.ServeMux
	entPages *enterprisePages
	mu       sync.RWMutex
	alerts   []model.Alert
}

// SetXDP attaches an XDP admin (used by the daemon when the
// kernel-eBPF backend is online).
func (s *Server) SetXDP(a XDPAdmin) { s.XDP = a }

// NewServer creates a dashboard server.
func NewServer(cfg Config) *Server {
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}
	s := &Server{Config: cfg, Addr: cfg.Addr, alerts: make([]model.Alert, 0, 100)}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/alerts/stream", s.handleAlertStream)
	mux.HandleFunc("/api/sensors", s.handleSensors)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/quarantine", s.handleQuarantine)
	mux.HandleFunc("/api/soak", s.handleSoak)
	mux.HandleFunc("/api/panic", s.handlePanic)
	// Phase D.2 incidents UI.
	mux.HandleFunc("/api/incidents", s.handleIncidentsList)
	mux.HandleFunc("/api/incidents/", s.handleIncidentDetail)
	mux.HandleFunc("/incidents", s.handleIncidentsPage)
	s.registerAdminRoutes(mux)
	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))
	s.mux = mux

	s.srv = &http.Server{
		Addr:    cfg.Addr,
		Handler: mux,
	}
	return s
}

// Start begins serving.
func (s *Server) Start() error {
	return s.srv.ListenAndServe()
}

// Stop shuts down gracefully.
func (s *Server) Stop(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

const _dashboardHTMLLegacy = `<!DOCTYPE html>
<html>
<head>
    <title>xhelix Dashboard</title>
    <meta charset="utf-8">
    <style>
        body { font-family: monospace; margin: 20px; background: #1a1a1a; color: #0f0; }
        h1 { color: #0f0; border-bottom: 1px solid #0f0; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #333; }
        .alert { margin: 5px 0; padding: 5px; background: #2a2a2a; }
        .critical { color: #f00; }
        .high { color: #fa0; }
        .warn { color: #ff0; }
        .info { color: #0f0; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #333; }
        th { color: #0f0; }
    </style>
</head>
<body>
    <h1>xhelix Dashboard v{{.Version}}</h1>
    <div class="section">
        <h2>Status</h2>
        <p>Version: {{.Version}}</p>
        <p>Sensors: {{.Sensors}}</p>
        <p>Timestamp: {{.Timestamp}}</p>
    </div>
    <div class="section">
        <h2>Navigation</h2>
        <ul>
            <li><a href="/api/health">Health</a></li>
            <li><a href="/api/alerts">Alerts</a></li>
            <li><a href="/api/sensors">Sensors</a></li>
            <li><a href="/api/rules">Rules</a></li>
            <li><a href="/api/quarantine">Quarantine</a></li>
        </ul>
    </div>
</body>
</html>`

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("dashboard").Parse(_dashboardHTMLLegacy))
	data := map[string]interface{}{
		"Version":   "0.0.2",
		"Sensors":   len(s.Sensors),
		"Timestamp": time.Now().Format(time.RFC3339),
	}
	_ = tmpl.Execute(w, data)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"sensors":   len(s.Sensors),
	}
	writeJSON(w, status)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	alerts := make([]model.Alert, len(s.alerts))
	copy(alerts, s.alerts)
	s.mu.RUnlock()
	writeJSON(w, alerts)
}

func (s *Server) handleAlertStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastCount := 0
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			count := len(s.alerts)
			var latest []model.Alert
			if count > lastCount {
				latest = s.alerts[lastCount:]
				lastCount = count
			}
			s.mu.RUnlock()
			for _, a := range latest {
				data, _ := json.Marshal(a)
				fmt.Fprintf(w, "data: %s\n\n", data)
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleSensors(w http.ResponseWriter, r *http.Request) {
	var out []map[string]interface{}
	for _, sn := range s.Sensors {
		h := sn.Health()
		out = append(out, map[string]interface{}{
			"name":       sn.Name(),
			"healthy":    h.Healthy,
			"reason":     h.Reason,
			"drop_count": h.DropCount,
			"last_event": h.LastEvent,
		})
	}
	writeJSON(w, out)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		writeJSON(w, map[string]interface{}{"count": 0})
		return
	}
	writeJSON(w, map[string]interface{}{
		"count": s.Rules.Count(),
	})
}

func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	if s.Quarantine == nil {
		writeJSON(w, map[string]interface{}{"records": []interface{}{}})
		return
	}
	writeJSON(w, map[string]interface{}{
		"records": s.Quarantine.Snapshot(),
	})
}

func (s *Server) handleSoak(w http.ResponseWriter, r *http.Request) {
	if s.Soak == nil {
		writeJSON(w, map[string]interface{}{"records": []interface{}{}})
		return
	}
	writeJSON(w, map[string]interface{}{
		"records": s.Soak.Snapshot(),
	})
}

func (s *Server) handlePanic(w http.ResponseWriter, r *http.Request) {
	if s.PanicSwitch == nil {
		writeJSON(w, map[string]interface{}{"armed": false})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"armed": s.PanicSwitch.Armed()})
	case http.MethodPost:
		if err := s.PanicSwitch.Arm(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]interface{}{"armed": true})
	case http.MethodDelete:
		if err := s.PanicSwitch.Disarm(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]interface{}{"armed": false})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	data, _ := json.Marshal(v)
	_, _ = w.Write(data)
}

// AddAlert appends an alert to the live buffer (called from the bus).
func (s *Server) AddAlert(a model.Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append(s.alerts, a)
	if len(s.alerts) > 1000 {
		s.alerts = s.alerts[len(s.alerts)-1000:]
	}
}

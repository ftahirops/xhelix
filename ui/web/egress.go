// Package web — egress dashboard handlers (Week 2).
package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/xhelix/xhelix/pkg/egressledger"
)

// EgressProvider is what the daemon supplies to the web server.
// Implemented by *egressledger.Ledger.
type EgressProvider interface {
	QueryLive(egressledger.FlowFilter) []egressledger.FlowRecord
	QueryTimeline(start, end time.Time, f egressledger.FlowFilter) []egressledger.FlowRecord
	QueryBinary(binary string, start, end time.Time) []egressledger.FlowRecord
	QueryRecent(since time.Time, dstSet map[string]bool, binary string, limit int) []egressledger.ProcEvent
	Stats() egressledger.Stats
}

// SetEgress wires the ledger into the web server. Nil-safe.
func (s *Server) SetEgress(p EgressProvider) { s.egress = p }

// RegisterEgressRoutes mounts the egress dashboard routes on an external
// mux. Used by web_setup.go to publish them under the auth-guarded
// enterprise mux as well as the loopback default mux.
func (s *Server) RegisterEgressRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/egress", s.handleEgressIndex)
	mux.HandleFunc("/egress/v2", s.handleEgressV2Index)
	mux.HandleFunc("/egress/v2/", s.handleEgressV2Index)
	mux.HandleFunc("/egress/", s.handleEgressIndex)
	mux.HandleFunc("/api/egress/live", s.handleEgressLive)
	mux.HandleFunc("/api/egress/timeline", s.handleEgressTimeline)
	mux.HandleFunc("/api/egress/binary", s.handleEgressBinary)
	mux.HandleFunc("/api/egress/stats", s.handleEgressStats)
	mux.HandleFunc("/api/egress/countries", s.handleEgressCountries)
	mux.HandleFunc("/api/egress/companies", s.handleEgressCompanies)
	mux.HandleFunc("/api/egress/connections", s.handleEgressConnections)
	mux.HandleFunc("/api/egress/overview", s.handleEgressOverview)
	mux.HandleFunc("/api/egress/country", s.handleEgressCountry)
	mux.HandleFunc("/api/egress/uid_names", s.handleEgressUIDNames)
	mux.HandleFunc("/api/egress/policy/list", s.handleEgressPolicyList)
	mux.HandleFunc("/api/egress/ipinfo", s.handleEgressIPInfo)
	mux.HandleFunc("/api/egress/flow", s.handleEgressFlow)
	mux.HandleFunc("/api/egress/internal", s.handleEgressInternal)
	mux.HandleFunc("/api/egress/process_detail", s.handleEgressProcessDetail)
	mux.HandleFunc("/api/egress/pid", s.handleEgressPID)
	mux.HandleFunc("/api/egress/verdict", s.handleEgressVerdict)
	s.RegisterEgressCaptureRoutes(mux)
	s.RegisterEgressFleetRoutes(mux)
	mux.Handle("/static/egress/", http.FileServer(http.FS(staticFS)))
}

// handleEgressIndex serves the embedded SPA shell.
func (s *Server) handleEgressIndex(w http.ResponseWriter, r *http.Request) {
	body, err := staticFS.ReadFile("static/egress/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body)
}

// handleEgressV2Index serves the Portmaster-inspired /egress/v2
// dashboard shell. Completely standalone from the v1 SPA — its own
// HTML, CSS, JS bundle under /static/egress/v2/.
func (s *Server) handleEgressV2Index(w http.ResponseWriter, r *http.Request) {
	body, err := staticFS.ReadFile("static/egress/v2/v2.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body)
}

func (s *Server) handleEgressLive(w http.ResponseWriter, r *http.Request) {
	if s.egress == nil {
		writeJSONEgress(w, []egressledger.FlowRecord{})
		return
	}
	f := parseFilter(r)
	writeJSONEgress(w, s.egress.QueryLive(f))
}

func (s *Server) handleEgressTimeline(w http.ResponseWriter, r *http.Request) {
	if s.egress == nil {
		writeJSONEgress(w, []egressledger.FlowRecord{})
		return
	}
	end := time.Now()
	start := end.Add(-time.Hour)
	// Accept either ?hours= or ?minutes= for range scoping.
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 720 {
			start = end.Add(-time.Duration(n) * time.Hour)
		}
	} else if v := r.URL.Query().Get("minutes"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 720*60 {
			start = end.Add(-time.Duration(n) * time.Minute)
		}
	}
	f := parseFilter(r)
	writeJSONEgress(w, s.egress.QueryTimeline(start, end, f))
}

func (s *Server) handleEgressBinary(w http.ResponseWriter, r *http.Request) {
	if s.egress == nil {
		writeJSONEgress(w, []egressledger.FlowRecord{})
		return
	}
	binary := r.URL.Query().Get("binary")
	if binary == "" {
		http.Error(w, "binary param required", http.StatusBadRequest)
		return
	}
	days := 1
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 30 {
			days = n
		}
	}
	end := time.Now()
	start := end.Add(-time.Duration(days) * 24 * time.Hour)
	writeJSONEgress(w, s.egress.QueryBinary(binary, start, end))
}

func (s *Server) handleEgressStats(w http.ResponseWriter, r *http.Request) {
	if s.egress == nil {
		writeJSONEgress(w, egressledger.Stats{})
		return
	}
	writeJSONEgress(w, s.egress.Stats())
}

// parseFilter pulls FlowFilter fields out of the request query string.
func parseFilter(r *http.Request) egressledger.FlowFilter {
	q := r.URL.Query()
	f := egressledger.FlowFilter{
		Binary:     q.Get("binary"),
		UID:        -1,
		CGroupID:   -1,
		DestCIDR:   q.Get("dest_cidr"),
		DestPort:   -1,
		SNI:        q.Get("sni"),
		DestClass:  q.Get("dest_class"),
		DenyOnly:   q.Get("deny_only") == "1" || q.Get("deny_only") == "true",
		Visibility: parseVisibility(q.Get("visibility")),
	}
	if v := q.Get("uid"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.UID = int32(n)
		}
	}
	if v := q.Get("cgroup"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			f.CGroupID = n
		}
	}
	if v := q.Get("port"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.DestPort = int32(n)
		}
	}
	return f
}

// parseVisibility normalizes the ?visibility= query param. Default is
// "public" — operators get a cleaner dashboard immediately. "all" /
// "any" mean no filter; "internal" is the dedicated internal page.
func parseVisibility(v string) string {
	switch v {
	case "":
		return "public"
	case "all", "any":
		return ""
	case "public", "internal":
		return v
	}
	return "public"
}

// writeJSONEgress streams JSON with a sane Content-Type. Local to this
// file so we don't collide with the existing writeJSON helper (which
// uses json.Marshal+Write); using Encoder here is fine because output
// is fully owned by these handlers.
func writeJSONEgress(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

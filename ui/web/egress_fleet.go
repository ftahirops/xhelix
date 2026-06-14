// Package web — Week 6 fleet calibration endpoints.
//
// Surfaces "this host vs. its cohort" comparisons via the local xhub
// fleet engine (when wired). All endpoints are nil-safe: when no
// FleetIntel provider is attached, they return {"available":false} so
// the dashboard can render a "fleet hub not configured" placeholder.
//
// Wiring: the daemon calls Server.SetFleetIntel(p) with an adapter
// over *xhubfleet.Engine (or a thin HTTP proxy when the hub is
// remote). The web package does NOT import xhubfleet directly to
// keep this surface decoupled from any one fleet implementation.
package web

import (
	"net/http"
)

// FleetIntel is the minimal read-side surface the dashboard needs
// from a fleet hub. All methods must be safe to call from any
// goroutine. An implementation that has nothing to report should
// return zero-values, never panic.
type FleetIntel interface {
	// Available reports whether a fleet hub is reachable. When false,
	// every other call returns empty / zero. The dashboard uses this
	// to decide whether to render the "enable fleet hub" placeholder
	// instead of empty cards.
	Available() bool
	// MyCohort returns the cohort key for the current host as a
	// human-readable string ("server|nginx|debian12|apt|…") plus
	// the size of that cohort (number of peer hosts that share it).
	// Empty key / size 0 → host hasn't published yet or cohort
	// unmatched.
	MyCohort() (key string, size int)
	// RarityForBinary returns the per-destination cohort rarity for
	// a binary observed on this host. Each row says "of N hosts in
	// my cohort, M have been seen connecting to dest:port". 0 → not
	// observed by any peer (you're an outlier of 1); N → ubiquitous.
	RarityForBinary(binary string) []FleetRarityRow
	// TopOutliers returns the highest-signal cohort outliers this
	// host has emitted over the recent window — i.e. (binary, dest)
	// pairs where this host is in <10% of cohort hosts. Up to limit
	// rows, sorted by lowest fraction first.
	TopOutliers(limit int) []FleetOutlier
}

// FleetRarityRow is one (dest, port) row in a per-binary rarity view.
type FleetRarityRow struct {
	DestCIDR   string  `json:"dest_cidr"`
	Port       uint16  `json:"port"`
	HostsSeen  int     `json:"hosts_seen"`
	CohortSize int     `json:"cohort_size"`
	Fraction   float64 `json:"fraction"`
}

// FleetOutlier is one cohort-rare (binary, dest) tuple this host has
// emitted in the recent window.
type FleetOutlier struct {
	Binary     string  `json:"binary"`
	DestCIDR   string  `json:"dest_cidr"`
	Port       uint16  `json:"port"`
	HostsSeen  int     `json:"hosts_seen"`
	CohortSize int     `json:"cohort_size"`
	Fraction   float64 `json:"fraction"`
	Reason     string  `json:"reason"`
}

// SetFleetIntel wires a fleet-intelligence provider into the dashboard.
// Nil-safe — passing nil disables all /api/egress/fleet/* endpoints
// (they return {"available": false, ...}).
func (s *Server) SetFleetIntel(p FleetIntel) { s.fleet = p }

// RegisterEgressFleetRoutes mounts the fleet calibration endpoints.
// Called from RegisterEgressRoutes (loopback + enterprise paths) and
// also direct from NewServer for the default mux.
func (s *Server) RegisterEgressFleetRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/egress/fleet/cohort", s.handleEgressFleetCohort)
	mux.HandleFunc("/api/egress/fleet/rarity", s.handleEgressFleetRarity)
	mux.HandleFunc("/api/egress/fleet/anomaly", s.handleEgressFleetAnomaly)
}

// fleetUnavailable is the shared placeholder body the dashboard
// branches on. The exact reason string is operator-readable but not
// load-bearing — the UI only checks `available`.
func fleetUnavailable(reason string) map[string]any {
	return map[string]any{
		"available": false,
		"reason":    reason,
	}
}

func (s *Server) handleEgressFleetCohort(w http.ResponseWriter, r *http.Request) {
	if s.fleet == nil {
		writeJSONEgress(w, fleetUnavailable("fleet hub not configured (set xhub.url in xhelix.yaml)"))
		return
	}
	if !s.fleet.Available() {
		writeJSONEgress(w, fleetUnavailable("fleet hub unreachable"))
		return
	}
	key, size := s.fleet.MyCohort()
	writeJSONEgress(w, map[string]any{
		"available":   true,
		"cohort_key":  key,
		"cohort_size": size,
	})
}

func (s *Server) handleEgressFleetRarity(w http.ResponseWriter, r *http.Request) {
	if s.fleet == nil || !s.fleet.Available() {
		writeJSONEgress(w, fleetUnavailable("fleet hub not configured"))
		return
	}
	binary := r.URL.Query().Get("binary")
	if binary == "" {
		http.Error(w, "binary param required", http.StatusBadRequest)
		return
	}
	rows := s.fleet.RarityForBinary(binary)
	if rows == nil {
		rows = []FleetRarityRow{}
	}
	writeJSONEgress(w, map[string]any{
		"available": true,
		"binary":    binary,
		"rows":      rows,
	})
}

func (s *Server) handleEgressFleetAnomaly(w http.ResponseWriter, r *http.Request) {
	if s.fleet == nil || !s.fleet.Available() {
		writeJSONEgress(w, fleetUnavailable("fleet hub not configured"))
		return
	}
	limit := 5
	if v := r.URL.Query().Get("limit"); v != "" {
		// keep parsing trivial — out-of-range falls back to default.
		if n := atoiDefault(v, 5); n > 0 && n <= 100 {
			limit = n
		}
	}
	rows := s.fleet.TopOutliers(limit)
	if rows == nil {
		rows = []FleetOutlier{}
	}
	writeJSONEgress(w, map[string]any{
		"available": true,
		"outliers":  rows,
	})
}

// atoiDefault is a tiny inline strconv.Atoi that returns def on error.
// Avoids dragging strconv import into this file for one trivial call;
// kept local to keep handler code line-of-sight.
func atoiDefault(s string, def int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	return n
}

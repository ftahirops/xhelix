package main

import (
	"encoding/json"
	"net/http"

	"github.com/xhelix/xhelix/pkg/incidentgraph"
)

// registerIncidentRoutes attaches the /api/incidents HTTP surface
// onto the given mux. Phase D.2.
//
//   GET  /api/incidents          → JSON array, currently-open incidents
//   GET  /api/incidents/all      → JSON array, recent (open + closed)
//   GET  /api/incidents/{id}     → JSON object, one incident
//
// The HTTP surface is wrapped by the existing AuthGuard at the mux
// level — no separate auth here. The endpoint reads live from the
// in-memory engine (Snapshot is cheap, <100 incidents typical).
// Read-only: close mutations go through the CLI.
func registerIncidentRoutes(mux *http.ServeMux, eng incidentgraph.Engine) {
	if mux == nil || eng == nil {
		return
	}
	mux.HandleFunc("/api/incidents", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, eng.Snapshot())
	})
	mux.HandleFunc("/api/incidents/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.URL.Path[len("/api/incidents/"):]
		if id == "" || id == "all" {
			// /api/incidents/all is open + recently-closed; the in-memory
			// engine only holds open. For a full audit list operators
			// use `xhelixctl incidents list --all`.
			writeJSON(w, eng.Snapshot())
			return
		}
		inc, ok := eng.Get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, inc)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

package xhubfleet

import (
	"encoding/json"
	"net/http"

	"github.com/xhelix/xhelix/pkg/brp"
)

// RegisterRoutes mounts the fleet engine handlers on the given mux.
// All endpoints are read-only except /api/fleet/publish; the caller
// wraps with whatever auth middleware the hub uses.
func (e *Engine) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/fleet/candidates", e.handleCandidates)
	mux.HandleFunc("/api/fleet/cohorts", e.handleCohorts)
	mux.HandleFunc("/api/fleet/trust", e.handleTrust)
	mux.HandleFunc("/api/fleet/publish", e.handlePublish)
	mux.HandleFunc("/api/brp/feed", e.handleFeed)
}

func (e *Engine) handleCandidates(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Query().Get("rebuild") == "1" {
		e.RebuildCandidates()
	}
	writeJSON(w, e.Candidates())
}

func (e *Engine) handleCohorts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, e.rarity.Cohorts())
}

func (e *Engine) handleTrust(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, e.trust.All())
}

func (e *Engine) handleFeed(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, e.publisher.Feed())
}

// handlePublish accepts an already-signed BRP profile (produced by the
// operator CLI) and stores it in the publisher feed. Signature
// verification is the caller's responsibility — the hub stores by
// profile_id and the agent-side verifier checks signatures using the
// configured public key set before applying any profile.
func (e *Engine) handlePublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var sp brp.SignedProfile
	if err := json.NewDecoder(r.Body).Decode(&sp); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if sp.Profile.ProfileID == "" {
		http.Error(w, "profile_id empty", http.StatusBadRequest)
		return
	}
	if err := e.publisher.PutSigned(sp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"published": sp.Profile.ProfileID})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

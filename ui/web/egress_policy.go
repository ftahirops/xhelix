// Package web — egress policy handlers (Week 3).
//
// These endpoints expose the signed per-binary policies loaded by
// pkg/egresspolicy.Store. They are read-only at this milestone; the
// observe→sign workflow + UI page is Week 4.
package web

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/xhelix/xhelix/pkg/egresspolicy"
)

// EgressPolicyProvider is the read+reload surface the web UI uses to
// inspect signed per-binary egress policies. Implemented in
// cmd/xhelix by egressPolicyWebAdapter wrapping *egresspolicy.Engine.
//
// Week 4 widened this interface to include the workflow surface
// (Propose / Install / Delete). Implementations may return errors for
// the workflow methods when the daemon hasn't wired the ledger or the
// store is not writable — the UI degrades to read-only in that case.
type EgressPolicyProvider interface {
	List() []egresspolicy.SignedPolicy
	Get(binary string) *egresspolicy.SignedPolicy
	Reload() (int, error)
	// Propose drafts a Policy from observed ledger flows for binary.
	// Optional: implementations may return (Proposal{}, error) when the
	// ledger isn't available.
	Propose(ctx context.Context, binary string, days int) (egresspolicy.Proposal, error)
	// Install verifies + persists a SignedPolicy. Returns the binary it
	// installed for and the new total count loaded.
	Install(sp egresspolicy.SignedPolicy) (string, int, error)
	// Delete removes a signed policy by binary. Idempotent.
	Delete(binary string) (int, error)
}

// SetEgressPolicy wires the egress policy engine into the server.
// Nil-safe; when never called, the policy endpoints fall back to the
// Week 2 "suggestions from observed flows" stub in egress_intel.go.
func (s *Server) SetEgressPolicy(p EgressPolicyProvider) { s.egressPolicy = p }

// RegisterEgressPolicyRoutes mounts the read+reload endpoints on an
// external mux. Idempotent; safe alongside the existing /api/egress/
// route table.
func (s *Server) RegisterEgressPolicyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/egress/policy/show", s.handleEgressPolicyShow)
	mux.HandleFunc("/api/egress/policy/reload", s.handleEgressPolicyReload)
	mux.HandleFunc("/api/egress/policy/propose", s.handleEgressPolicyPropose)
	mux.HandleFunc("/api/egress/policy/install", s.handleEgressPolicyInstall)
	mux.HandleFunc("/api/egress/policy/delete", s.handleEgressPolicyDelete)
}

func (s *Server) handleEgressPolicyPropose(w http.ResponseWriter, r *http.Request) {
	if s.egressPolicy == nil {
		http.Error(w, "egress policy not enabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Binary string `json:"binary"`
		Days   int    `json:"days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Binary == "" {
		http.Error(w, "binary is required", http.StatusBadRequest)
		return
	}
	if req.Days <= 0 {
		req.Days = 14
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	prop, err := s.egressPolicy.Propose(ctx, req.Binary, req.Days)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONEgress(w, prop)
}

func (s *Server) handleEgressPolicyInstall(w http.ResponseWriter, r *http.Request) {
	if s.egressPolicy == nil {
		http.Error(w, "egress policy not enabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var sp egresspolicy.SignedPolicy
	if err := json.NewDecoder(r.Body).Decode(&sp); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	binary, total, err := s.egressPolicy.Install(sp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONEgress(w, map[string]any{"installed": binary, "loaded_total": total})
}

func (s *Server) handleEgressPolicyDelete(w http.ResponseWriter, r *http.Request) {
	if s.egressPolicy == nil {
		http.Error(w, "egress policy not enabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Binary string `json:"binary"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Binary == "" {
		http.Error(w, "binary is required", http.StatusBadRequest)
		return
	}
	total, err := s.egressPolicy.Delete(req.Binary)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONEgress(w, map[string]any{"deleted": req.Binary, "loaded_total": total})
}

func (s *Server) handleEgressPolicyShow(w http.ResponseWriter, r *http.Request) {
	if s.egressPolicy == nil {
		http.Error(w, "egress policy not enabled", http.StatusServiceUnavailable)
		return
	}
	binary := r.URL.Query().Get("binary")
	if binary == "" {
		http.Error(w, "binary param required", http.StatusBadRequest)
		return
	}
	sp := s.egressPolicy.Get(binary)
	if sp == nil {
		http.Error(w, "no signed policy for that binary", http.StatusNotFound)
		return
	}
	writeJSONEgress(w, sp)
}

func (s *Server) handleEgressPolicyReload(w http.ResponseWriter, r *http.Request) {
	if s.egressPolicy == nil {
		http.Error(w, "egress policy not enabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	n, err := s.egressPolicy.Reload()
	resp := map[string]any{"loaded": n}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSONEgress(w, resp)
}

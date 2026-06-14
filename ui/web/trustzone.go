// Package web — trust-zone handlers (Week 5 operator UI surface).
//
// Mirrors the safetynet handlers in shape: a thin provider interface,
// a Set wire-in method on Server, a RegisterZoneRoutes mux registrar.
// No CSRF on POST endpoints — same posture as the existing safety
// endpoints; the daemon assumes the AuthGuard wrapper above already
// handles auth/origin checks.
package web

import (
	"encoding/json"
	"net/http"

	"github.com/xhelix/xhelix/pkg/trustzone"
)

// TrustZoneProvider is the slice of *trustzone.Manager the web layer
// uses. Kept as an interface so tests can inject fakes.
type TrustZoneProvider interface {
	All() []trustzone.Assignment
	Default() trustzone.Label
	Add(a trustzone.Assignment) error
	Remove(index int) error
	SetDefault(l trustzone.Label) error
	Reload() (int, error)
}

// SetTrustZone wires the trust-zone manager into the server. Nil-safe.
func (s *Server) SetTrustZone(p TrustZoneProvider) { s.trustzone = p }

// RegisterZoneRoutes mounts trust-zone routes on an external mux.
// Idempotent; safe to call from both legacy + enterprise muxes.
func (s *Server) RegisterZoneRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/zones/list", s.handleZoneList)
	mux.HandleFunc("/api/zones/add", s.handleZoneAdd)
	mux.HandleFunc("/api/zones/remove", s.handleZoneRemove)
	mux.HandleFunc("/api/zones/default", s.handleZoneDefault)
	mux.HandleFunc("/api/zones/reload", s.handleZoneReload)
}

type zoneListResp struct {
	DefaultLabel trustzone.Label        `json:"default_label"`
	Assignments  []trustzone.Assignment `json:"assignments"`
}

func (s *Server) handleZoneList(w http.ResponseWriter, r *http.Request) {
	if s.trustzone == nil {
		writeJSONEgress(w, zoneListResp{DefaultLabel: trustzone.LabelTrusted})
		return
	}
	writeJSONEgress(w, zoneListResp{
		DefaultLabel: s.trustzone.Default(),
		Assignments:  s.trustzone.All(),
	})
}

func (s *Server) handleZoneAdd(w http.ResponseWriter, r *http.Request) {
	if s.trustzone == nil {
		http.Error(w, "trust zone not enabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var a trustzone.Assignment
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if a.Label == "" {
		http.Error(w, "label required", http.StatusBadRequest)
		return
	}
	if err := s.trustzone.Add(a); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONEgress(w, map[string]any{"ok": true})
}

type zoneRemoveReq struct {
	Index int `json:"index"`
}

func (s *Server) handleZoneRemove(w http.ResponseWriter, r *http.Request) {
	if s.trustzone == nil {
		http.Error(w, "trust zone not enabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req zoneRemoveReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.trustzone.Remove(req.Index); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONEgress(w, map[string]any{"ok": true})
}

type zoneDefaultReq struct {
	Label trustzone.Label `json:"label"`
}

func (s *Server) handleZoneDefault(w http.ResponseWriter, r *http.Request) {
	if s.trustzone == nil {
		http.Error(w, "trust zone not enabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req zoneDefaultReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.trustzone.SetDefault(req.Label); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONEgress(w, map[string]any{"ok": true})
}

func (s *Server) handleZoneReload(w http.ResponseWriter, r *http.Request) {
	if s.trustzone == nil {
		http.Error(w, "trust zone not enabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	n, err := s.trustzone.Reload()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONEgress(w, map[string]any{"ok": true, "assignments": n})
}

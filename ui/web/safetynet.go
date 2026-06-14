// Package web — safety-net handlers (operator UI surface).
package web

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/xhelix/xhelix/pkg/safetynet"
)

// SafetyNetProvider is the slice of *safetynet.SafetyNet the web layer
// uses. Kept as an interface so tests can inject fakes.
type SafetyNetProvider interface {
	AllowList() []string
	BlockList() []string
	AddAllow(cidr string) error
	RemoveAllow(cidr string) error
	AddBlock(cidr string) error
	RemoveBlock(cidr string) error
	RecentAttempts(n int) []safetynet.Attempt
	Stats() safetynet.Stats
}

// SetSafetyNet wires the safety-net into the server. Nil-safe.
func (s *Server) SetSafetyNet(p SafetyNetProvider) { s.safety = p }

// RegisterSafetyRoutes mounts safety-net routes on an external mux.
// Idempotent; safe to call from both default + enterprise muxes.
func (s *Server) RegisterSafetyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/safety/list", s.handleSafetyList)
	mux.HandleFunc("/api/safety/attempts", s.handleSafetyAttempts)
	mux.HandleFunc("/api/safety/stats", s.handleSafetyStats)
	mux.HandleFunc("/api/safety/whoami", s.handleSafetyWhoami)
	mux.HandleFunc("/api/safety/allow", s.handleSafetyAllowAdd)
	mux.HandleFunc("/api/safety/allow/delete", s.handleSafetyAllowDel)
	mux.HandleFunc("/api/safety/block", s.handleSafetyBlockAdd)
	mux.HandleFunc("/api/safety/block/delete", s.handleSafetyBlockDel)
}

type safetyListResp struct {
	Allow []string `json:"allow"`
	Block []string `json:"block"`
}

type safetyCIDRReq struct {
	CIDR string `json:"cidr"`
}

func (s *Server) handleSafetyList(w http.ResponseWriter, r *http.Request) {
	if s.safety == nil {
		writeJSONEgress(w, safetyListResp{})
		return
	}
	writeJSONEgress(w, safetyListResp{
		Allow: s.safety.AllowList(),
		Block: s.safety.BlockList(),
	})
}

func (s *Server) handleSafetyAttempts(w http.ResponseWriter, r *http.Request) {
	if s.safety == nil {
		writeJSONEgress(w, []safetynet.Attempt{})
		return
	}
	n := 50
	if v := r.URL.Query().Get("n"); v != "" {
		if x, err := strconv.Atoi(v); err == nil && x > 0 && x <= 5000 {
			n = x
		}
	}
	writeJSONEgress(w, s.safety.RecentAttempts(n))
}

func (s *Server) handleSafetyStats(w http.ResponseWriter, r *http.Request) {
	if s.safety == nil {
		writeJSONEgress(w, safetynet.Stats{})
		return
	}
	writeJSONEgress(w, s.safety.Stats())
}

// handleSafetyWhoami returns the visiting client IP so the UI can offer
// an "Add my current IP" button. Uses RemoteAddr; honors a trusted
// X-Forwarded-For only if the existing server is configured for it
// (the simple form here is RemoteAddr-only — the operator UI page is
// reached locally or over the SSH tunnel in practice).
func (s *Server) handleSafetyWhoami(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	writeJSONEgress(w, map[string]string{"ip": host})
}

func (s *Server) handleSafetyAllowAdd(w http.ResponseWriter, r *http.Request) {
	s.mutateSafety(w, r, func(c string) error { return s.safety.AddAllow(c) })
}

func (s *Server) handleSafetyAllowDel(w http.ResponseWriter, r *http.Request) {
	s.mutateSafety(w, r, func(c string) error { return s.safety.RemoveAllow(c) })
}

func (s *Server) handleSafetyBlockAdd(w http.ResponseWriter, r *http.Request) {
	s.mutateSafety(w, r, func(c string) error { return s.safety.AddBlock(c) })
}

func (s *Server) handleSafetyBlockDel(w http.ResponseWriter, r *http.Request) {
	s.mutateSafety(w, r, func(c string) error { return s.safety.RemoveBlock(c) })
}

func (s *Server) mutateSafety(w http.ResponseWriter, r *http.Request, fn func(string) error) {
	if s.safety == nil {
		http.Error(w, "safety net not enabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req safetyCIDRReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.CIDR = strings.TrimSpace(req.CIDR)
	if req.CIDR == "" {
		http.Error(w, "cidr required", http.StatusBadRequest)
		return
	}
	if err := fn(req.CIDR); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONEgress(w, map[string]any{"ok": true})
}

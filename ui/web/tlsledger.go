package web

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"

	"github.com/xhelix/xhelix/pkg/tlsledger"
)

// TLSPlaintextProvider is the read+admin surface the daemon wires to
// the web server. Nil-safe — when unset, every endpoint returns 503.
type TLSPlaintextProvider interface {
	List(n int, filter tlsledger.ListFilter, remoteIP string) []tlsledger.Record
	Get(id, remoteIP string) (tlsledger.Record, bool)
	Stats() tlsledger.Stats
	AddAllow(binary string)
	RemoveAllow(binary string)
	AllowList() []string
}

// SetTLSPlaintext wires the provider. Call before Start().
func (s *Server) SetTLSPlaintext(p TLSPlaintextProvider) {
	s.tlsplaintext = p
}

// RegisterTLSPlaintextRoutes mounts the handlers.
func (s *Server) RegisterTLSPlaintextRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/tls/plaintext/list", s.handleTLSPlaintextList)
	mux.HandleFunc("/api/tls/plaintext/get", s.handleTLSPlaintextGet)
	mux.HandleFunc("/api/tls/plaintext/stats", s.handleTLSPlaintextStats)
	mux.HandleFunc("/api/tls/plaintext/allow", s.handleTLSPlaintextAllow)
	mux.HandleFunc("/api/tls/plaintext/allowlist", s.handleTLSPlaintextAllowList)
}

// remoteIP returns the IP for audit logging. Trusts ONLY the TCP peer
// (r.RemoteAddr) — X-Forwarded-For is client-controlled and would let
// any caller forge the audit identity for sensitive plaintext access.
// If a deployment is fronted by a reverse proxy, route the trusted
// proxy through pkg/web AuthGuard's TrustForwardedFor + TrustedProxies
// path instead (it validates the immediate TCP peer first).
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleTLSPlaintextList(w http.ResponseWriter, r *http.Request) {
	if s.tlsplaintext == nil {
		http.Error(w, "tls plaintext ledger not enabled", http.StatusServiceUnavailable)
		return
	}
	n := 50
	if v := r.URL.Query().Get("n"); v != "" {
		if x, err := strconv.Atoi(v); err == nil && x > 0 && x <= 500 {
			n = x
		}
	}
	filter := tlsledger.ListFilter{
		Binary:        r.URL.Query().Get("binary"),
		PeerSNI:       r.URL.Query().Get("peer_sni"),
		DirectionSpec: r.URL.Query().Get("direction"),
	}
	recs := s.tlsplaintext.List(n, filter, remoteIP(r))
	writeJSON(w, recs)
}

func (s *Server) handleTLSPlaintextGet(w http.ResponseWriter, r *http.Request) {
	if s.tlsplaintext == nil {
		http.Error(w, "tls plaintext ledger not enabled", http.StatusServiceUnavailable)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	rec, ok := s.tlsplaintext.Get(id, remoteIP(r))
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, rec)
}

func (s *Server) handleTLSPlaintextStats(w http.ResponseWriter, r *http.Request) {
	if s.tlsplaintext == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	out := map[string]any{
		"enabled": true,
		"stats":   s.tlsplaintext.Stats(),
	}
	writeJSON(w, out)
}

func (s *Server) handleTLSPlaintextAllow(w http.ResponseWriter, r *http.Request) {
	if s.tlsplaintext == nil {
		http.Error(w, "tls plaintext ledger not enabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Binary string `json:"binary"`
		Action string `json:"action"` // "add" | "remove"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Binary == "" {
		http.Error(w, "missing binary", http.StatusBadRequest)
		return
	}
	switch body.Action {
	case "add":
		s.tlsplaintext.AddAllow(body.Binary)
	case "remove":
		s.tlsplaintext.RemoveAllow(body.Binary)
	default:
		http.Error(w, "action must be add or remove", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "allowlist": s.tlsplaintext.AllowList()})
}

func (s *Server) handleTLSPlaintextAllowList(w http.ResponseWriter, r *http.Request) {
	if s.tlsplaintext == nil {
		writeJSON(w, []string{})
		return
	}
	writeJSON(w, s.tlsplaintext.AllowList())
}

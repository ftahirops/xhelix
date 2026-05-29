// Package web — on-demand packet-capture endpoints. Operator-initiated
// tcpdump captures, bounded by size + duration. The pcap manager lives
// in pkg/pcap; this file is just the HTTP surface.
package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/pcap"
)

// PCAPProvider is the slice of *pcap.Manager the web layer uses.
// Implemented by *pcap.Manager; kept as an interface so handlers
// degrade gracefully when packet capture isn't available
// (tcpdump missing, etc.).
type PCAPProvider interface {
	Start(ctx context.Context, filter, description string, dur time.Duration, sizeMB int) (pcap.Capture, error)
	Stop(id string) error
	List() []pcap.Capture
	Get(id string) (pcap.Capture, bool)
	Path(id string) (string, bool)
	Delete(id string) error
}

// SetPCAP wires the capture manager. Nil-safe — when nil, handlers
// return 503 with a clear "unavailable" message so the UI can show
// a placeholder.
func (s *Server) SetPCAP(p PCAPProvider) { s.pcap = p }

// RegisterEgressCaptureRoutes mounts the capture endpoints. Called by
// the daemon alongside the other egress route registrations.
func (s *Server) RegisterEgressCaptureRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/egress/capture/start", s.handleCaptureStart)
	mux.HandleFunc("/api/egress/capture/stop", s.handleCaptureStop)
	mux.HandleFunc("/api/egress/capture/list", s.handleCaptureList)
	mux.HandleFunc("/api/egress/capture/delete", s.handleCaptureDelete)
	// Trailing-slash so /api/egress/capture/<id>/download routes here.
	mux.HandleFunc("/api/egress/capture/", s.handleCaptureItem)
}

func (s *Server) pcapUnavailable(w http.ResponseWriter) bool {
	if s.pcap == nil {
		http.Error(w, "packet capture unavailable — install tcpdump and restart xhelix", http.StatusServiceUnavailable)
		return true
	}
	return false
}

type captureStartReq struct {
	Filter          string `json:"filter"`
	Description     string `json:"description"`
	DurationSeconds int    `json:"duration_seconds"`
	SizeMB          int    `json:"size_mb"`
}

func (s *Server) handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	// Check availability first so the UI's GET probe sees 503 cleanly
	// when tcpdump isn't installed (it would otherwise see 405).
	if s.pcapUnavailable(w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req captureStartReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	dur := time.Duration(req.DurationSeconds) * time.Second
	rec, err := s.pcap.Start(r.Context(), req.Filter, req.Description, dur, req.SizeMB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONEgress(w, rec)
}

type captureIDReq struct {
	ID string `json:"id"`
}

func (s *Server) handleCaptureStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pcapUnavailable(w) {
		return
	}
	var req captureIDReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.pcap.Stop(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	rec, _ := s.pcap.Get(req.ID)
	writeJSONEgress(w, rec)
}

func (s *Server) handleCaptureList(w http.ResponseWriter, r *http.Request) {
	if s.pcap == nil {
		// Still 200 — UI uses an empty list + the /start endpoint's
		// 503 to decide whether to show the "unavailable" placeholder.
		writeJSONEgress(w, []pcap.Capture{})
		return
	}
	writeJSONEgress(w, s.pcap.List())
}

func (s *Server) handleCaptureDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pcapUnavailable(w) {
		return
	}
	var req captureIDReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.pcap.Delete(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSONEgress(w, map[string]string{"status": "deleted"})
}

// handleCaptureItem routes /api/egress/capture/<id>/download and
// /api/egress/capture/<id> (GET → metadata).
func (s *Server) handleCaptureItem(w http.ResponseWriter, r *http.Request) {
	if s.pcapUnavailable(w) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/egress/capture/")
	if path == "" || strings.HasPrefix(path, "start") || strings.HasPrefix(path, "stop") ||
		strings.HasPrefix(path, "list") || strings.HasPrefix(path, "delete") {
		http.NotFound(w, r)
		return
	}
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}
	switch action {
	case "", "info":
		rec, ok := s.pcap.Get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSONEgress(w, rec)
	case "download":
		p, ok := s.pcap.Path(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("Content-Disposition", `attachment; filename="`+id+`.pcap"`)
		_, _ = io.Copy(w, f)
	default:
		http.NotFound(w, r)
	}
}

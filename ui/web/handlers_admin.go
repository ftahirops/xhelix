package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// AdminConfig adds the admin-action surfaces to the dashboard.
type AdminConfig struct {
	XDPAdmin XDPAdmin
}

// XDPAdmin is the subset of pkg/xdpadmin.Admin the dashboard needs.
// We define an interface here so the web package doesn't pull in the
// xdpadmin package directly (kept dependency-light).
type XDPAdmin interface {
	Add(ip net.IP) error
	Remove(ip net.IP) error
	List() ([]net.IP, error)
}

func (s *Server) registerAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/alerts/fp", s.handleMarkFP)            // POST
	mux.HandleFunc("/api/rules/promote", s.handlePromoteRule)   // POST
	mux.HandleFunc("/api/quarantine/resume", s.handleResume)    // POST
	mux.HandleFunc("/api/quarantine/kill", s.handleKill)        // POST
	mux.HandleFunc("/api/panic/arm", s.handlePanicArm)          // POST
	mux.HandleFunc("/api/panic/disarm", s.handlePanicDisarm)    // POST
	mux.HandleFunc("/api/xdp/drop", s.handleXDPDrop)            // POST
	mux.HandleFunc("/api/xdp/undrop", s.handleXDPUndrop)        // POST
	mux.HandleFunc("/api/xdp/list", s.handleXDPList)            // GET
}

// handleMarkFP records a false positive for a rule. Resets the
// soak counter for that rule.
func (s *Server) handleMarkFP(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		RuleID string `json:"rule_id"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.RuleID == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("rule_id required"))
		return
	}
	if s.Soak == nil {
		writeErr(w, http.StatusServiceUnavailable, fmt.Errorf("soak engine not configured"))
		return
	}
	s.Soak.MarkFP(req.RuleID, time.Now())
	writeOK(w, map[string]string{
		"rule_id": req.RuleID,
		"action":  "fp_marked",
		"reason":  req.Reason,
	})
}

// handlePromoteRule moves a rule from detect → quarantine after
// soak.Promotable returns true.
func (s *Server) handlePromoteRule(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		RuleID string `json:"rule_id"`
		Mode   string `json:"mode"` // "quarantine" | "block"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if s.Soak == nil {
		writeErr(w, http.StatusServiceUnavailable, fmt.Errorf("soak engine not configured"))
		return
	}
	ok, rec := s.Soak.Promotable(req.RuleID, time.Now())
	if !ok {
		writeErr(w, http.StatusForbidden, fmt.Errorf("rule not promotable yet"))
		return
	}
	writeOK(w, map[string]any{
		"rule_id":      req.RuleID,
		"new_mode":     req.Mode,
		"promoted_at":  time.Now().UTC(),
		"clean_days":   rec.ConsecutiveCleanDays,
		"zero_fp_since": rec.ZeroFPSince,
	})
}

// handleResume sends SIGCONT to a quarantined pid.
func (s *Server) handleResume(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	pidStr := r.URL.Query().Get("pid")
	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("pid required"))
		return
	}
	if s.Quarantine == nil {
		writeErr(w, http.StatusServiceUnavailable, fmt.Errorf("quarantine not configured"))
		return
	}
	if err := s.Quarantine.Resume(uint32(pid)); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeOK(w, map[string]any{"pid": pid, "action": "resumed"})
}

// handleKill sends SIGKILL to a quarantined pid.
func (s *Server) handleKill(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	pidStr := r.URL.Query().Get("pid")
	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("pid required"))
		return
	}
	if s.Quarantine == nil {
		writeErr(w, http.StatusServiceUnavailable, fmt.Errorf("quarantine not configured"))
		return
	}
	if err := s.Quarantine.Kill(uint32(pid)); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeOK(w, map[string]any{"pid": pid, "action": "killed"})
}

// handlePanicArm flips the kill switch.
func (s *Server) handlePanicArm(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	if s.PanicSwitch == nil {
		writeErr(w, http.StatusServiceUnavailable, fmt.Errorf("panic switch not configured"))
		return
	}
	if err := s.PanicSwitch.Arm(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeOK(w, map[string]string{"action": "panic_armed"})
}

func (s *Server) handlePanicDisarm(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	if s.PanicSwitch == nil {
		writeErr(w, http.StatusServiceUnavailable, fmt.Errorf("panic switch not configured"))
		return
	}
	if err := s.PanicSwitch.Disarm(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeOK(w, map[string]string{"action": "panic_disarmed"})
}

// handleXDPDrop adds an IP to the kernel-side XDP drop set.
func (s *Server) handleXDPDrop(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	ip := net.ParseIP(req.IP)
	if ip == nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid IP"))
		return
	}
	if s.XDP == nil {
		writeErr(w, http.StatusServiceUnavailable, fmt.Errorf("XDP admin not configured"))
		return
	}
	if err := s.XDP.Add(ip); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeOK(w, map[string]string{"ip": ip.String(), "action": "dropped"})
}

func (s *Server) handleXDPUndrop(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	ip := net.ParseIP(req.IP)
	if ip == nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid IP"))
		return
	}
	if s.XDP == nil {
		writeErr(w, http.StatusServiceUnavailable, fmt.Errorf("XDP admin not configured"))
		return
	}
	if err := s.XDP.Remove(ip); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeOK(w, map[string]string{"ip": ip.String(), "action": "undropped"})
}

func (s *Server) handleXDPList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("GET required"))
		return
	}
	if s.XDP == nil {
		writeErr(w, http.StatusServiceUnavailable, fmt.Errorf("XDP admin not configured"))
		return
	}
	ips, err := s.XDP.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	writeOK(w, map[string]any{"ips": out, "count": len(out)})
}

// helpers

func requirePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("POST required"))
		return false
	}
	return true
}

func writeOK(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

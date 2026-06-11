package web

import (
	"net/http"
	"strconv"
	"time"
)

// CausalProvider assembles a causal chain for a process or lineage (P6).
// Wired by the daemon via SetCausal. Nil-safe.
type CausalProvider interface {
	TraceByPID(pid uint32) *CausalChainView
	TraceByLineage(id uint64) *CausalChainView
}

// CausalChainView is the web view of an assembled causal chain.
type CausalChainView struct {
	Found     bool                 `json:"found"`
	LineageID uint64               `json:"lineage_id,omitempty"`
	OriginIP  string               `json:"origin_ip,omitempty"`
	Origin    *CausalOriginView    `json:"origin,omitempty"`
	Processes []CausalProcessView  `json:"processes"`
}

// CausalOriginView is the root cause (who/where started the chain).
type CausalOriginView struct {
	Type       string    `json:"type"`
	User       string    `json:"user,omitempty"`
	SourceIP   string    `json:"source_ip,omitempty"`
	SourcePort uint16    `json:"source_port,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
}

// CausalProcessView is one hop (root → target order).
type CausalProcessView struct {
	PID       uint32    `json:"pid"`
	Comm      string    `json:"comm"`
	ExePath   string    `json:"exe_path,omitempty"`
	Cgroup    string    `json:"cgroup,omitempty"`
	UID       uint32    `json:"uid"`
	SpawnedAt time.Time `json:"spawned_at,omitempty"`
	Exited    bool      `json:"exited"`
}

// SetCausal wires a CausalProvider into the server.
func (s *Server) SetCausal(p CausalProvider) { s.causal = p }

// handleCausal serves GET /api/causal?pid=N or ?lineage=M (viewer). Returns
// the assembled chain, or {found:false} when the process/lineage is not in
// the live graph (exited + evicted, or never graphed).
func (s *Server) handleCausal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.causal == nil {
		writeJSON(w, &CausalChainView{Processes: []CausalProcessView{}})
		return
	}
	q := r.URL.Query()
	if v := q.Get("pid"); v != "" {
		pid, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			apiErr(w, "invalid pid", http.StatusBadRequest)
			return
		}
		writeJSON(w, orEmpty(s.causal.TraceByPID(uint32(pid))))
		return
	}
	if v := q.Get("lineage"); v != "" {
		lid, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			apiErr(w, "invalid lineage", http.StatusBadRequest)
			return
		}
		writeJSON(w, orEmpty(s.causal.TraceByLineage(lid)))
		return
	}
	apiErr(w, "provide ?pid= or ?lineage=", http.StatusBadRequest)
}

func orEmpty(c *CausalChainView) *CausalChainView {
	if c == nil {
		return &CausalChainView{Processes: []CausalProcessView{}}
	}
	if c.Processes == nil {
		c.Processes = []CausalProcessView{}
	}
	return c
}

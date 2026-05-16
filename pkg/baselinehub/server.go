package baselinehub

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server is the HTTPS endpoint agents POST to. The token-based auth
// is intentionally simple — operators wanting per-tenant isolation
// run multiple xhub instances rather than push multi-tenancy into
// one hub.
type Server struct {
	store      *Store
	authToken  string  // empty disables auth (dev only)
	log        *slog.Logger
	rateMu     sync.Mutex
	rateBucket map[string]int     // host_tag → bytes posted this minute
	rateWindow time.Time

	// Cached rare-endpoint computations to avoid recomputing on every
	// poll.
	cacheMu sync.Mutex
	cache   map[string]*cachedRare
}

type cachedRare struct {
	at  time.Time
	res *RareList
}

// ServerConfig is what NewServer accepts.
type ServerConfig struct {
	Store     *Store
	AuthToken string
	Logger    *slog.Logger
}

// NewServer builds an HTTP handler graph from the config.
func NewServer(cfg ServerConfig) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{
		store:      cfg.Store,
		authToken:  cfg.AuthToken,
		log:        cfg.Logger,
		rateBucket: map[string]int{},
		rateWindow: time.Now(),
		cache:      map[string]*cachedRare{},
	}
}

// RegisterRoutes wires the HTTP routes onto the given mux.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/upload", s.handleUpload)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/rare/", s.handleRare)
	mux.HandleFunc("/healthz", s.handleHealth)
}

func (s *Server) authOK(r *http.Request) bool {
	if s.authToken == "" {
		return true // auth disabled
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	return constantTimeEq(auth[len(prefix):], s.authToken)
}

// constantTimeEq compares two strings in constant time INCLUDING for
// unequal lengths — the prior version returned early on length
// mismatch, leaking the token's exact length via timing. The stdlib
// crypto/subtle ConstantTimeCompare handles unequal lengths in a
// length-independent way: it returns 0 immediately but only after
// the comparison itself is constant-time relative to the longer
// input. The defence-in-depth here is also that a real attacker
// can't easily probe the token over HTTP at the resolution required
// to time-distinguish 10s of bytes — but the previous code made it
// trivially wrong-on-paper.
func constantTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

const maxUploadBytes = 8 * 1024 * 1024

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxUploadBytes))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var u Upload
	if err := json.Unmarshal(body, &u); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if u.HostTag == "" {
		http.Error(w, "missing host_tag", http.StatusBadRequest)
		return
	}
	// Per-host bytes/min rate cap to bound disk pressure from a
	// runaway agent.
	if !s.rateAllow(u.HostTag, len(body)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if err := s.store.IngestUploadWithSize(u, len(body)); err != nil {
		s.log.Warn("hub: ingest failed", "host", u.HostTag, "err", err)
		http.Error(w, "ingest failed", http.StatusInternalServerError)
		return
	}
	s.log.Info("hub: upload received",
		"host", u.HostTag, "windows", len(u.Windows), "bytes", len(body))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.store.Stats())
}

func (s *Server) handleRare(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Binary names contain "/" which Go's mux normalises if put in
	// the path. Take the binary as a query parameter; keeps the value
	// bit-for-bit identical to what was uploaded.
	binary := r.URL.Query().Get("binary")
	if binary == "" {
		// Backward-compat: also accept it as a path suffix for
		// hand-rolled URLs without slashes (e.g. "/api/rare/nginx").
		const prefix = "/api/rare/"
		if strings.HasPrefix(r.URL.Path, prefix) {
			binary = r.URL.Path[len(prefix):]
		}
	}
	if binary == "" {
		http.Error(w, "missing binary (use ?binary=...)", http.StatusBadRequest)
		return
	}
	lookback := 7
	if v := r.URL.Query().Get("lookback_days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 90 {
			lookback = n
		}
	}
	cutoff := 0.95
	if v := r.URL.Query().Get("rarity_cutoff"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f < 1 {
			cutoff = f
		}
	}
	cacheKey := fmt.Sprintf("%s|%d|%.2f", binary, lookback, cutoff)
	s.cacheMu.Lock()
	if c, ok := s.cache[cacheKey]; ok && time.Since(c.at) < time.Minute {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Cache", "hit")
		_ = json.NewEncoder(w).Encode(c.res)
		s.cacheMu.Unlock()
		return
	}
	s.cacheMu.Unlock()

	res, err := s.store.ComputeRare(binary, lookback, cutoff)
	if err != nil {
		http.Error(w, "compute rare: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.cacheMu.Lock()
	s.cache[cacheKey] = &cachedRare{at: time.Now(), res: res}
	s.cacheMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Cache", "miss")
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// rateAllow caps each host_tag at ~50 MB/min. Returns false when the
// host has exceeded the cap in the current 60s window.
func (s *Server) rateAllow(host string, bytes int) bool {
	const capBytes = 50 * 1024 * 1024
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	if time.Since(s.rateWindow) > time.Minute {
		s.rateBucket = map[string]int{}
		s.rateWindow = time.Now()
	}
	if s.rateBucket[host]+bytes > capBytes {
		return false
	}
	s.rateBucket[host] += bytes
	return true
}

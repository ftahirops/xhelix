// my-net-gate — the visualisation + UX sibling for xhelix.
//
// Runs as the *logged-in user*, not root. Subscribes to xhelix's
// LocalAPI (over the per-user-readable Unix socket) and exposes
// a small HTTP+JSON surface on 127.0.0.1:13443 that the
// apps/ui/ frontend consumes.
//
// Privilege separation: xhelix (root) owns detection + chain;
// my-net-gate (user) owns visualisation + alert review. Failure
// of my-net-gate cannot affect xhelix's detection path.
//
// Wire model: this binary is the *adapter*. The UI hits HTTP;
// the adapter forwards as LocalAPI Call/Stream. No business
// logic here beyond auth + caching.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xhelix/xhelix/pkg/localapi"
)

func main() {
	var (
		socketPath = flag.String("socket", "/run/xhelix.sock", "xhelix LocalAPI socket")
		listenAddr = flag.String("listen", "127.0.0.1:13443", "HTTP listen address (use 0.0.0.0:13443 to expose remotely; pair with --allow-ip)")
		cachePath  = flag.String("cache", "", "SQLite cache path (default: $HOME/.cache/xhelix/mynetgate.db)")
		allowIPs   = flag.String("allow-ip", "127.0.0.1/32,::1/128", "comma-separated IPs/CIDRs allowed to connect; everything else gets 403")
		allowOrig  = flag.String("allow-origin", "", "comma-separated CORS origins allowed (empty = echo Origin only when remote IP is allowlisted)")
	)
	flag.Parse()

	allowNets, err := parseAllowlist(*allowIPs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "my-net-gate: invalid --allow-ip: %v\n", err)
		os.Exit(2)
	}
	allowOrigins := parseOriginList(*allowOrig)

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	log.Info("my-net-gate starting", "socket", *socketPath, "listen", *listenAddr)

	cp := *cachePath
	if cp == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cp = home + "/.cache/xhelix/mynetgate.db"
			_ = os.MkdirAll(home+"/.cache/xhelix", 0o755)
		} else {
			cp = "/tmp/mynetgate.db"
		}
	}
	cache, err := OpenCache(cp, log)
	if err != nil {
		log.Warn("cache open failed; running without cache", "err", err)
	} else {
		log.Info("cache ready", "path", cp)
	}

	srv := &server{socketPath: *socketPath, log: log, cache: cache}
	go runCachePruner(srv)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ping", srv.ping)
	mux.HandleFunc("/api/v1/history", srv.history)
	mux.HandleFunc("/api/v1/history/activity/", srv.activity)
	mux.HandleFunc("/api/v1/processes", srv.processes)
	mux.HandleFunc("/api/v1/process/", srv.process)
	mux.HandleFunc("/api/v1/alerts", srv.alerts)
	mux.HandleFunc("/api/v1/suppression", srv.suppression)
	mux.HandleFunc("/api/v1/enforce", srv.enforce)
	mux.HandleFunc("/api/v1/intent/poll", srv.intentPoll)
	mux.HandleFunc("/api/v1/intent/decide", srv.intentDecide)
	mux.HandleFunc("/api/v1/stream", srv.stream)
	mux.HandleFunc("/api/v1/verdict/explain", srv.verdictExplain)
	mux.HandleFunc("/api/v1/policy", srv.policy)
	mux.HandleFunc("/api/v1/policy/telemetry", srv.policyTelemetry)
	mux.HandleFunc("/api/v1/policy/app", srv.policyApp)
	mux.HandleFunc("/api/v1/enforce/status", srv.enforceStatus)
	mux.HandleFunc("/api/v1/enforce/arm", srv.enforceArm)
	mux.HandleFunc("/api/v1/enforce/disarm", srv.enforceDisarm)
	mux.Handle("/", http.FileServer(http.Dir("apps/ui/static")))

	httpSrv := &http.Server{
		Addr:              *listenAddr,
		Handler:           withIPAllowlist(allowNets, log, withCORS(allowOrigins, mux)),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Info("access control", "allow_ip", *allowIPs, "allow_origin", *allowOrig)

	go func() {
		log.Info("http listening", "addr", *listenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("http listen failed", "err", err)
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Info("shutdown")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
}

// server is the HTTP-to-LocalAPI adapter.
type server struct {
	socketPath string
	log        *slog.Logger
	cache      *Cache
}

func runCachePruner(s *server) {
	if s.cache == nil {
		return
	}
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for range t.C {
		_ = s.cache.Prune(context.Background(), 7*24*time.Hour)
	}
}

func (s *server) ping(w http.ResponseWriter, r *http.Request) {
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		http.Error(w, "xhelix socket unreachable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	out := map[string]any{"ok": true, "socket": s.socketPath}
	_ = json.NewEncoder(w).Encode(out)
}

func (s *server) history(w http.ResponseWriter, r *http.Request) {
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		// Daemon unreachable — serve from cache if available.
		if s.cache != nil {
			if cached := s.cache.LoadActivities(); cached != nil {
				w.Header().Set("X-Xhelix-Stale", "true")
				_, _ = w.Write(cached)
				return
			}
		}
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	var resp any
	err = c.Call("history.list", map[string]any{
		"since":  r.URL.Query().Get("since"),
		"filter": r.URL.Query().Get("filter"),
	}, &resp)
	if err != nil {
		// Daemon errored — try cache fallback.
		if s.cache != nil {
			if cached := s.cache.LoadActivities(); cached != nil {
				w.Header().Set("X-Xhelix-Stale", "true")
				_, _ = w.Write(cached)
				return
			}
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// Fresh response — cache it for the next outage.
	if s.cache != nil {
		if raw, e := json.Marshal(resp); e == nil {
			_ = s.cache.StoreActivities(raw)
		}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *server) processes(w http.ResponseWriter, r *http.Request) {
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	var resp any
	if err := c.Call("processes.list", nil, &resp); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *server) process(w http.ResponseWriter, r *http.Request) {
	// Path forms: /api/v1/process/<pid>  or  /api/v1/process/<pid>/investigate
	rest := r.URL.Path[len("/api/v1/process/"):]
	if rest == "" {
		http.Error(w, "missing pid", http.StatusBadRequest)
		return
	}
	pidStr, action, _ := strings.Cut(rest, "/")
	pid64, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		http.Error(w, "bad pid", http.StatusBadRequest)
		return
	}
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	var resp any
	switch action {
	case "":
		err = c.Call("process.detail", map[string]uint32{"pid": uint32(pid64)}, &resp)
	case "investigate":
		secs := 5
		if s := r.URL.Query().Get("seconds"); s != "" {
			if n, e := strconv.Atoi(s); e == nil && n > 0 && n <= 30 {
				secs = n
			}
		}
		err = c.Call("process.investigate", map[string]any{"pid": uint32(pid64), "seconds": secs}, &resp)
	default:
		http.Error(w, "unknown action", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// withCORS echoes the request Origin only when it is in the
// configured allow-list. An empty allow-list disables CORS entirely
// (the SPA is served same-origin, so CORS is not needed by default).
func withCORS(allowed []string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && originAllowed(origin, allowed) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// withIPAllowlist drops requests whose peer IP is not in `allowed`.
// We honor X-Forwarded-For only when the immediate peer is itself in
// the allowlist (i.e. a trusted reverse proxy you put in front of
// mynetgate). The default allowlist is 127.0.0.1/::1, so by default
// no header is trusted.
func withIPAllowlist(allowed []*net.IPNet, log *slog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer := peerIP(r.RemoteAddr)
		if peer == nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !ipAllowed(peer, allowed) {
			log.Warn("blocked non-allowlisted client", "remote", r.RemoteAddr, "path", r.URL.Path)
			http.Error(w, "forbidden: client IP not in --allow-ip", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func parseAllowlist(spec string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range strings.Split(spec, ",") {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				if ip.To4() != nil {
					s += "/32"
				} else {
					s += "/128"
				}
			}
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", raw, err)
		}
		out = append(out, ipnet)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("allow-list empty")
	}
	return out, nil
}

func parseOriginList(spec string) []string {
	var out []string
	for _, raw := range strings.Split(spec, ",") {
		s := strings.TrimSpace(raw)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == origin {
			return true
		}
	}
	return false
}

func peerIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(host)
}

func ipAllowed(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// _ = fmt.Sprintf  // keep fmt-import warning quiet when not used
var _ = fmt.Sprintf

// activity returns a single Activity row's drill-down detail.
func (s *server) activity(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/v1/history/activity/"):]
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	var resp any
	if err := c.Call("history.activity", map[string]string{"id": id}, &resp); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// alerts lists currently-open alerts.
func (s *server) alerts(w http.ResponseWriter, r *http.Request) {
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		if s.cache != nil {
			if cached := s.cache.LoadAlerts(); cached != nil {
				w.Header().Set("X-Xhelix-Stale", "true")
				_, _ = w.Write(cached)
				return
			}
		}
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	var resp any
	if err := c.Call("alerts.list", nil, &resp); err != nil {
		if s.cache != nil {
			if cached := s.cache.LoadAlerts(); cached != nil {
				w.Header().Set("X-Xhelix-Stale", "true")
				_, _ = w.Write(cached)
				return
			}
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if s.cache != nil {
		if raw, e := json.Marshal(resp); e == nil {
			_ = s.cache.StoreAlerts(raw)
		}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// suppression POSTs a new suppression entry.
func (s *server) suppression(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	var resp any
	if err := c.Call("suppression.add", in, &resp); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// enforce POSTs an enforcement action (quarantine / restore / kill).
func (s *server) enforce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	var resp any
	if err := c.Call("enforce.action", in, &resp); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// intentPoll long-polls the daemon for pending intent prompts.
// The daemon's hook returns immediately with {id:"", ...} when
// nothing is pending.
func (s *server) intentPoll(w http.ResponseWriter, r *http.Request) {
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	var resp any
	if err := c.Call("intent.poll", nil, &resp); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// intentDecide returns the operator's decision for a pending prompt.
func (s *server) intentDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	var resp any
	if err := c.Call("intent.decide", in, &resp); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// policy is a GET/POST shim for the daemon's policy.get / policy.save
// methods. GET returns the current YAML + settings; POST {yaml: ...}
// saves it back. Save is immediate; the daemon flushes its verdict
// cache so rules apply to the next flow.
func (s *server) policy(w http.ResponseWriter, r *http.Request) {
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	var resp any
	switch r.Method {
	case http.MethodGet:
		if err := c.Call("policy.get", nil, &resp); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	case http.MethodPost:
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := c.Call("policy.save", in, &resp); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	default:
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// policyTelemetry toggles the block-all-telemetry flag.
// POST {enabled: true|false}. Persisted to disk.
func (s *server) policyTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	var resp any
	if err := c.Call("policy.toggle_telemetry", in, &resp); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// policyApp adds or removes one per-process rule.
func (s *server) policyApp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.proxyCall(w, r, "policy.upsert_app", false, in)
}

// enforceStatus, enforceArm, enforceDisarm proxy to the daemon's
// enforce.* handlers. Arm body: {"soak_seconds": N (optional)}.
func (s *server) enforceStatus(w http.ResponseWriter, r *http.Request) {
	s.proxyCall(w, r, "enforce.status", true, nil)
}

func (s *server) enforceArm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	s.proxyCall(w, r, "enforce.arm", false, in)
}

func (s *server) enforceDisarm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	s.proxyCall(w, r, "enforce.disarm", false, nil)
}

func (s *server) proxyCall(w http.ResponseWriter, r *http.Request, method string, requireGet bool, params any) {
	if requireGet && r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	var resp any
	if err := c.Call(method, params, &resp); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// verdictExplain proxies POST /api/v1/verdict/explain → daemon's
// verdict.explain handler. Body is a JSON object with any of:
// {pid, exe, exe_sha, comm, dst_ip, dst_port, dns_name, sni, country, asn}.
func (s *server) verdictExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	var resp any
	if err := c.Call("verdict.explain", in, &resp); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// stream proxies the daemon's stream.events streamer onto an SSE
// HTTP response. The UI's "live" tab subscribes via EventSource.
func (s *server) stream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	c, err := localapi.Dial(s.socketPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer c.Close()
	ctx := r.Context()
	err = c.Stream(ctx, "stream.events", nil, func(raw json.RawMessage) error {
		_, werr := fmt.Fprintf(w, "data: %s\n\n", raw)
		if werr != nil {
			return werr
		}
		flusher.Flush()
		return nil
	})
	if err != nil && err != context.Canceled {
		s.log.Debug("stream ended", "err", err)
	}
}

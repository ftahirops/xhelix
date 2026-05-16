// Package hub implements xhelix's multi-host correlation server and
// its agent-side push client.
//
// Architecture:
//
//   agent <─ HTTP POST events ─> hub
//   hub maintains a fleet-wide deduped CEP engine
//   alerts emerge when (host_a + host_b) match a multi-host pattern
//
// The hub is mTLS-friendly (server.crt, client.crt) but TLS is
// optional for v0.x. Traffic is JSON-lines for debuggability;
// future revisions will offer a binary protocol once the schema
// stabilises.
package hub

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/correlator"
	"github.com/xhelix/xhelix/pkg/model"
)

// Server is the hub HTTP service.
type Server struct {
	Addr string

	mu          sync.Mutex
	srv         *http.Server
	corr        *correlator.Engine
	hosts       map[string]*hostState
	emit        func(model.Alert)
	startedAt   time.Time
	alertsTotal atomic.Uint64
	eventsTotal atomic.Uint64
}

type hostState struct {
	HostID    string
	LastSeen  time.Time
	EventRate uint64
}

// NewServer creates a hub configured at addr (e.g., ":7443"). The
// emit callback is invoked when a fleet-wide correlation completes.
func NewServer(addr string, emit func(model.Alert)) (*Server, error) {
	if emit == nil {
		emit = func(model.Alert) {}
	}
	s := &Server{
		Addr:      addr,
		hosts:     map[string]*hostState{},
		emit:      emit,
		startedAt: time.Now().UTC(),
	}
	corr, err := correlator.New(func(a model.Alert) {
		s.alertsTotal.Add(1)
		s.emit(a)
	})
	if err != nil {
		return nil, err
	}
	s.corr = corr
	mux := http.NewServeMux()
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/hosts", s.handleHosts)
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

// LoadCorrelations applies multi-host correlation rules to the hub.
func (s *Server) LoadCorrelations(rules []correlator.Rule) error {
	return s.corr.Load(rules)
}

// Start blocks serving HTTP.
func (s *Server) Start() error { return s.srv.ListenAndServe() }

// Stop drains in-flight requests.
func (s *Server) Stop(ctx context.Context) error { return s.srv.Shutdown(ctx) }

// handleEvents accepts JSON-lines push from agents.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	host := r.Header.Get("X-Xhelix-Host")
	if host == "" {
		host = r.RemoteAddr
	}
	scanner := bufio.NewScanner(r.Body)
	scanner.Buffer(make([]byte, 0, 65536), 1<<20)
	count := 0
	for scanner.Scan() {
		var ev model.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		if ev.Host == "" {
			ev.Host = host
		}
		s.corr.Ingest(r.Context(), ev)
		count++
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	hs, ok := s.hosts[host]
	if !ok {
		hs = &hostState{HostID: host}
		s.hosts[host] = hs
	}
	hs.LastSeen = time.Now().UTC()
	hs.EventRate += uint64(count)
	s.mu.Unlock()

	s.eventsTotal.Add(uint64(count))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted": count,
		"host":     host,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"events_total":  s.eventsTotal.Load(),
		"alerts_total":  s.alertsTotal.Load(),
		"hosts":         len(s.hosts),
		"sessions":      s.corr.SessionCount(),
		"uptime_seconds": int64(time.Since(s.startedAt).Seconds()),
	})
}

func (s *Server) handleHosts(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := make([]hostState, 0, len(s.hosts))
	for _, h := range s.hosts {
		out = append(out, *h)
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// Client is the agent-side push API.
type Client struct {
	Endpoint string
	HostID   string
	HTTP     *http.Client

	mu     sync.Mutex
	buffer []model.Event
}

// NewClient constructs a hub push client.
func NewClient(endpoint, hostID string) *Client {
	return &Client{
		Endpoint: endpoint,
		HostID:   hostID,
		HTTP:     &http.Client{Timeout: 10 * time.Second},
	}
}

// Push submits one event.
//
// Events are buffered; Flush is called on each Push when the buffer
// reaches BatchSize, or by the caller on shutdown.
func (c *Client) Push(ev model.Event) {
	c.mu.Lock()
	c.buffer = append(c.buffer, ev)
	flush := len(c.buffer) >= 64
	var batch []model.Event
	if flush {
		batch = c.buffer
		c.buffer = nil
	}
	c.mu.Unlock()
	if flush {
		_ = c.send(batch)
	}
}

// Flush ships the current buffer.
func (c *Client) Flush() error {
	c.mu.Lock()
	batch := c.buffer
	c.buffer = nil
	c.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	return c.send(batch)
}

func (c *Client) send(batch []model.Event) error {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		enc := json.NewEncoder(pw)
		for _, ev := range batch {
			_ = enc.Encode(ev)
		}
	}()
	req, err := http.NewRequest(http.MethodPost, c.Endpoint+"/api/events", pr)
	if err != nil {
		return err
	}
	req.Header.Set("X-Xhelix-Host", c.HostID)
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hub: HTTP %d", resp.StatusCode)
	}
	return nil
}

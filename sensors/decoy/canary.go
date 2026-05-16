package decoy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// Token is a canary token tied to a persona / honey file.
type Token struct {
	ID      string
	Type    string // "aws-creds" | "env-file" | ...
	Persona string
}

// CanaryReceiver is a tiny HTTP server that fires a Critical event
// when an embedded canary is used externally (e.g., the AWS API
// receives the fake key, the Slack webhook is POSTed, the embedded
// internal URL is fetched).
//
// Operators expose this receiver on a host outside the protected
// fleet. Tokens carry the URL pattern /<id> so any IP/hostname
// works; the receiver only inspects the path component.
type CanaryReceiver struct {
	addr   string
	host   string
	tokens map[string]Token

	mu      sync.Mutex
	out     chan<- model.Event
	srv     *http.Server
	running atomic.Bool
	hits    atomic.Uint64
	bound   string
}

// NewCanaryReceiver returns a receiver listening on addr.
//
// addr "" picks a random local port — useful in tests.
func NewCanaryReceiver(addr, host string, tokens []Token) *CanaryReceiver {
	m := make(map[string]Token, len(tokens))
	for _, t := range tokens {
		m[t.ID] = t
	}
	return &CanaryReceiver{addr: addr, host: host, tokens: m}
}

// Name implements sensors.Sensor.
func (r *CanaryReceiver) Name() string { return "decoy.canary" }

// Start implements sensors.Sensor.
func (r *CanaryReceiver) Start(ctx context.Context, out chan<- model.Event) error {
	if !r.running.CompareAndSwap(false, true) {
		return errors.New("canary: already started")
	}
	r.mu.Lock()
	r.out = out
	r.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/", r.handle)

	addr := r.addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}

	ln, err := listenAddr(addr)
	if err != nil {
		r.running.Store(false)
		return err
	}
	r.mu.Lock()
	r.srv = srv
	r.bound = ln.Addr().String()
	r.mu.Unlock()

	go func() { _ = srv.Serve(ln) }()
	return nil
}

// Stop implements sensors.Sensor.
func (r *CanaryReceiver) Stop(ctx context.Context) error {
	if !r.running.CompareAndSwap(true, false) {
		return nil
	}
	r.mu.Lock()
	srv := r.srv
	r.srv = nil
	r.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

// Health implements sensors.Sensor.
func (r *CanaryReceiver) Health() sensors.Health {
	return sensors.Health{Healthy: r.running.Load()}
}

// Addr returns the bound address (after Start).
func (r *CanaryReceiver) Addr() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bound
}

// Hits returns how many canaries have triggered.
func (r *CanaryReceiver) Hits() uint64 { return r.hits.Load() }

// handle is the HTTP entry point. The path's first segment is the
// token ID; unknown IDs return a generic 200 so an attacker cannot
// distinguish a canary from a real endpoint.
func (r *CanaryReceiver) handle(w http.ResponseWriter, req *http.Request) {
	id := pathFirstSegment(req.URL.Path)
	r.mu.Lock()
	tok, ok := r.tokens[id]
	out := r.out
	r.mu.Unlock()

	if ok {
		r.hits.Add(1)
		ev := model.NewEvent("decoy.canary", model.SeverityCritical)
		ev.Host = r.host
		ev.Tags["token_used"] = "true"
		ev.Tags["token_id"] = id
		ev.Tags["token_type"] = tok.Type
		ev.Tags["persona"] = tok.Persona
		ev.Tags["src"] = req.RemoteAddr
		ev.Tags["user_agent"] = req.UserAgent()
		ev.Tags["method"] = req.Method
		ev.Tags["path"] = req.URL.Path
		if out != nil {
			select {
			case out <- ev:
			case <-time.After(50 * time.Millisecond):
			}
		}
	}

	// Always return a plausible response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func pathFirstSegment(p string) string {
	for len(p) > 0 && p[0] == '/' {
		p = p[1:]
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return p
}

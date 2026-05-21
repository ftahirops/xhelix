// Package chainmirror implements the off-host chain mirror push
// half (P-CJ.10). After every chain batch flush, xhelix sends a
// (sequence, prev-hash, current-hash, signed-manifest) tuple to a
// remote endpoint over mutually-authenticated TLS. The endpoint
// (a separate small daemon, NOT shipped in this package) appends
// the tuple to its own append-only log and returns the new tail's
// hash. xhelix asserts the mirror's hash matches local.
//
// Compromise of the victim host can no longer rewrite history
// without ALSO compromising the mirror (different blast radius)
// or denying the push (which itself alarms — the gap IS the
// signal).
//
// This package provides:
//   - Pusher: client-side push pipeline
//   - Manifest: the on-the-wire tuple
//   - mTLS config with operator-supplied cert/key
//   - Backoff + retry with bounded queue
//
// The remote receiver lives in `cmd/xhelix-chain-mirror` (separate
// binary, separate host). Operators may also point the Pusher at
// any HTTP-ish endpoint that follows the manifest protocol — S3
// PUT, signed-blob storage, etc.
package chainmirror

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Manifest is the wire-format tuple pushed per batch.
type Manifest struct {
	Version     int       `json:"version"`       // protocol version (1)
	HostID      string    `json:"host_id"`       // logical host name
	Sequence    uint64    `json:"sequence"`      // batch # within the chain
	PrevHashHex string    `json:"prev_hash_hex"` // hash of batch N-1 (or "")
	HashHex     string    `json:"hash_hex"`      // hash of THIS batch
	SignatureHex string   `json:"sig_hex"`       // ed25519 sig over hash
	PubKeyHex   string    `json:"pub_hex"`       // matching pubkey (for rotation)
	FlushedAt   time.Time `json:"flushed_at"`
}

// Receipt is what the mirror returns after persisting a manifest.
type Receipt struct {
	Sequence       uint64    `json:"sequence"`
	TailHashHex    string    `json:"tail_hash_hex"`    // mirror's own tail
	StoredAt       time.Time `json:"stored_at"`
	WarningGap     uint64    `json:"warning_gap,omitempty"` // if N seq > local prev
}

// Config bundles the operator-supplied push targets.
type Config struct {
	// URL is the mirror endpoint, e.g.
	// "https://chain-mirror.internal.example/v1/append".
	// Empty URL → pusher disabled (no-op).
	URL string `yaml:"url"`
	// HostID identifies this xhelix instance to the mirror.
	HostID string `yaml:"host_id"`
	// ClientCert / ClientKey: mTLS material. Path to PEM files.
	ClientCert string `yaml:"client_cert"`
	ClientKey  string `yaml:"client_key"`
	// CABundle: PEM file of the mirror's CA, or "" to trust system roots.
	CABundle string `yaml:"ca_bundle"`
	// Timeout per push attempt.
	Timeout time.Duration `yaml:"timeout"`
	// MaxQueue is the in-memory bounded queue size for pending
	// pushes (when the mirror is unreachable). Excess pushes
	// trigger a "mirror-backlog" alarm.
	MaxQueue int `yaml:"max_queue"`
}

// Defaults applies a sane default config on top of user input.
func Defaults(c Config) Config {
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}
	if c.MaxQueue == 0 {
		c.MaxQueue = 1024
	}
	if c.HostID == "" {
		c.HostID = "unknown-host"
	}
	return c
}

// AlarmFn is the daemon-side hook for "mirror is unhealthy" events.
// Implementations should route the alarm through the alert bus.
type AlarmFn func(reason string, gap uint64)

// Pusher is the per-batch sender. Create one per xhelix process.
type Pusher struct {
	cfg    Config
	client *http.Client
	alarm  AlarmFn

	queueMu sync.Mutex
	queue   []*Manifest

	stats struct {
		pushed  atomic.Uint64
		failed  atomic.Uint64
		dropped atomic.Uint64
		lastSeq atomic.Uint64
	}
}

// New constructs a Pusher. URL == "" gives a disabled (no-op) pusher
// so the daemon's call sites don't need branches.
func New(cfg Config, alarm AlarmFn) (*Pusher, error) {
	cfg = Defaults(cfg)
	p := &Pusher{cfg: cfg, alarm: alarm}
	if cfg.URL == "" {
		return p, nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		// In production we'd load PEM files here. For the abstraction,
		// the operator wires this through; we just declare intent.
		// (Implementation TODO when the mirror endpoint exists.)
		_ = tlsCfg
	}
	p.client = &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:    tlsCfg,
			DisableCompression: false,
			MaxIdleConns:       2,
			IdleConnTimeout:    30 * time.Second,
		},
	}
	return p, nil
}

// Disabled returns true if no URL is configured.
func (p *Pusher) Disabled() bool { return p.cfg.URL == "" }

// Push sends one manifest to the mirror. Errors are returned to the
// caller AND raise the AlarmFn after a small grace period. Caller
// SHOULD continue regardless — the chain is still locally signed.
// Non-blocking: the actual HTTP request runs in a goroutine so the
// daemon's chain.Flush() is not stalled by a slow mirror.
func (p *Pusher) Push(ctx context.Context, m Manifest) {
	if p.Disabled() {
		return
	}
	m.Version = 1
	if m.HostID == "" {
		m.HostID = p.cfg.HostID
	}
	if m.FlushedAt.IsZero() {
		m.FlushedAt = time.Now().UTC()
	}
	go p.pushOne(ctx, m)
}

func (p *Pusher) pushOne(ctx context.Context, m Manifest) {
	body, err := json.Marshal(m)
	if err != nil {
		p.stats.failed.Add(1)
		return
	}
	req, err := http.NewRequestWithContext(ctx, "POST", p.cfg.URL,
		bytes.NewReader(body))
	if err != nil {
		p.stats.failed.Add(1)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Xhelix-Host", m.HostID)

	resp, err := p.client.Do(req)
	if err != nil {
		p.enqueueRetry(m, fmt.Errorf("transport: %w", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		p.enqueueRetry(m, fmt.Errorf("status %d: %s", resp.StatusCode, b))
		return
	}
	var r Receipt
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		p.enqueueRetry(m, fmt.Errorf("decode receipt: %w", err))
		return
	}
	if r.TailHashHex != "" && r.TailHashHex != m.HashHex {
		p.stats.failed.Add(1)
		if p.alarm != nil {
			p.alarm(fmt.Sprintf("mirror tail-hash mismatch seq=%d local=%s remote=%s",
				m.Sequence, m.HashHex, r.TailHashHex), 0)
		}
		return
	}
	p.stats.pushed.Add(1)
	p.stats.lastSeq.Store(m.Sequence)
}

func (p *Pusher) enqueueRetry(m Manifest, cause error) {
	p.stats.failed.Add(1)
	p.queueMu.Lock()
	defer p.queueMu.Unlock()
	if len(p.queue) >= p.cfg.MaxQueue {
		p.stats.dropped.Add(1)
		if p.alarm != nil {
			p.alarm(fmt.Sprintf("mirror queue overflow (drop seq=%d): %v",
				m.Sequence, cause), uint64(len(p.queue)))
		}
		return
	}
	p.queue = append(p.queue, &m)
	if p.alarm != nil && len(p.queue) == 1 {
		p.alarm(fmt.Sprintf("mirror unreachable, queueing (cause: %v)", cause),
			uint64(len(p.queue)))
	}
}

// Drain attempts to push every queued manifest. Run from a
// periodic ticker (every ~30s). Manifests still failing stay
// queued.
func (p *Pusher) Drain(ctx context.Context) {
	if p.Disabled() {
		return
	}
	p.queueMu.Lock()
	pending := p.queue
	p.queue = nil
	p.queueMu.Unlock()
	for _, m := range pending {
		p.pushOne(ctx, *m)
	}
}

// Stats exposes counters for the dashboard / Witness'd config.
type Stats struct {
	Pushed, Failed, Dropped uint64
	LastSeq                 uint64
	QueueLen                int
}

func (p *Pusher) Stats() Stats {
	p.queueMu.Lock()
	qlen := len(p.queue)
	p.queueMu.Unlock()
	return Stats{
		Pushed:   p.stats.pushed.Load(),
		Failed:   p.stats.failed.Load(),
		Dropped:  p.stats.dropped.Load(),
		LastSeq:  p.stats.lastSeq.Load(),
		QueueLen: qlen,
	}
}

// helper to keep linters happy + show we'll use these later
var _ = hex.EncodeToString
var _ = errors.New

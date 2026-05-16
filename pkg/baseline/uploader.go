package baseline

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Uploader ships windows to a remote xhub. It is fail-soft: failed
// uploads are queued to disk so they retry across restarts; the
// agent never blocks waiting on the hub.
//
// Wire format is identical to baselinehub.Upload (we use a local
// definition to avoid importing the hub package — keeps the agent's
// build graph small).
type Uploader struct {
	cfg      UploaderConfig
	log      *slog.Logger
	client   *http.Client

	mu       sync.Mutex
	queueDir string

	stats struct {
		queued   atomic.Uint64
		uploaded atomic.Uint64
		failed   atomic.Uint64
		bytes    atomic.Uint64
	}
}

// UploaderConfig is the public knobs.
type UploaderConfig struct {
	URL              string        // https://xhub.example.com:18444
	HostTag          string
	RoleTag          string
	XhelixVer        string
	AuthToken        string
	UploadInterval   time.Duration // default 5m
	QueueDir         string        // for failed uploads
	TLSInsecureSkipVerify bool
	Logger           *slog.Logger
}

// uploadEnvelope mirrors baselinehub.Upload. Defined locally to keep
// pkg/baseline independent of pkg/baselinehub.
type uploadEnvelope struct {
	HostTag    string    `json:"host_tag"`
	RoleTag    string    `json:"role_tag,omitempty"`
	XhelixVer  string    `json:"xhelix_ver,omitempty"`
	UploadedAt time.Time `json:"uploaded_at"`
	Windows    []*Window `json:"windows"`
}

// NewUploader returns an unstarted uploader. Call Start() with the
// daemon's context to begin the retry loop.
func NewUploader(cfg UploaderConfig) (*Uploader, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("uploader: empty URL")
	}
	if cfg.HostTag == "" {
		return nil, fmt.Errorf("uploader: empty HostTag")
	}
	if cfg.UploadInterval == 0 {
		cfg.UploadInterval = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.QueueDir != "" {
		if err := os.MkdirAll(cfg.QueueDir, 0o700); err != nil {
			return nil, err
		}
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.TLSInsecureSkipVerify}
	return &Uploader{
		cfg:      cfg,
		log:      cfg.Logger,
		queueDir: cfg.QueueDir,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
				DisableKeepAlives: false,
			},
		},
	}, nil
}

// Push enqueues windows for upload. Non-blocking: writes them to the
// on-disk retry queue and returns. The retry loop handles actual
// HTTP delivery.
func (u *Uploader) Push(windows []*Window) error {
	if len(windows) == 0 {
		return nil
	}
	if u.queueDir == "" {
		// No queue dir = best-effort in-memory only.
		go u.uploadOnce(windows)
		return nil
	}
	env := uploadEnvelope{
		HostTag:    u.cfg.HostTag,
		RoleTag:    u.cfg.RoleTag,
		XhelixVer:  u.cfg.XhelixVer,
		UploadedAt: time.Now().UTC(),
		Windows:    windows,
	}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	// Nanosecond timestamp + per-process counter so that even rapid
	// systemd restarts within the same UTC second don't collide and
	// silently overwrite a not-yet-uploaded batch from the prior run.
	// O_EXCL ensures any residual collision fails loudly rather than
	// truncating data.
	name := fmt.Sprintf("%s-%d.json",
		time.Now().UTC().Format("20060102T150405.000000000"),
		u.stats.queued.Add(1))
	path := filepath.Join(u.queueDir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// Start launches the retry goroutine.
func (u *Uploader) Start(ctx context.Context) {
	go u.loop(ctx)
}

func (u *Uploader) loop(ctx context.Context) {
	t := time.NewTicker(u.cfg.UploadInterval)
	defer t.Stop()
	// Try once immediately so the first batch ships fast.
	u.flushQueue(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			u.flushQueue(ctx)
		}
	}
}

// flushQueue tries to upload every queued file in age order. Stops
// on the first failure to avoid hammering a down hub. Successfully-
// uploaded files are deleted; failures stay for the next tick.
func (u *Uploader) flushQueue(ctx context.Context) {
	if u.queueDir == "" {
		return
	}
	entries, err := os.ReadDir(u.queueDir)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // alphabetic == chronological for our naming
	for _, name := range names {
		select {
		case <-ctx.Done():
			return
		default:
		}
		path := filepath.Join(u.queueDir, name)
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := u.send(ctx, body); err != nil {
			u.stats.failed.Add(1)
			u.log.Debug("uploader: send failed; will retry", "name", name, "err", err)
			return // back off; don't loop
		}
		_ = os.Remove(path)
		u.stats.uploaded.Add(1)
		u.stats.bytes.Add(uint64(len(body)))
	}
}

// uploadOnce is the no-queue path — fire-and-forget upload of a
// single batch with no retry. Used when QueueDir is empty.
func (u *Uploader) uploadOnce(windows []*Window) {
	env := uploadEnvelope{
		HostTag:    u.cfg.HostTag,
		RoleTag:    u.cfg.RoleTag,
		XhelixVer:  u.cfg.XhelixVer,
		UploadedAt: time.Now().UTC(),
		Windows:    windows,
	}
	body, err := json.Marshal(env)
	if err != nil {
		u.stats.failed.Add(1)
		return
	}
	if err := u.send(context.Background(), body); err != nil {
		u.stats.failed.Add(1)
		u.log.Debug("uploader: oneshot send failed", "err", err)
		return
	}
	u.stats.uploaded.Add(1)
	u.stats.bytes.Add(uint64(len(body)))
}

func (u *Uploader) send(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		u.cfg.URL+"/api/upload", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if u.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+u.cfg.AuthToken)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("hub returned %d", resp.StatusCode)
	}
	return nil
}

// RareEndpoint mirrors baselinehub.RareEndpoint locally so this
// package doesn't import the hub package.
type RareEndpoint struct {
	Binary    string  `json:"binary"`
	Endpoint  string  `json:"endpoint"`
	HostsSeen int     `json:"hosts_seen"`
	TotalHosts int    `json:"total_hosts"`
	Rarity    float64 `json:"rarity"`
}

// rareListResp matches baselinehub.RareList for unmarshalling.
type rareListResp struct {
	Binary       string         `json:"binary"`
	GeneratedAt  time.Time      `json:"generated_at"`
	TotalHosts   int            `json:"total_hosts"`
	RarityCutoff float64        `json:"rarity_cutoff"`
	Rare         []RareEndpoint `json:"rare"`
}

// PullRare fetches the cross-fleet rare-endpoint list for one binary.
// Returns (nil, nil) on a benign error so the caller can degrade
// silently when the hub is down — Phase 3 fleet correlation is
// enrichment, not a hard dependency.
func (u *Uploader) PullRare(ctx context.Context, binary string) ([]RareEndpoint, error) {
	if u.cfg.URL == "" {
		return nil, nil
	}
	endpoint := u.cfg.URL + "/api/rare/?binary=" + urlQueryEscape(binary)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if u.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+u.cfg.AuthToken)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, nil
	}
	var r rareListResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return r.Rare, nil
}

// urlQueryEscape: avoid pulling net/url for one call.
func urlQueryEscape(s string) string {
	const hex = "0123456789ABCDEF"
	out := make([]byte, 0, len(s)+8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			out = append(out, c)
		default:
			out = append(out, '%', hex[c>>4], hex[c&0xf])
		}
	}
	return string(out)
}

// Stats reports uploader counters.
type UploaderStats struct {
	Queued   uint64
	Uploaded uint64
	Failed   uint64
	Bytes    uint64
	QueuedOnDisk int
}

func (u *Uploader) Stats() UploaderStats {
	out := UploaderStats{
		Queued:   u.stats.queued.Load(),
		Uploaded: u.stats.uploaded.Load(),
		Failed:   u.stats.failed.Load(),
		Bytes:    u.stats.bytes.Load(),
	}
	if u.queueDir != "" {
		entries, _ := os.ReadDir(u.queueDir)
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".json" {
				out.QueuedOnDisk++
			}
		}
	}
	return out
}

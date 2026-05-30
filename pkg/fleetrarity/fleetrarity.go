package fleetrarity

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Provider is the read surface the verdict router consults.
type Provider interface {
	Lookup(binary, endpoint string) Rarity
}

// Config configures the hub client.
type Config struct {
	HubURL    string        // e.g. https://xhub:18444 (same as the agent upload URL)
	AuthToken string        // bearer token (same as upload auth)
	MinCohort int           // below this many cohort hosts, rarity is Unknown. Default 5.
	CacheTTL  time.Duration // per-binary RareList cache lifetime. Default 5m.
	Insecure  bool          // TLS skip-verify; mirrors the operator's existing upload config. Default false (secure).
	Timeout   time.Duration // per-request timeout. Default 3s.
}

type cacheEntry struct {
	rareSet    map[string]struct{}
	cohortSize int
	at         time.Time
	ok         bool
}

// Client queries the hub's /api/rare/ endpoint and answers per-endpoint
// rarity, cached by binary. Safe for concurrent use. Degrades to
// Rarity{Known:false} (no effect) on any error or sub-min cohort.
type Client struct {
	cfg  Config
	http *http.Client
	mu   sync.Mutex
	c    map[string]cacheEntry
}

func NewClient(cfg Config) *Client {
	if cfg.MinCohort <= 0 {
		cfg.MinCohort = 5
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	tr := &http.Transport{}
	if cfg.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // mirrors operator's existing upload TLS setting; default is secure
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout, Transport: tr}, c: map[string]cacheEntry{}}
}

func (cl *Client) Lookup(binary, endpoint string) Rarity {
	e := cl.rareSetFor(binary)
	if !e.ok || e.cohortSize < cl.cfg.MinCohort {
		return Rarity{Known: false, CohortSize: e.cohortSize}
	}
	_, rare := e.rareSet[endpoint]
	return Rarity{Known: true, Rare: rare, CohortSize: e.cohortSize}
}

func (cl *Client) rareSetFor(binary string) cacheEntry {
	cl.mu.Lock()
	if e, ok := cl.c[binary]; ok && time.Since(e.at) < cl.cfg.CacheTTL {
		cl.mu.Unlock()
		return e
	}
	cl.mu.Unlock()
	e := cl.fetch(binary)
	cl.mu.Lock()
	cl.c[binary] = e
	cl.mu.Unlock()
	return e
}

func (cl *Client) fetch(binary string) cacheEntry {
	u := cl.cfg.HubURL + "/api/rare/?binary=" + url.QueryEscape(binary)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return cacheEntry{at: time.Now(), ok: false}
	}
	if cl.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+cl.cfg.AuthToken)
	}
	resp, err := cl.http.Do(req)
	if err != nil {
		return cacheEntry{at: time.Now(), ok: false}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return cacheEntry{at: time.Now(), ok: false}
	}
	var rl struct {
		TotalHosts int `json:"total_hosts"`
		Rare       []struct {
			Endpoint string `json:"endpoint"`
		} `json:"rare"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rl); err != nil {
		return cacheEntry{at: time.Now(), ok: false}
	}
	set := make(map[string]struct{}, len(rl.Rare))
	for _, r := range rl.Rare {
		set[r.Endpoint] = struct{}{}
	}
	return cacheEntry{rareSet: set, cohortSize: rl.TotalHosts, at: time.Now(), ok: true}
}

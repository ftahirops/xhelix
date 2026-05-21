// Package intel provides threat-intel feed ingestion for xhelix.
//
// It downloads and refreshes IP reputation lists from public feeds
// (Spamhaus DROP, emergingthreats, etc.) and populates the eBPF
// bad_ips map so the agent can drop or flag known-malicious traffic.
package intel

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Feed is one threat-intel source.
type Feed struct {
	Name    string
	URL     string
	Type    string // "drop" | "reputation" | "domain"
	Refresh time.Duration
}

// Manager orchestrates multiple feeds.
type Manager struct {
	feeds  []Feed
	client *http.Client
	log    *slog.Logger
	badIPs map[string]struct{}
	mu     sync.RWMutex
	stopCh chan struct{}
}

// DefaultFeeds is the built-in set of free threat-intel sources.
var DefaultFeeds = []Feed{
	{
		Name:    "spamhaus-drop",
		URL:     "https://www.spamhaus.org/drop/drop.txt",
		Type:    "drop",
		Refresh: 24 * time.Hour,
	},
	{
		Name:    "spamhaus-edrop",
		URL:     "https://www.spamhaus.org/drop/edrop.txt",
		Type:    "drop",
		Refresh: 24 * time.Hour,
	},
}

// NewManager creates a manager with the given feeds.
func NewManager(feeds []Feed, cacheDir string, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return &Manager{
		feeds:  feeds,
		client: &http.Client{Timeout: 30 * time.Second},
		log:    log,
		badIPs: map[string]struct{}{},
		stopCh: make(chan struct{}),
	}
}

// Start begins periodic refresh of all feeds.
func (m *Manager) Start(ctx context.Context) {
	// Immediate first refresh
	m.refreshAll(ctx)

	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.stopCh:
				return
			case <-ticker.C:
				m.refreshAll(ctx)
			}
		}
	}()
}

// Stop halts refresh.
func (m *Manager) Stop() {
	close(m.stopCh)
}

// BadIPs returns a snapshot of currently known-bad IPs.
func (m *Manager) BadIPs() []net.IP {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]net.IP, 0, len(m.badIPs))
	for ipStr := range m.badIPs {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

// IsBad returns true if ip is in the threat-intel set.
func (m *Manager) IsBad(ip net.IP) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.badIPs[ip.String()]
	return ok
}

func (m *Manager) refreshAll(ctx context.Context) {
	for _, f := range m.feeds {
		if err := m.refreshFeed(ctx, f); err != nil {
			m.log.Warn("intel refresh failed", "feed", f.Name, "err", err)
		} else {
			m.log.Info("intel refreshed", "feed", f.Name)
		}
	}
}

func (m *Manager) refreshFeed(ctx context.Context, f Feed) error {
	req, err := http.NewRequestWithContext(ctx, "GET", f.URL, nil)
	if err != nil {
		return err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		// Spamhaus format: "1.2.3.0/24 ; SBL12345"
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		cidr := fields[0]
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try plain IP
			ip = net.ParseIP(cidr)
			if ip == nil {
				continue
			}
		}
		m.badIPs[ip.String()] = struct{}{}
	}
	return scanner.Err()
}

// AddStatic seeds the bad-IP set from a slice of literal IP strings.
// Used to bake in known-malicious indicators (campaign C2 servers,
// commodity-malware infrastructure) so the rule fires without
// waiting for an external feed refresh. Idempotent.
//
// Invalid entries are silently ignored — these files are operator-
// editable and a typo shouldn't stop the daemon.
func (m *Manager) AddStatic(ips []string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	added := 0
	for _, s := range ips {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, exists := m.badIPs[key]; !exists {
			m.badIPs[key] = struct{}{}
			added++
		}
	}
	return added
}

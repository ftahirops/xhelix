package destclass

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Feed is one CIDR source the syncer pulls from periodically.
type Feed struct {
	Name  string         // "aws", "cloudflare", "gcp"
	Class Class          // ClassCloudProvider or ClassCDN
	URL   string         // source URL
	Parse func([]byte) ([]string, error)
}

// DefaultFeeds is the safe set of public, well-known feeds. All HTTPS,
// all returning IPv4 + IPv6 CIDRs.
func DefaultFeeds() []Feed {
	return []Feed{
		{
			Name:  "aws",
			Class: ClassCloudProvider,
			URL:   "https://ip-ranges.amazonaws.com/ip-ranges.json",
			Parse: parseAWS,
		},
		{
			Name:  "cloudflare-v4",
			Class: ClassCDN,
			URL:   "https://www.cloudflare.com/ips-v4",
			Parse: parseLineList,
		},
		{
			Name:  "cloudflare-v6",
			Class: ClassCDN,
			URL:   "https://www.cloudflare.com/ips-v6",
			Parse: parseLineList,
		},
	}
}

// SyncOnce fetches every feed, parses, and applies the union to the
// classifier. Errors per-feed are returned together; one bad feed
// doesn't break the others. Existing built-in CIDRs are preserved as
// a floor (we union, not overwrite).
func SyncOnce(ctx context.Context, c *Classifier, feeds []Feed, hc *http.Client) []error {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	cloud := append([]string{}, defaultCloudCIDRs()...)
	cdn := append([]string{}, defaultCDNCIDRs()...)
	var errs []error
	for _, f := range feeds {
		cidrs, err := fetchOne(ctx, hc, f)
		if err != nil {
			errs = append(errs, fmt.Errorf("feed %s: %w", f.Name, err))
			continue
		}
		switch f.Class {
		case ClassCloudProvider:
			cloud = append(cloud, cidrs...)
		case ClassCDN:
			cdn = append(cdn, cidrs...)
		}
	}
	c.SetCloudCIDRs(dedup(cloud))
	c.SetCDNCIDRs(dedup(cdn))
	return errs
}

// SyncLoop runs SyncOnce immediately, then every interval until ctx
// is cancelled. Default interval (zero) is 24h.
func SyncLoop(ctx context.Context, c *Classifier, feeds []Feed, hc *http.Client, interval time.Duration, onErr func(error)) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	for _, e := range SyncOnce(ctx, c, feeds, hc) {
		if onErr != nil {
			onErr(e)
		}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, e := range SyncOnce(ctx, c, feeds, hc) {
				if onErr != nil {
					onErr(e)
				}
			}
		}
	}
}

func fetchOne(ctx context.Context, hc *http.Client, f Feed) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", f.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // 16 MiB safety
	if err != nil {
		return nil, err
	}
	return f.Parse(body)
}

func parseAWS(body []byte) ([]string, error) {
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Prefixes)+len(doc.IPv6Prefixes))
	for _, p := range doc.Prefixes {
		if p.IPPrefix != "" {
			out = append(out, p.IPPrefix)
		}
	}
	for _, p := range doc.IPv6Prefixes {
		if p.IPv6Prefix != "" {
			out = append(out, p.IPv6Prefix)
		}
	}
	return out, nil
}

func parseLineList(body []byte) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func dedup(in []string) []string {
	seen := map[string]struct{}{}
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

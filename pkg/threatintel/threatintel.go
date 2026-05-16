// Package threatintel maintains an in-memory set of "known bad" IPs
// that the alert pipeline cross-references on every outbound
// connection.
//
// Sources shipped by default (pure-text feeds, no API key):
//
//   spamhaus_drop      https://www.spamhaus.org/drop/drop.txt
//   spamhaus_edrop     https://www.spamhaus.org/drop/edrop.txt
//   tor_exits          https://check.torproject.org/torbulkexitlist
//   firehol_level1     https://iplists.firehol.org/files/firehol_level1.netset
//
// Each is a plain CIDR-or-IP-per-line list. Comments start with `#` or `;`.
//
// Why these specific sources: zero-FP curated lists. Spamhaus DROP is
// hard-revoked netblocks. Tor exits aren't malicious per se but
// outbound to a Tor exit from a server is almost never legitimate
// for the kind of host you'd run xhelix on. firehol_level1 is the
// "you should never see this" union of public blocklists.
//
// We refresh on a schedule (default 6h). On fetch failure, the
// previous set is preserved — never go open. An offline restart with
// no network just runs without intel until a successful fetch.
//
// Lookup is O(log N) via sorted CIDR set.
package threatintel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Source is one feed.
type Source struct {
	Name string
	URL  string
}

// DefaultSources returns the bundled feed list. Operators add their
// own (MISP, OTX, internal) via Config.ExtraSources.
func DefaultSources() []Source {
	return []Source{
		{"spamhaus_drop", "https://www.spamhaus.org/drop/drop.txt"},
		{"spamhaus_edrop", "https://www.spamhaus.org/drop/edrop.txt"},
		{"tor_exits", "https://check.torproject.org/torbulkexitlist"},
		{"firehol_level1", "https://iplists.firehol.org/files/firehol_level1.netset"},
	}
}

// Config tunes the fetcher.
type Config struct {
	Sources       []Source       // default = DefaultSources()
	ExtraSources  []Source
	RefreshEvery  time.Duration  // default 6h
	HTTPTimeout   time.Duration  // default 30s
	Logger        *slog.Logger
	// AllowOffline lets the daemon start with no feed if the first
	// fetch fails. Default false — a hard fetch failure aborts Start
	// so the operator notices before relying on intel.
	AllowOffline  bool
}

// Set is the queryable collection.
type Set struct {
	mu     sync.RWMutex
	v4     []v4Range
	v6     []v6Range
	bySrc  map[string]int
	loaded time.Time
}

type v4Range struct {
	low, high uint32
	source    string
}

type v6Range struct {
	low, high [16]byte
	source    string
}

// Tagged is a lookup result. Empty tag = no match.
type Tagged struct {
	Source string // e.g. "spamhaus_drop"
}

// Lookup returns a Tagged{Source} when ip is in any feed, or empty.
// Both v4 and v6 are supported.
func (s *Set) Lookup(ip net.IP) Tagged {
	if ip == nil {
		return Tagged{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v4 := ip.To4(); v4 != nil {
		x := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
		i := sort.Search(len(s.v4), func(i int) bool { return s.v4[i].high >= x })
		if i < len(s.v4) && s.v4[i].low <= x && x <= s.v4[i].high {
			return Tagged{Source: s.v4[i].source}
		}
		return Tagged{}
	}
	v6 := ip.To16()
	if v6 == nil {
		return Tagged{}
	}
	var key [16]byte
	copy(key[:], v6)
	i := sort.Search(len(s.v6), func(i int) bool { return cmp16(s.v6[i].high, key) >= 0 })
	if i < len(s.v6) && cmp16(s.v6[i].low, key) <= 0 && cmp16(key, s.v6[i].high) <= 0 {
		return Tagged{Source: s.v6[i].source}
	}
	return Tagged{}
}

// Stats is the dashboard view.
type Stats struct {
	V4Ranges    int
	V6Ranges    int
	BySource    map[string]int
	LoadedAt    time.Time
}

func (s *Set) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := Stats{
		V4Ranges: len(s.v4),
		V6Ranges: len(s.v6),
		BySource: map[string]int{},
		LoadedAt: s.loaded,
	}
	for k, v := range s.bySrc {
		out.BySource[k] = v
	}
	return out
}

// Fetcher manages periodic refreshes.
type Fetcher struct {
	cfg     Config
	set     *Set
	log     *slog.Logger
	client  *http.Client

	running atomic.Bool
	cancel  context.CancelFunc
}

// New returns an unstarted fetcher. The Set is shared via Set().
func New(cfg Config) *Fetcher {
	if len(cfg.Sources) == 0 {
		cfg.Sources = DefaultSources()
	}
	cfg.Sources = append(cfg.Sources, cfg.ExtraSources...)
	if cfg.RefreshEvery == 0 {
		cfg.RefreshEvery = 6 * time.Hour
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	// Private HTTP client + transport so the fetcher's connection
	// pool is isolated from anything else in the binary that uses
	// http.DefaultClient. Explicit timeouts at every layer so a
	// silent peer can't pin a goroutine past the context deadline.
	client := &http.Client{
		Timeout: cfg.HTTPTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: cfg.HTTPTimeout,
			ExpectContinueTimeout: 1 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          16,
		},
	}
	return &Fetcher{cfg: cfg, log: cfg.Logger, client: client,
		set: &Set{bySrc: map[string]int{}}}
}

// Set returns the shared lookup target. Safe for concurrent reads
// across daemon goroutines.
func (f *Fetcher) Set() *Set { return f.set }

// Start performs the first fetch synchronously and then schedules
// periodic refreshes. If the first fetch fails and AllowOffline is
// false, returns the error.
func (f *Fetcher) Start(parent context.Context) error {
	if !f.running.CompareAndSwap(false, true) {
		return nil
	}
	if err := f.refresh(parent); err != nil && !f.cfg.AllowOffline {
		f.running.Store(false)
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	f.cancel = cancel
	go f.loop(ctx)
	return nil
}

func (f *Fetcher) Stop() {
	if !f.running.CompareAndSwap(true, false) {
		return
	}
	if f.cancel != nil {
		f.cancel()
	}
}

func (f *Fetcher) loop(ctx context.Context) {
	t := time.NewTicker(f.cfg.RefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := f.refresh(ctx); err != nil {
				f.log.Warn("threatintel refresh failed", "err", err)
			}
		}
	}
}

// refresh fetches all sources in parallel and atomically swaps the Set.
func (f *Fetcher) refresh(ctx context.Context) error {
	type result struct {
		src   string
		v4    []v4Range
		v6    []v6Range
	}
	ch := make(chan result, len(f.cfg.Sources))
	var wg sync.WaitGroup
	for _, src := range f.cfg.Sources {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			v4, v6, err := f.fetchOne(ctx, src)
			if err != nil {
				f.log.Warn("source fetch failed", "src", src.Name, "err", err)
				return
			}
			ch <- result{src: src.Name, v4: v4, v6: v6}
		}()
	}
	wg.Wait()
	close(ch)

	var allV4 []v4Range
	var allV6 []v6Range
	bySrc := map[string]int{}
	for r := range ch {
		allV4 = append(allV4, r.v4...)
		allV6 = append(allV6, r.v6...)
		bySrc[r.src] = len(r.v4) + len(r.v6)
	}
	if len(allV4) == 0 && len(allV6) == 0 {
		return fmt.Errorf("threatintel: zero entries fetched")
	}
	sort.Slice(allV4, func(i, j int) bool { return allV4[i].low < allV4[j].low })
	sort.Slice(allV6, func(i, j int) bool { return cmp16(allV6[i].low, allV6[j].low) < 0 })
	// Overlapping ranges (Spamhaus and FireHOL routinely cover the
	// same blocks) break the simple binary-search Lookup: the search
	// for first-high>=x can land on a range that doesn't contain x
	// while skipping the larger range that does. Merge overlaps
	// after sorting so the resulting set has disjoint ranges.
	allV4 = mergeV4(allV4)
	allV6 = mergeV6(allV6)

	f.set.mu.Lock()
	f.set.v4 = allV4
	f.set.v6 = allV6
	f.set.bySrc = bySrc
	f.set.loaded = time.Now()
	f.set.mu.Unlock()
	f.log.Info("threatintel refreshed",
		"v4_ranges", len(allV4), "v6_ranges", len(allV6),
		"sources", len(bySrc))
	return nil
}

func (f *Fetcher) fetchOne(ctx context.Context, src Source) ([]v4Range, []v6Range, error) {
	c, cancel := context.WithTimeout(ctx, f.cfg.HTTPTimeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(c, "GET", src.URL, nil)
	req.Header.Set("User-Agent", "xhelix-threatintel/1")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseList(resp.Body, src.Name)
}

// parseList is exported-ish via the test below; consumes a feed
// stream and returns parsed ranges. Comments + empty lines skipped.
func parseList(r io.Reader, src string) ([]v4Range, []v6Range, error) {
	var v4 []v4Range
	var v6 []v6Range
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// spamhaus DROP format: "203.0.113.0/24 ; SBL12345"
		if i := strings.IndexByte(line, ';'); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.IndexByte(line, '#'); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		// Either CIDR or bare IP.
		if !strings.ContainsAny(line, "/") {
			ip := net.ParseIP(line)
			if ip == nil {
				continue
			}
			if v4ip := ip.To4(); v4ip != nil {
				x := uint32(v4ip[0])<<24 | uint32(v4ip[1])<<16 | uint32(v4ip[2])<<8 | uint32(v4ip[3])
				v4 = append(v4, v4Range{low: x, high: x, source: src})
			} else {
				var key [16]byte
				copy(key[:], ip.To16())
				v6 = append(v6, v6Range{low: key, high: key, source: src})
			}
			continue
		}
		_, n, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		if v4ip := n.IP.To4(); v4ip != nil {
			low := uint32(v4ip[0])<<24 | uint32(v4ip[1])<<16 | uint32(v4ip[2])<<8 | uint32(v4ip[3])
			ones, _ := n.Mask.Size()
			high := low | (^uint32(0) >> ones)
			v4 = append(v4, v4Range{low: low, high: high, source: src})
		} else {
			var lo, hi [16]byte
			copy(lo[:], n.IP.To16())
			copy(hi[:], lo[:])
			ones, _ := n.Mask.Size()
			// fill the hi address from bit `ones` onward
			for i := ones; i < 128; i++ {
				hi[i/8] |= 1 << (7 - uint(i%8))
			}
			v6 = append(v6, v6Range{low: lo, high: hi, source: src})
		}
	}
	return v4, v6, sc.Err()
}

func cmp16(a, b [16]byte) int {
	for i := 0; i < 16; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// mergeV4 collapses overlapping or adjacent v4 ranges. Caller has
// already sorted by low. Each result range carries the source name
// of the first (sorted) input range that introduced it; for
// alert-attribution purposes this is "good enough" — the operator
// can grep the merged set if they need precise per-source provenance.
func mergeV4(in []v4Range) []v4Range {
	if len(in) <= 1 {
		return in
	}
	out := make([]v4Range, 0, len(in))
	cur := in[0]
	for i := 1; i < len(in); i++ {
		if in[i].low <= cur.high+1 { // overlap or touching
			if in[i].high > cur.high {
				cur.high = in[i].high
			}
			continue
		}
		out = append(out, cur)
		cur = in[i]
	}
	out = append(out, cur)
	return out
}

// mergeV6 — same as mergeV4 for v6 ranges. Note we don't try to
// "touching" merge (cur.high+1) for v6 because uint16 arithmetic on
// [16]byte is inconvenient and the gain is marginal; we only merge
// strict overlaps.
func mergeV6(in []v6Range) []v6Range {
	if len(in) <= 1 {
		return in
	}
	out := make([]v6Range, 0, len(in))
	cur := in[0]
	for i := 1; i < len(in); i++ {
		if cmp16(in[i].low, cur.high) <= 0 { // overlap
			if cmp16(in[i].high, cur.high) > 0 {
				cur.high = in[i].high
			}
			continue
		}
		out = append(out, cur)
		cur = in[i]
	}
	out = append(out, cur)
	return out
}

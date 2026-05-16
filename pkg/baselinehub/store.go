package baselinehub

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/baseline"
)

// Store persists incoming Uploads to disk and serves cross-fleet
// queries. Layout:
//
//   <dir>/feed/2026-05-04/<host_tag>.jsonl     — per-host, per-day windows
//   <dir>/feed/2026-05-03/<host_tag>.jsonl.gz  — older days, gzipped
//
// Cross-fleet queries (rare endpoints, etc.) read all .jsonl/.jsonl.gz
// from the lookback window and compute on the fly. This is fine up
// to ~1000 hosts × 30 days; beyond that we'd want a real DB.
type Store struct {
	dir string

	mu      sync.Mutex
	current map[string]*os.File // host_tag → file handle for today

	stats struct {
		uploads      uint64
		windows      uint64
		bytes        uint64
		uniqueHosts  map[string]struct{}
		uniqueBins   map[string]struct{}
		newestWindow time.Time
		oldestWindow time.Time
	}
}

// NewStore creates the hub storage rooted at dir.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "feed"), 0o700); err != nil {
		return nil, err
	}
	return &Store{
		dir:     dir,
		current: map[string]*os.File{},
	}, nil
}

// IngestUpload writes one Upload to disk. payloadBytes is the size
// of the original wire payload (used for stats only); pass 0 if not
// available.
func (s *Store) IngestUpload(u Upload) error {
	return s.IngestUploadWithSize(u, 0)
}

// IngestUploadWithSize is the same as IngestUpload but accepts the
// wire-payload byte size, which the server has at request time and
// the in-process call sites generally don't.
func (s *Store) IngestUploadWithSize(u Upload, payloadBytes int) error {
	if u.HostTag == "" {
		return fmt.Errorf("hub: empty host_tag")
	}
	day := time.Now().UTC().Format("2006-01-02")
	dir := filepath.Join(s.dir, "feed", day)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, sanitize(u.HostTag)+".jsonl")

	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.current[u.HostTag]
	if !ok || fileBaseDay(f.Name()) != day {
		if ok {
			_ = f.Close()
		}
		nf, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		s.current[u.HostTag] = nf
		f = nf
	}

	enc := json.NewEncoder(f)
	for _, w := range u.Windows {
		// Tag every persisted window with the source host. The hub
		// reads these back when computing rare-endpoint aggregates.
		envelope := struct {
			HostTag string             `json:"host_tag"`
			RoleTag string             `json:"role_tag,omitempty"`
			Window  *baseline.Window   `json:"window"`
		}{u.HostTag, u.RoleTag, w}
		if err := enc.Encode(envelope); err != nil {
			return err
		}
		s.stats.windows++
		if s.stats.uniqueHosts == nil {
			s.stats.uniqueHosts = map[string]struct{}{}
			s.stats.uniqueBins = map[string]struct{}{}
		}
		s.stats.uniqueHosts[u.HostTag] = struct{}{}
		s.stats.uniqueBins[w.Binary] = struct{}{}
		if s.stats.oldestWindow.IsZero() || w.Hour.Before(s.stats.oldestWindow) {
			s.stats.oldestWindow = w.Hour
		}
		if w.Hour.After(s.stats.newestWindow) {
			s.stats.newestWindow = w.Hour
		}
	}
	s.stats.uploads++
	if payloadBytes > 0 {
		s.stats.bytes += uint64(payloadBytes)
	}
	return nil
}

// Stats returns current ingest counters.
func (s *Store) Stats() IngestStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return IngestStats{
		UploadsTotal:   s.stats.uploads,
		WindowsTotal:   s.stats.windows,
		BytesTotal:     s.stats.bytes,
		UniqueHosts:    len(s.stats.uniqueHosts),
		UniqueBinaries: len(s.stats.uniqueBins),
		OldestWindow:   s.stats.oldestWindow,
		NewestWindow:   s.stats.newestWindow,
	}
}

// Close flushes and closes all open file handles.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.current {
		_ = f.Close()
	}
	s.current = map[string]*os.File{}
	return nil
}

// ComputeRare reads every host's windows for a given binary across
// the last `lookbackDays` and returns the endpoints that appear on
// fewer than `rarityCutoff` fraction of hosts.
//
// O(hosts × windows) per call; cache at the caller for hot binaries.
func (s *Store) ComputeRare(binary string, lookbackDays int, rarityCutoff float64) (*RareList, error) {
	if rarityCutoff <= 0 || rarityCutoff >= 1 {
		rarityCutoff = 0.95 // default: endpoints seen on < 5% of hosts
	}
	now := time.Now().UTC()
	cutoff := now.AddDate(0, 0, -lookbackDays).Format("2006-01-02")

	feedDir := filepath.Join(s.dir, "feed")
	dayEntries, err := os.ReadDir(feedDir)
	if err != nil {
		return nil, err
	}

	// host_tag → set of endpoints (across all hours) for this binary
	perHostEndpoints := map[string]map[string]struct{}{}
	today := time.Now().UTC().Format("2006-01-02")

	for _, de := range dayEntries {
		if !de.IsDir() || de.Name() < cutoff {
			continue
		}
		dayPath := filepath.Join(feedDir, de.Name())
		hostFiles, err := os.ReadDir(dayPath)
		if err != nil {
			continue
		}
		for _, hf := range hostFiles {
			path := filepath.Join(dayPath, hf.Name())
			// For today's files (concurrently appended to by
			// IngestUpload) take s.mu briefly to serialise against
			// in-flight writes. The lock is held only for the
			// duration of one file's scan, which is fast for the
			// per-host JSONL — much smaller than the full feed.
			// Older days' files are immutable; no lock needed.
			if de.Name() == today {
				s.mu.Lock()
				_ = s.scanFileFor(path, binary, perHostEndpoints)
				s.mu.Unlock()
			} else {
				_ = s.scanFileFor(path, binary, perHostEndpoints)
			}
		}
	}

	totalHosts := len(perHostEndpoints)
	if totalHosts == 0 {
		return &RareList{
			Binary: binary, GeneratedAt: now, TotalHosts: 0,
			RarityCutoff: rarityCutoff,
		}, nil
	}

	// Count host appearances per endpoint.
	endpointHostCount := map[string]int{}
	for _, eps := range perHostEndpoints {
		for ep := range eps {
			endpointHostCount[ep]++
		}
	}

	rare := []RareEndpoint{}
	for ep, n := range endpointHostCount {
		rarity := 1.0 - float64(n)/float64(totalHosts)
		if rarity >= rarityCutoff {
			rare = append(rare, RareEndpoint{
				Binary: binary, Endpoint: ep,
				HostsSeen: n, TotalHosts: totalHosts,
				Rarity: rarity,
			})
		}
	}
	sort.Slice(rare, func(i, j int) bool { return rare[i].Rarity > rare[j].Rarity })

	return &RareList{
		Binary: binary, GeneratedAt: now, TotalHosts: totalHosts,
		RarityCutoff: rarityCutoff, Rare: rare,
	}, nil
}

// scanFileFor reads a (possibly gzipped) per-host JSONL feed file
// and accumulates endpoints for the requested binary into out.
func (s *Store) scanFileFor(path, binary string,
	out map[string]map[string]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	dec := json.NewDecoder(r)
	for dec.More() {
		var env struct {
			HostTag string             `json:"host_tag"`
			Window  *baseline.Window   `json:"window"`
		}
		if err := dec.Decode(&env); err != nil {
			break
		}
		if env.Window == nil || env.Window.Binary != binary {
			continue
		}
		set, ok := out[env.HostTag]
		if !ok {
			set = map[string]struct{}{}
			out[env.HostTag] = set
		}
		for ep := range env.Window.Endpoints {
			set[ep] = struct{}{}
		}
	}
	return nil
}

func sanitize(s string) string {
	if s == "" {
		return "_"
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9', c == '-', c == '_', c == '.':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

func fileBaseDay(path string) string {
	// /var/lib/xhub/feed/2026-05-04/web-01.jsonl → 2026-05-04
	dir := filepath.Dir(path)
	return filepath.Base(dir)
}

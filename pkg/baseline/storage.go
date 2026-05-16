package baseline

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Store persists Aggregator output to disk as JSON Lines, one file
// per UTC day. Day boundaries trigger a rotation; the rotated file
// is gzipped in place so a 30-day retention window stays small.
//
// Layout:
//
//   <dir>/2026-05-04.jsonl       ← today, plain
//   <dir>/2026-05-03.jsonl.gz    ← yesterday, compressed
//   <dir>/2026-05-02.jsonl.gz
//   ...
//
// Format: one JSON object per line, exactly Window.MarshalJSON. We
// chose JSONL over Parquet to keep the agent dependency-free; an
// off-line process (training pipeline, fleet hub) can transcode to
// Parquet at the warm-storage tier.
//
// Concurrency: a single Store has one goroutine that owns the file
// handle. Callers Push() windows on a buffered channel; the writer
// drains, encodes, and rotates as needed.
type Store struct {
	dir string
	log *slog.Logger

	in        chan *Window
	closeCh   chan struct{}
	closeOnce sync.Once

	mu          sync.Mutex
	currentDay  string // "2026-05-04"
	currentFile *os.File

	// Counters are atomic so writeOne() (running on the store
	// goroutine) and Stats() (running on the caller's goroutine —
	// dashboard polls, the doctor, tests) can update + read without
	// taking s.mu. Taking s.mu in writeOne would also work but
	// serialises against ensureFile and the close path, slowing the
	// hot write loop.
	stats struct {
		written  atomic.Uint64
		rotated  atomic.Uint64
		dropped  atomic.Uint64
		writeErr atomic.Uint64
	}
}

// NewStore opens (or creates) the directory and returns an unstarted
// Store. Call Start() to launch the writer goroutine.
func NewStore(dir string, log *slog.Logger) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("baseline: empty store dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if log == nil {
		log = slog.Default()
	}
	return &Store{
		dir:     dir,
		log:     log,
		in:      make(chan *Window, 1024),
		closeCh: make(chan struct{}),
	}, nil
}

// Start launches the writer goroutine. Returns immediately.
func (s *Store) Start(ctx context.Context) {
	go s.run(ctx)
}

// Stop closes the input channel and waits for the writer to finish.
// Safe to call multiple times.
func (s *Store) Stop() {
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
}

// Push enqueues windows for persistence. Non-blocking: drops on full
// queue rather than back-pressure the aggregator. Drops are counted
// for the dashboard.
func (s *Store) Push(windows []*Window) {
	for _, w := range windows {
		select {
		case s.in <- w:
		default:
			s.stats.dropped.Add(1)
		}
	}
}

// WriteSync writes windows synchronously, bypassing the channel and
// the writer goroutine. Used at shutdown when the writer goroutine
// may already have exited via ctx.Done(), and for tests that don't
// want to wait on a goroutine. Safe to call concurrently with the
// writer (both go through ensureFile + currentFile under s.mu).
func (s *Store) WriteSync(windows []*Window) {
	for _, w := range windows {
		s.writeOne(w)
	}
}

// Stats reports counters.
type StoreStats struct {
	Written  uint64
	Rotated  uint64
	Dropped  uint64
	WriteErr uint64
	OpenFile string
}

func (s *Store) Stats() StoreStats {
	// Counters are atomic — no lock required for the four scalars.
	// We still take s.mu briefly to read currentFile name safely.
	out := StoreStats{
		Written:  s.stats.written.Load(),
		Rotated:  s.stats.rotated.Load(),
		Dropped:  s.stats.dropped.Load(),
		WriteErr: s.stats.writeErr.Load(),
	}
	s.mu.Lock()
	if s.currentFile != nil {
		out.OpenFile = s.currentFile.Name()
	}
	s.mu.Unlock()
	return out
}

func (s *Store) run(ctx context.Context) {
	defer s.close()
	for {
		select {
		case <-ctx.Done():
			s.drainPending()
			return
		case <-s.closeCh:
			s.drainPending()
			return
		case w := <-s.in:
			s.writeOne(w)
		}
	}
}

func (s *Store) drainPending() {
	for {
		select {
		case w := <-s.in:
			s.writeOne(w)
		default:
			return
		}
	}
}

// writeOne serialises one window and appends it to the active day's
// file. Holds s.mu for the entire body so concurrent callers
// (run goroutine + WriteSync from shutdown) cannot interleave Write
// calls on s.currentFile and produce torn JSONL records.
func (s *Store) writeOne(w *Window) {
	day := w.Hour.Format("2006-01-02")
	body, jerr := json.Marshal(w)
	if jerr != nil {
		s.stats.writeErr.Add(1)
		return
	}
	body = append(body, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureFileLocked(day); err != nil {
		s.stats.writeErr.Add(1)
		s.log.Warn("baseline: ensureFile", "err", err)
		return
	}
	if _, err := s.currentFile.Write(body); err != nil {
		s.stats.writeErr.Add(1)
		s.log.Warn("baseline: write", "err", err)
		return
	}
	s.stats.written.Add(1)
}

// ensureFileLocked opens (or rotates to) the JSONL file for the
// given UTC day. Caller MUST already hold s.mu — the public-shape
// "ensureFile" ancestor used to take the lock itself, but the new
// writeOne takes s.mu around the whole body, so we factor the
// locking up to the caller and rename to make the contract clear.
func (s *Store) ensureFileLocked(day string) error {
	if s.currentDay == day && s.currentFile != nil {
		return nil
	}
	// Close + gzip the prior file.
	if s.currentFile != nil {
		prevPath := s.currentFile.Name()
		_ = s.currentFile.Close()
		s.currentFile = nil
		if err := gzipInPlace(prevPath); err != nil {
			s.log.Warn("baseline: gzip rotated file", "path", prevPath, "err", err)
		}
		s.stats.rotated.Add(1)
	}
	path := filepath.Join(s.dir, day+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	s.currentFile = f
	s.currentDay = day
	return nil
}

func (s *Store) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentFile != nil {
		_ = s.currentFile.Close()
		s.currentFile = nil
	}
}

// gzipInPlace compresses path → path+".gz" then removes the original.
// Safe to call on a small file; we use it on rotated daily JSONL,
// not on hot-path writes.
func gzipInPlace(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(path+".gz", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(out)
	if _, err := copyAll(gz, in); err != nil {
		_ = gz.Close()
		_ = out.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

func copyAll(dst writer, src reader) (int64, error) {
	buf := make([]byte, 64*1024)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return total, nil
			}
			return total, err
		}
	}
}

// Tiny interfaces to avoid pulling in io for one usage.
type writer interface{ Write([]byte) (int, error) }
type reader interface{ Read([]byte) (int, error) }

// PruneOlderThan deletes baseline files older than the cutoff (by
// the YYYY-MM-DD encoded in the filename). Run from a daily ticker.
func (s *Store) PruneOlderThan(cutoff time.Time) (int, error) {
	s.mu.Lock()
	dir := s.dir
	s.mu.Unlock()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	cutoffStr := cutoff.UTC().Format("2006-01-02")
	removed := 0
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		// Expect "2026-05-04.jsonl" or "2026-05-04.jsonl.gz".
		if len(name) < 10 {
			continue
		}
		day := name[:10]
		if day < cutoffStr {
			if err := os.Remove(filepath.Join(dir, name)); err == nil {
				removed++
			}
		}
	}
	return removed, nil
}

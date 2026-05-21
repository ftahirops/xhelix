// Package forensicingest tails JSON-lines forensic streams written
// by the Ring 2 deception binaries (honey-sh, sinkhole, dnspoison)
// and feeds them into the daemon's in-process forensic.Store.
//
// One Ingestor scans a directory; each *.jsonl file gets a
// long-running follower goroutine that reads new lines as they're
// appended. No fsnotify dependency — just stat + seek-to-end +
// sleep. Cheap; one ~30 LOC goroutine per active file.
//
// The deception binaries already emit `{"type":"...","body":{...}}`
// envelopes that forensic.ProcessLine knows how to parse, so no
// shared serialization code is required.
//
// See PROTECTED_SERVICES_TRAP.md §7 (forensic harvest pipeline) and
// pkg/forensic/ingest.go for the envelope schema.
package forensicingest

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/forensic"
)

// Config tunes the ingestor.
type Config struct {
	// Dir is the directory containing *.jsonl files. The ingestor
	// re-scans for new files every ScanInterval.
	Dir string

	// ScanInterval — how often to look for new files.
	// Default 5s.
	ScanInterval time.Duration

	// PollInterval — how often each follower polls its file for
	// appended lines. Default 250ms (cheap; one stat() + bufio
	// read per file).
	PollInterval time.Duration

	// MaxLineBytes — bound on per-line read buffer. Default 1 MiB.
	// Lines longer than this are dropped with a log entry.
	MaxLineBytes int

	// OnError, if set, receives non-fatal errors (parse failures,
	// stat errors). nil = silently dropped.
	OnError func(path string, err error)

	Log *slog.Logger
}

func (c Config) defaulted() Config {
	d := c
	if d.ScanInterval <= 0 {
		d.ScanInterval = 5 * time.Second
	}
	if d.PollInterval <= 0 {
		d.PollInterval = 250 * time.Millisecond
	}
	if d.MaxLineBytes <= 0 {
		d.MaxLineBytes = 1024 * 1024
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return d
}

// Ingestor tails a forensic-log directory.
type Ingestor struct {
	cfg     Config
	store   *forensic.Store
	co      *forensic.CoEngine // optional; co-occurrence rules
	mu      sync.Mutex
	tailing map[string]context.CancelFunc

	// Counters
	linesRead    atomic.Int64
	parseErrors  atomic.Int64
	filesActive  atomic.Int64
	cooccurFires atomic.Int64
	onCoHit      func(forensic.Hit)
}

// New builds an Ingestor. CoEngine is optional — pass nil to skip
// co-occurrence evaluation (the ingestor still populates the
// Store). onCoHit, if non-nil, is called for each co-occurrence
// rule fire — useful for emitting alerts back through the bus.
func New(cfg Config, store *forensic.Store, co *forensic.CoEngine, onCoHit func(forensic.Hit)) *Ingestor {
	cfg = cfg.defaulted()
	return &Ingestor{
		cfg:     cfg,
		store:   store,
		co:      co,
		tailing: map[string]context.CancelFunc{},
		onCoHit: onCoHit,
	}
}

// Run starts the scan loop. Returns when ctx is cancelled. Caller
// invokes via `go ing.Run(ctx)`.
func (i *Ingestor) Run(ctx context.Context) {
	if i.cfg.Dir == "" {
		i.cfg.Log.Warn("forensicingest: empty Dir; ingestor idle")
		<-ctx.Done()
		return
	}
	if err := os.MkdirAll(i.cfg.Dir, 0o755); err != nil {
		i.cfg.Log.Warn("forensicingest: mkdir", "dir", i.cfg.Dir, "err", err)
		// Don't bail — operator may fix permissions while we wait.
	}
	t := time.NewTicker(i.cfg.ScanInterval)
	defer t.Stop()

	i.scan(ctx)
	for {
		select {
		case <-ctx.Done():
			i.stopAll()
			return
		case <-t.C:
			i.scan(ctx)
		}
	}
}

// scan walks Dir for *.jsonl files and starts a follower for each
// new one. Existing followers are left running; closed files
// auto-exit via their follower goroutine.
func (i *Ingestor) scan(ctx context.Context) {
	entries, err := os.ReadDir(i.cfg.Dir)
	if err != nil {
		i.notifyErr(i.cfg.Dir, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(i.cfg.Dir, e.Name())
		i.mu.Lock()
		_, already := i.tailing[path]
		i.mu.Unlock()
		if already {
			continue
		}
		fctx, cancel := context.WithCancel(ctx)
		i.mu.Lock()
		i.tailing[path] = cancel
		i.mu.Unlock()
		i.filesActive.Add(1)
		go i.follow(fctx, path)
	}
}

// follow reads new lines from path until ctx is cancelled or the
// file is removed. Resilient to file truncation (rotation: detects
// shrink + reopens) and to lines split across reads (bufio handles
// it).
func (i *Ingestor) follow(ctx context.Context, path string) {
	defer func() {
		i.mu.Lock()
		delete(i.tailing, path)
		i.mu.Unlock()
		i.filesActive.Add(-1)
	}()

	f, err := os.Open(path)
	if err != nil {
		i.notifyErr(path, err)
		return
	}
	defer f.Close()

	// Start from the head of the file the first time we see it.
	// (Operators don't lose evidence on daemon restart this way.)
	br := bufio.NewReaderSize(f, 64*1024)
	var lastSize int64

	// P-RF.9g L1: use a single Ticker rather than re-allocating
	// time.After timers each iteration. Allocating in a hot poll
	// loop adds GC pressure under sub-100ms PollInterval values.
	pollTicker := time.NewTicker(i.cfg.PollInterval)
	defer pollTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			line = trimTrailingNewline(line)
			if len(line) > i.cfg.MaxLineBytes {
				i.notifyErr(path, fmt.Errorf("line too long: %d > %d", len(line), i.cfg.MaxLineBytes))
			} else {
				_, perr := forensic.ProcessLine(i.store, line)
				if perr != nil {
					i.parseErrors.Add(1)
					i.notifyErr(path, perr)
				} else {
					i.linesRead.Add(1)
					i.evalCo(line)
				}
			}
		}
		if err == nil {
			continue
		}
		if err == io.EOF {
			// Check for rotation: shrunk file → reopen.
			st, statErr := os.Stat(path)
			if statErr != nil {
				// File deleted — exit follower.
				return
			}
			if st.Size() < lastSize {
				_, _ = f.Seek(0, io.SeekStart)
				br.Reset(f)
				lastSize = 0
				continue
			}
			lastSize = st.Size()
			select {
			case <-ctx.Done():
				return
			case <-pollTicker.C:
			}
			continue
		}
		// Other error — log and back off.
		i.notifyErr(path, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(i.cfg.PollInterval):
		}
	}
}

// evalCo runs the optional CoEngine against the observations
// produced by this line. We re-parse the line for the envelope
// type so we can extract the source identifier (BeaconID /
// SessionID / Peer) — without it, CoEngine can't bucket.
//
// Cheap-ish: one extra JSON unmarshal per line. The full
// observation extraction already happened in ProcessLine; this
// just lifts the (kind, value, source) tuples for the engine.
func (i *Ingestor) evalCo(line []byte) {
	if i.co == nil {
		return
	}
	// session_end / beacon_end → free CoEngine state for that
	// source. Fixes C2 from the P-RF.9g review.
	if source := sessionEndSource(line); source != "" {
		i.co.Forget(source)
		return
	}
	for _, obs := range extractObservations(line) {
		hits := i.co.Observe(obs)
		for _, h := range hits {
			i.cooccurFires.Add(1)
			if i.onCoHit != nil {
				i.onCoHit(h)
			}
		}
	}
}

// stopAll cancels every active follower.
func (i *Ingestor) stopAll() {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, cancel := range i.tailing {
		cancel()
	}
}

// Stats are observable counters.
type Stats struct {
	LinesRead    int64
	ParseErrors  int64
	FilesActive  int64
	CooccurFires int64
}

// Stats returns a snapshot.
func (i *Ingestor) Stats() Stats {
	return Stats{
		LinesRead:    i.linesRead.Load(),
		ParseErrors:  i.parseErrors.Load(),
		FilesActive:  i.filesActive.Load(),
		CooccurFires: i.cooccurFires.Load(),
	}
}

func (i *Ingestor) notifyErr(path string, err error) {
	if i.cfg.OnError != nil {
		i.cfg.OnError(path, err)
		return
	}
	i.cfg.Log.Debug("forensicingest", "path", path, "err", err)
}

func trimTrailingNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

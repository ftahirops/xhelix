package integrity

import (
	"context"
	"io/fs"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultPaths returns the critical paths every Linux baseline should
// cover. Operators can override / extend via config.
func DefaultPaths() []string {
	return []string{
		"/usr/bin",
		"/usr/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
		"/bin",
		"/sbin",
		"/lib",
		"/lib64",
		"/usr/lib/systemd/system",
		"/lib/systemd/system",
		"/etc/systemd/system",
		"/usr/lib/security",
		"/lib/security",
		"/lib/x86_64-linux-gnu/security",
		"/etc/pam.d",
	}
}

// DefaultMaxFileSize is the per-file SHA cap. 256 MB covers every
// real binary; bigger files are skipped with a note (typically not
// executables anyway).
const DefaultMaxFileSize = 256 * 1024 * 1024

// WalkOptions tunes a baseline build.
type WalkOptions struct {
	Paths       []string  // default DefaultPaths
	MaxFileSize int64     // 0 → DefaultMaxFileSize
	Workers     int       // 0 → runtime.NumCPU(); clamped to [1, 16]
	OnProgress  func(WalkProgress)
	Log         *slog.Logger
}

// WalkProgress is delivered to the optional progress callback as the
// walk advances.
type WalkProgress struct {
	PathsScanned  uint64
	FilesHashed   uint64
	FilesSkipped  uint64
	BytesHashed   uint64
	CurrentPath   string
}

// Build walks the configured paths concurrently, hashing every
// regular file and upserting into the baseline. Existing rows are
// preserved with their higher-trust source (see Baseline.Upsert).
// Idempotent. Returns a summary when ctx is not cancelled, otherwise
// returns partial counts when ctx expires.
func Build(ctx context.Context, b *Baseline, opts WalkOptions) (WalkProgress, error) {
	if len(opts.Paths) == 0 {
		opts.Paths = DefaultPaths()
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > 16 {
		workers = 16
	}
	if workers < 1 {
		workers = 1
	}

	type job struct{ path string }
	jobs := make(chan job, workers*4)

	var pathsScanned uint64
	var filesHashed uint64
	var filesSkipped uint64
	var bytesHashed uint64
	var lastReport atomic.Int64
	lastReport.Store(time.Now().UnixNano())

	report := func(cur string) {
		if opts.OnProgress == nil {
			return
		}
		// Throttle to ~one callback per 250ms.
		now := time.Now().UnixNano()
		if now-lastReport.Load() < int64(250*time.Millisecond) {
			return
		}
		lastReport.Store(now)
		opts.OnProgress(WalkProgress{
			PathsScanned: atomic.LoadUint64(&pathsScanned),
			FilesHashed:  atomic.LoadUint64(&filesHashed),
			FilesSkipped: atomic.LoadUint64(&filesSkipped),
			BytesHashed:  atomic.LoadUint64(&bytesHashed),
			CurrentPath:  cur,
		})
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				hash, size, mt, err := HashFile(j.path, opts.MaxFileSize)
				if err != nil {
					atomic.AddUint64(&filesSkipped, 1)
					continue
				}
				_ = b.Upsert(Row{
					Path:      j.path,
					SHA256:    hash,
					Size:      size,
					MtimeUnix: mt.Unix(),
					Source:    SourceTOFU,
				})
				atomic.AddUint64(&filesHashed, 1)
				atomic.AddUint64(&bytesHashed, uint64(size))
				report(j.path)
			}
		}()
	}

	for _, root := range opts.Paths {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				// Silent on per-entry errors (missing dirs, etc.) —
				// the walker covers many candidate roots, some of
				// which may not exist on every distro.
				return nil
			}
			atomic.AddUint64(&pathsScanned, 1)
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() {
				atomic.AddUint64(&filesSkipped, 1)
				return nil
			}
			// Skip clearly-not-binary file extensions.
			if isUninterestingExt(p) {
				atomic.AddUint64(&filesSkipped, 1)
				return nil
			}
			select {
			case jobs <- job{path: p}:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
	}
	close(jobs)
	wg.Wait()

	final := WalkProgress{
		PathsScanned: atomic.LoadUint64(&pathsScanned),
		FilesHashed:  atomic.LoadUint64(&filesHashed),
		FilesSkipped: atomic.LoadUint64(&filesSkipped),
		BytesHashed:  atomic.LoadUint64(&bytesHashed),
	}
	if opts.Log != nil {
		opts.Log.Info("integrity baseline build complete",
			"paths_scanned", final.PathsScanned,
			"files_hashed", final.FilesHashed,
			"files_skipped", final.FilesSkipped,
			"bytes_hashed_mb", final.BytesHashed/(1024*1024))
	}
	return final, ctx.Err()
}

// isUninterestingExt filters obvious non-binary files. Keeps the
// walker fast and the DB compact. Conservative — we keep things that
// might be binary (.so, .ko, scripts).
func isUninterestingExt(p string) bool {
	low := strings.ToLower(p)
	for _, ext := range []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg",
		".pdf", ".html", ".css", ".md", ".txt",
		".log", ".gz", ".xz", ".bz2",
		".desktop", ".policy",
	} {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	return false
}

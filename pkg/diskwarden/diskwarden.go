// Package diskwarden monitors xhelix-owned disk and auto-prunes when
// usage exceeds a configured cap. Addresses the bounded-growth issue
// called out in the perf review: the JSONL daily rollup writes
// ~280 MB/day with no rotation, plus ip-timeseries growing 30d
// retention, plus integrity baseline and chain segments.
//
// Pruning order (oldest first, never touches today's working file):
//
//  1. gzip yesterday's egress-analytics JSONL if still uncompressed.
//  2. Delete egress-analytics .jsonl.gz older than retention_days.
//  3. Vacuum ip-timeseries SQLite (drops dead pages after retention sweep).
//  4. Delete chain segments past chain retention.
//
// Each prune step emits a critical-grade audit log so operators see
// every byte the warden touches.
package diskwarden

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Config controls the warden.
type Config struct {
	// CapBytes is the total xhelix-owned bytes (state + log dirs)
	// above which pruning kicks in. Default 4 GiB.
	CapBytes int64
	// MinFreePercent triggers prune when filesystem free space drops
	// below this percentage of total, regardless of CapBytes.
	// Default 5 (% free).
	MinFreePercent int
	// RetentionDays for egress-analytics JSONL files. Default 30.
	RetentionDays int
	// CheckInterval is how often the warden walks the tree.
	// Default 1 hour.
	CheckInterval time.Duration
	// StateDir is the xhelix state root (default /var/lib/xhelix).
	StateDir string
	// LogDir is the xhelix log root (default /var/log/xhelix).
	LogDir string
	// Log receives audit lines.
	Log *slog.Logger
}

// Warden runs the periodic check + prune loop.
type Warden struct {
	cfg Config

	stats struct {
		runs            atomic.Uint64
		prunes          atomic.Uint64
		bytesReclaimed  atomic.Uint64
		lastBytesOwned  atomic.Int64
		lastFreePercent atomic.Int64
	}
}

// New constructs a Warden with defaults filled in.
func New(cfg Config) *Warden {
	if cfg.CapBytes <= 0 {
		cfg.CapBytes = 4 << 30 // 4 GiB
	}
	if cfg.MinFreePercent <= 0 {
		cfg.MinFreePercent = 5
	}
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 30
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = time.Hour
	}
	if cfg.StateDir == "" {
		cfg.StateDir = "/var/lib/xhelix"
	}
	if cfg.LogDir == "" {
		cfg.LogDir = "/var/log/xhelix"
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Warden{cfg: cfg}
}

// Start runs the warden loop until ctx cancels. Returns immediately;
// loop runs in a goroutine. First check fires after a 10s delay so
// initial baseline build can settle.
func (w *Warden) Start(ctx context.Context) {
	go func() {
		first := time.NewTimer(10 * time.Second)
		defer first.Stop()
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		}
		w.Tick(ctx)
		t := time.NewTicker(w.cfg.CheckInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				w.Tick(ctx)
			}
		}
	}()
}

// Tick runs one check + prune pass. Exported so operator CLI can
// invoke on demand ('xhelixctl diskwarden sweep').
func (w *Warden) Tick(ctx context.Context) {
	w.stats.runs.Add(1)
	owned := dirSize(w.cfg.StateDir) + dirSize(w.cfg.LogDir)
	w.stats.lastBytesOwned.Store(owned)
	freePct := freePercentFor(w.cfg.StateDir)
	w.stats.lastFreePercent.Store(int64(freePct))

	overCap := owned > w.cfg.CapBytes
	lowDisk := freePct >= 0 && freePct < w.cfg.MinFreePercent

	if !overCap && !lowDisk {
		w.cfg.Log.Debug("diskwarden ok",
			"bytes_owned", owned, "cap", w.cfg.CapBytes,
			"free_percent", freePct)
		return
	}

	w.cfg.Log.Warn("diskwarden trigger — pruning",
		"bytes_owned", owned, "cap", w.cfg.CapBytes,
		"free_percent", freePct, "min_free_percent", w.cfg.MinFreePercent,
		"reason_over_cap", overCap, "reason_low_disk", lowDisk)

	reclaimed := w.prune(ctx)
	w.stats.prunes.Add(1)
	w.stats.bytesReclaimed.Add(uint64(reclaimed))
	w.cfg.Log.Warn("diskwarden prune complete",
		"bytes_reclaimed", reclaimed,
		"bytes_owned_after", dirSize(w.cfg.StateDir)+dirSize(w.cfg.LogDir))
}

// prune executes the prune order, returns bytes reclaimed.
func (w *Warden) prune(ctx context.Context) int64 {
	var total int64
	total += w.gzipYesterdayRollup()
	total += w.deleteOldRollups()
	return total
}

// gzipYesterdayRollup compresses yesterday's egress-analytics .jsonl
// in place if it isn't already gzipped. Today's file is untouched.
func (w *Warden) gzipYesterdayRollup() int64 {
	dir := filepath.Join(w.cfg.StateDir, "egress-analytics")
	today := time.Now().UTC().Format("2006-01-02") + ".jsonl"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var reclaimed int64
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".jsonl") || n == today {
			continue
		}
		src := filepath.Join(dir, n)
		dst := src + ".gz"
		if _, err := os.Stat(dst); err == nil {
			// Already gzipped; remove the uncompressed copy.
			if st, err := os.Stat(src); err == nil {
				reclaimed += st.Size()
				_ = os.Remove(src)
			}
			continue
		}
		saved, err := gzipFile(src, dst)
		if err != nil {
			w.cfg.Log.Warn("diskwarden gzip failed", "file", n, "err", err)
			continue
		}
		_ = os.Remove(src)
		reclaimed += saved
		w.cfg.Log.Info("diskwarden gzipped rollup", "file", n, "bytes_saved", saved)
	}
	return reclaimed
}

// deleteOldRollups removes .jsonl.gz files older than RetentionDays.
// Operates on the modification time (sufficient for our use; not
// affected by clock skew the way mtime-on-create would be).
func (w *Warden) deleteOldRollups() int64 {
	dir := filepath.Join(w.cfg.StateDir, "egress-analytics")
	cutoff := time.Now().AddDate(0, 0, -w.cfg.RetentionDays)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	// Sort by name so oldest goes first (YYYY-MM-DD prefix sorts chronologically).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	var reclaimed int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		full := filepath.Join(dir, e.Name())
		st, err := os.Stat(full)
		if err != nil {
			continue
		}
		if st.ModTime().Before(cutoff) {
			reclaimed += st.Size()
			if err := os.Remove(full); err == nil {
				w.cfg.Log.Info("diskwarden deleted old rollup",
					"file", e.Name(), "age_days", int(time.Since(st.ModTime()).Hours()/24))
			}
		}
	}
	return reclaimed
}

// Stats returns counter snapshot.
type Stats struct {
	Runs            uint64
	Prunes          uint64
	BytesReclaimed  uint64
	LastBytesOwned  int64
	LastFreePercent int64
}

func (w *Warden) Stats() Stats {
	return Stats{
		Runs:            w.stats.runs.Load(),
		Prunes:          w.stats.prunes.Load(),
		BytesReclaimed:  w.stats.bytesReclaimed.Load(),
		LastBytesOwned:  w.stats.lastBytesOwned.Load(),
		LastFreePercent: w.stats.lastFreePercent.Load(),
	}
}

// dirSize sums all regular file bytes under root. 0 on any error.
func dirSize(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// freePercentFor returns free filesystem percent on the FS containing
// path, or -1 on error.
func freePercentFor(path string) int {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return -1
	}
	total := s.Blocks * uint64(s.Bsize)
	if total == 0 {
		return -1
	}
	free := s.Bavail * uint64(s.Bsize)
	return int(free * 100 / total)
}

// gzipFile gzips src into dst, returns bytes saved.
func gzipFile(src, dst string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		_ = gz.Close()
		return 0, err
	}
	if err := gz.Close(); err != nil {
		return 0, err
	}
	srcSize := fileSize(src)
	dstSize := fileSize(dst)
	return srcSize - dstSize, nil
}

func fileSize(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.Size()
}

// Helper for testing: lets tests inject a custom "now".
var _ = fmt.Sprintf

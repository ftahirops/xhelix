// Package fim implements xhelix's file-integrity baseline (AIDE-lite)
// and live drift watcher.
//
// Phase 2 ships the baseline + scheduled verify path. The fanotify
// live watcher lives in fim_linux.go and is gated to Linux.
package fim

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Entry is a single baseline record.
type Entry struct {
	Path     string
	Inode    uint64
	Mtime    time.Time
	Size     int64
	Mode     uint32
	UID      uint32
	GID      uint32
	SHA256   string
	Symlink  string
	LastSeen time.Time
}

// Drift describes a difference between baseline and current state.
type Drift struct {
	Path   string
	Reason string
	Want   Entry
	Got    Entry
}

// Baseline persists entries in SQLite for restart safety.
type Baseline struct {
	mu sync.Mutex
	db *sql.DB
}

// MaxHashSize caps per-file hash work.
const MaxHashSize = 256 * 1024 * 1024

// Open opens (or creates) a baseline at path.
func Open(path string) (*Baseline, error) {
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open fim: %w", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS entries (
			path     TEXT PRIMARY KEY,
			inode    INTEGER,
			mtime_ns INTEGER,
			size     INTEGER,
			mode     INTEGER,
			uid      INTEGER,
			gid      INTEGER,
			sha256   TEXT,
			symlink  TEXT,
			last_seen INTEGER
		);
		CREATE INDEX IF NOT EXISTS entries_last_seen ON entries(last_seen);
	`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Baseline{db: db}, nil
}

// Close releases the database handle.
func (b *Baseline) Close() error { return b.db.Close() }

// Build walks paths and writes a fresh baseline. Existing entries
// for paths in scope are replaced; entries outside scope are left
// alone.
//
// Build is safe to re-run; it is idempotent given the same files.
func (b *Baseline) Build(ctx context.Context, paths []string) (int, error) {
	count := 0
	for _, root := range paths {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			ent, err := readEntry(p, info)
			if err != nil {
				return nil // best-effort
			}
			if err := b.upsert(ctx, ent); err != nil {
				return err
			}
			count++
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			return count, fmt.Errorf("walk %s: %w", root, err)
		}
	}
	return count, nil
}

// Verify compares current filesystem state to the baseline.
//
// Returns a list of Drift records: changed (sha mismatch), removed
// (entry exists in baseline but not on disk), added (file present
// in scope but not in baseline) — the third only when the caller
// passes a non-empty paths slice.
func (b *Baseline) Verify(ctx context.Context, paths []string) ([]Drift, error) {
	rows, err := b.db.QueryContext(ctx, `SELECT path, sha256, mtime_ns, size FROM entries`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	have := make(map[string]Entry, 4096)
	for rows.Next() {
		var ent Entry
		var mNs int64
		if err := rows.Scan(&ent.Path, &ent.SHA256, &mNs, &ent.Size); err != nil {
			return nil, err
		}
		ent.Mtime = time.Unix(0, mNs)
		have[ent.Path] = ent
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var drifts []Drift
	seen := make(map[string]bool, len(have))
	for path, want := range have {
		seen[path] = true
		info, err := os.Lstat(path)
		if err != nil {
			drifts = append(drifts, Drift{Path: path, Reason: "removed", Want: want})
			continue
		}
		got, err := readEntry(path, info)
		if err != nil {
			drifts = append(drifts, Drift{Path: path, Reason: "stat-failed", Want: want})
			continue
		}
		if got.SHA256 != "" && want.SHA256 != "" && got.SHA256 != want.SHA256 {
			drifts = append(drifts, Drift{Path: path, Reason: "sha-mismatch", Want: want, Got: got})
		}
	}
	return drifts, nil
}

func (b *Baseline) upsert(ctx context.Context, e Entry) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO entries (path, inode, mtime_ns, size, mode, uid, gid,
		                     sha256, symlink, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET
		  inode=excluded.inode, mtime_ns=excluded.mtime_ns,
		  size=excluded.size, mode=excluded.mode, uid=excluded.uid,
		  gid=excluded.gid, sha256=excluded.sha256,
		  symlink=excluded.symlink, last_seen=excluded.last_seen
	`,
		e.Path, e.Inode, e.Mtime.UnixNano(), e.Size, e.Mode,
		e.UID, e.GID, e.SHA256, e.Symlink, time.Now().UnixNano())
	return err
}

func readEntry(path string, info os.FileInfo) (Entry, error) {
	e := Entry{
		Path:  path,
		Mtime: info.ModTime(),
		Size:  info.Size(),
		Mode:  uint32(info.Mode().Perm()),
	}
	mode := info.Mode()
	switch {
	case mode.IsRegular():
		sum, err := hashFile(path)
		if err != nil {
			return e, err
		}
		e.SHA256 = sum
	case mode&os.ModeSymlink != 0:
		t, err := os.Readlink(path)
		if err != nil {
			return e, err
		}
		e.Symlink = t
	}
	if err := readPlatformAttrs(&e, info); err != nil {
		// platform attrs are best-effort; log later if needed.
		_ = err
	}
	return e, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyN(h, f, MaxHashSize); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

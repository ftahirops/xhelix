// Package integrity is the binary integrity baseline + verifier
// described in docs/EGRESS_C2_DISARM_AND_BINARY_INTEGRITY_2026-05-22.md
// Pillar B.
//
// Layer 1 (B1, this file): persistent baseline of (path → SHA-256).
// Built on first install by walking critical paths; refreshed on
// authentic package-manager upgrades. SQLite-backed at
// /var/lib/xhelix/integrity-baseline.db.
//
// Layer 2 (B2, separate package): authenticated-upgrade tester
// (T1–T5) that decides whether a binary write traces back to a
// legitimate dpkg/rpm transaction.
//
// Layer 3 (B3, pkg/execguard extension): execve-time SHA verification
// — every execve consults this baseline; mismatch outside an
// authentic-upgrade context triggers disarm + critical alert.
package integrity

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Source classifies how a baseline row landed in the DB.
type Source string

const (
	SourcePkgMgr   Source = "pkg-mgr"  // verified via dpkg/rpm/etc.
	SourceTOFU     Source = "tofu"     // first-seen on disk, accepted
	SourceOperator Source = "operator" // operator-blessed (xhelixctl)
)

// Row is one baseline record.
type Row struct {
	Path      string
	SHA256    string
	Size      int64
	MtimeUnix int64
	Source    Source
	Package   string // dpkg/rpm package name when known
	AddedAt   time.Time
	UpdatedAt time.Time
}

// Baseline is the persistent store.
type Baseline struct {
	mu sync.RWMutex
	db *sql.DB
}

// Open opens or creates the baseline DB. ":memory:" works for tests.
func Open(path string) (*Baseline, error) {
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open integrity baseline: %w", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS baseline (
			path        TEXT PRIMARY KEY,
			sha256      TEXT NOT NULL,
			size        INTEGER NOT NULL,
			mtime_unix  INTEGER NOT NULL,
			source      TEXT NOT NULL,
			package     TEXT,
			added_at    INTEGER NOT NULL,
			updated_at  INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS baseline_pkg_idx ON baseline(package);
	`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init integrity schema: %w", err)
	}
	return &Baseline{db: db}, nil
}

// Close releases the database handle.
func (b *Baseline) Close() error { return b.db.Close() }

// Upsert inserts or refreshes a row. The Source on the existing row
// is preserved unless the caller's Source is strictly higher-trust
// (pkg-mgr > operator > tofu). This prevents a TOFU-discovered file
// from clobbering a pkg-mgr-validated row.
func (b *Baseline) Upsert(r Row) error {
	if r.Path == "" || r.SHA256 == "" || r.Source == "" {
		return errors.New("integrity Upsert: path, sha256, source required")
	}
	if r.AddedAt.IsZero() {
		r.AddedAt = time.Now().UTC()
	}
	r.UpdatedAt = time.Now().UTC()
	b.mu.Lock()
	defer b.mu.Unlock()
	// Check existing row; preserve higher-trust source.
	var existingSource string
	row := b.db.QueryRow(`SELECT source FROM baseline WHERE path = ?`, r.Path)
	if err := row.Scan(&existingSource); err == nil {
		if sourceRank(Source(existingSource)) > sourceRank(r.Source) {
			r.Source = Source(existingSource)
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("integrity select existing: %w", err)
	}
	_, err := b.db.Exec(`
		INSERT INTO baseline
			(path, sha256, size, mtime_unix, source, package, added_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET
			sha256=excluded.sha256,
			size=excluded.size,
			mtime_unix=excluded.mtime_unix,
			source=excluded.source,
			package=COALESCE(excluded.package, baseline.package),
			updated_at=excluded.updated_at
	`, r.Path, r.SHA256, r.Size, r.MtimeUnix, string(r.Source), r.Package,
		r.AddedAt.Unix(), r.UpdatedAt.Unix())
	if err != nil {
		return fmt.Errorf("integrity upsert: %w", err)
	}
	return nil
}

// Lookup returns the baseline row for path. Bool false = no row.
func (b *Baseline) Lookup(path string) (Row, bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var r Row
	var src string
	var pkg sql.NullString
	var added, updated int64
	err := b.db.QueryRow(`
		SELECT path, sha256, size, mtime_unix, source, package, added_at, updated_at
		FROM baseline WHERE path = ?
	`, path).Scan(&r.Path, &r.SHA256, &r.Size, &r.MtimeUnix, &src, &pkg, &added, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return Row{}, false, nil
	}
	if err != nil {
		return Row{}, false, err
	}
	r.Source = Source(src)
	if pkg.Valid {
		r.Package = pkg.String
	}
	r.AddedAt = time.Unix(added, 0).UTC()
	r.UpdatedAt = time.Unix(updated, 0).UTC()
	return r, true, nil
}

// Forget deletes a baseline row (e.g. when a package is purged).
func (b *Baseline) Forget(path string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, err := b.db.Exec(`DELETE FROM baseline WHERE path = ?`, path)
	return err
}

// Count returns the total number of baselined rows.
func (b *Baseline) Count() (int, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var n int
	err := b.db.QueryRow(`SELECT COUNT(*) FROM baseline`).Scan(&n)
	return n, err
}

// PerSource returns row counts grouped by source.
func (b *Baseline) PerSource() (map[Source]int, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	rows, err := b.db.Query(`SELECT source, COUNT(*) FROM baseline GROUP BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[Source]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return out, err
		}
		out[Source(s)] = n
	}
	return out, rows.Err()
}

// HashFile computes the SHA-256 hex of the file at path. Skips files
// larger than maxSize. Returns "" on any error (caller decides what
// to do). Size cap protects against pathological cases.
func HashFile(path string, maxSize int64) (string, int64, time.Time, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	if !st.Mode().IsRegular() {
		return "", 0, time.Time{}, fmt.Errorf("not a regular file: %s", path)
	}
	if maxSize > 0 && st.Size() > maxSize {
		return "", st.Size(), st.ModTime(), fmt.Errorf("file %s too large (%d bytes > cap %d)", path, st.Size(), maxSize)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", st.Size(), st.ModTime(), err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", st.Size(), st.ModTime(), err
	}
	return hex.EncodeToString(h.Sum(nil)), st.Size(), st.ModTime(), nil
}

func sourceRank(s Source) int {
	switch s {
	case SourcePkgMgr:
		return 3
	case SourceOperator:
		return 2
	case SourceTOFU:
		return 1
	}
	return 0
}

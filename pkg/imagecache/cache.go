// Package imagecache hashes executable binaries on first-seen and
// keeps a memory + SQLite-backed cache of (path, mtime) -> SHA-256.
package imagecache

import (
	"context"
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

// Image is a record about a binary observed at execve time.
type Image struct {
	Path      string
	Mtime     time.Time
	Size      int64
	SHA256    string
	FirstSeen time.Time
	LastSeen  time.Time
	Package   string
	Verified  bool
}

// MaxHashSize caps the per-file hash work to a sane bound.
const MaxHashSize = 256 * 1024 * 1024 // 256 MB

// Cache is the public API.
type Cache struct {
	mu  sync.RWMutex
	mem map[string]*Image
	db  *sql.DB
}

// Open opens (or creates) a SQLite-backed image cache.
//
// path == ":memory:" works for tests.
func Open(path string) (*Cache, error) {
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open imagecache: %w", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS images (
			path        TEXT NOT NULL,
			mtime_ns    INTEGER NOT NULL,
			size        INTEGER,
			sha256      TEXT,
			first_seen  INTEGER,
			last_seen   INTEGER,
			package     TEXT,
			verified    INTEGER,
			PRIMARY KEY (path, mtime_ns)
		);
	`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Cache{db: db, mem: make(map[string]*Image, 256)}, nil
}

// Close releases the database handle.
func (c *Cache) Close() error { return c.db.Close() }

// Lookup returns a cached entry, if any, for (path, mtime).
func (c *Cache) Lookup(path string, mtime time.Time) (*Image, bool) {
	key := path + "|" + mtime.UTC().Format(time.RFC3339Nano)
	c.mu.RLock()
	if img, ok := c.mem[key]; ok {
		c.mu.RUnlock()
		return img, true
	}
	c.mu.RUnlock()

	row := c.db.QueryRow(`SELECT path, mtime_ns, size, sha256, first_seen, last_seen,
		package, verified FROM images WHERE path = ? AND mtime_ns = ?`,
		path, mtime.UnixNano())
	var img Image
	var mNs, fs, ls int64
	var verified int
	err := row.Scan(&img.Path, &mNs, &img.Size, &img.SHA256, &fs, &ls,
		&img.Package, &verified)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	img.Mtime = time.Unix(0, mNs)
	img.FirstSeen = time.Unix(0, fs)
	img.LastSeen = time.Unix(0, ls)
	img.Verified = verified != 0

	c.mu.Lock()
	c.mem[key] = &img
	c.mu.Unlock()
	return &img, true
}

// Compute hashes path (truncating at MaxHashSize) and inserts a
// fresh entry.
func (c *Cache) Compute(ctx context.Context, path string) (*Image, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, errors.New("imagecache: path is a directory")
	}
	if existing, ok := c.Lookup(path, st.ModTime()); ok {
		return existing, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.CopyN(h, f, MaxHashSize); err != nil && err != io.EOF {
		return nil, err
	}
	img := &Image{
		Path:      path,
		Mtime:     st.ModTime(),
		Size:      st.Size(),
		SHA256:    hex.EncodeToString(h.Sum(nil)),
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	if _, err := c.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO images
		  (path, mtime_ns, size, sha256, first_seen, last_seen, package, verified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, img.Path, img.Mtime.UnixNano(), img.Size, img.SHA256,
		img.FirstSeen.UnixNano(), img.LastSeen.UnixNano(), img.Package,
		boolToInt(img.Verified)); err != nil {
		return nil, fmt.Errorf("insert image: %w", err)
	}

	c.mu.Lock()
	key := path + "|" + img.Mtime.UTC().Format(time.RFC3339Nano)
	c.mem[key] = img
	c.mu.Unlock()
	return img, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

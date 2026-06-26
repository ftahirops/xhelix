package recorder

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Options configures the Store.
type Options struct {
	// Path is the on-disk DB file. The directory is created with 0o750 if missing.
	Path string

	// ExemplarsPerShape caps how many raw-value exemplars are kept per
	// (app_id, shape_hash). Default: 20.
	ExemplarsPerShape int

	// RetentionDays caps how long shapes are kept. DropOld removes shapes whose
	// last_seen is older than RetentionDays before now. Default: 30.
	// Per ERRORS.md: stores must prune; this knob must have a consumer.
	RetentionDays int
}

// ShapeRow is one result row from Shapes.
type ShapeRow struct {
	AppID     string
	ShapeHash string
	RootType  string
	Phase     string
	Count     int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// Store is the recorder's durable SQLite backend. Open with NewStore;
// close with Close when done.
type Store struct {
	db                *sql.DB
	exemplarsPerShape int
	retentionDays     int
}

const recorderSchema = `
CREATE TABLE IF NOT EXISTS shapes (
  app_id     TEXT NOT NULL,
  shape_hash TEXT NOT NULL,
  root_type  TEXT,
  phase      TEXT,
  count      INTEGER NOT NULL DEFAULT 0,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  PRIMARY KEY (app_id, shape_hash)
);
CREATE INDEX IF NOT EXISTS shapes_app  ON shapes(app_id);
CREATE INDEX IF NOT EXISTS shapes_last ON shapes(last_seen);
CREATE TABLE IF NOT EXISTS exemplars (
  app_id     TEXT NOT NULL,
  shape_hash TEXT NOT NULL,
  edge_kind  TEXT NOT NULL,
  raw        TEXT NOT NULL,
  PRIMARY KEY (app_id, shape_hash, edge_kind, raw)
);
CREATE INDEX IF NOT EXISTS exemplars_shape ON exemplars(app_id, shape_hash);
`

// NewStore opens (or creates) the SQLite database at opts.Path, applies WAL +
// synchronous=NORMAL pragmas (mirroring pkg/coldstore), creates the schema, and
// returns a ready Store.
func NewStore(opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("recorder: Path is required")
	}
	if opts.ExemplarsPerShape <= 0 {
		opts.ExemplarsPerShape = 20
	}
	if opts.RetentionDays == 0 {
		opts.RetentionDays = 30
	}

	if err := os.MkdirAll(filepath.Dir(opts.Path), 0o750); err != nil {
		return nil, fmt.Errorf("recorder mkdir: %w", err)
	}

	// Mirror pkg/coldstore: _pragma URL params applied to every connection.
	dsn := opts.Path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("recorder open: %w", err)
	}
	// SQLite is single-writer; more connections only invite lock contention.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("recorder ping: %w", err)
	}
	if _, err := db.Exec(recorderSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("recorder schema: %w", err)
	}

	return &Store{
		db:                db,
		exemplarsPerShape: opts.ExemplarsPerShape,
		retentionDays:     opts.RetentionDays,
	}, nil
}

// RecordChain upserts the shape row for c (incrementing count, advancing
// last_seen) and inserts edge exemplars up to ExemplarsPerShape per shape.
// Writes synchronously — recorder volume is per-flushed-chain, far below
// per-event, so no write-behind queue is needed for Cycle 1.
func (s *Store) RecordChain(c Chain) error {
	sh := ShapeHash(c.Edges)
	firstNS := c.FirstSeen.UnixNano()
	lastNS := c.LastSeen.UnixNano()

	_, err := s.db.Exec(`
		INSERT INTO shapes (app_id, shape_hash, root_type, phase, count, first_seen, last_seen)
		VALUES (?, ?, ?, ?, 1, ?, ?)
		ON CONFLICT(app_id, shape_hash) DO UPDATE SET
			count     = count + 1,
			last_seen = max(last_seen, excluded.last_seen)`,
		c.AppID, sh, c.RootType, c.Phase, firstNS, lastNS)
	if err != nil {
		return fmt.Errorf("recorder upsert shape: %w", err)
	}

	// Insert exemplars, enforcing the per-shape cap. We pre-count before each
	// edge insert so the cap is accurate across edges in the same chain call.
	for _, e := range c.Edges {
		if e.Raw == "" {
			continue
		}
		var n int
		if err := s.db.QueryRow(
			`SELECT COUNT(*) FROM exemplars WHERE app_id=? AND shape_hash=?`,
			c.AppID, sh,
		).Scan(&n); err != nil {
			return fmt.Errorf("recorder count exemplars: %w", err)
		}
		if n >= s.exemplarsPerShape {
			// Cap reached for this shape; skip remaining edges.
			break
		}
		if _, err := s.db.Exec(
			`INSERT OR IGNORE INTO exemplars (app_id, shape_hash, edge_kind, raw) VALUES (?, ?, ?, ?)`,
			c.AppID, sh, string(e.Kind), e.Raw,
		); err != nil {
			return fmt.Errorf("recorder insert exemplar: %w", err)
		}
	}
	return nil
}

// Shapes returns all shape rows for the given app_id, ordered by last_seen
// descending (most recently observed first).
func (s *Store) Shapes(appID string) ([]ShapeRow, error) {
	rows, err := s.db.Query(`
		SELECT app_id, shape_hash, root_type, phase, count, first_seen, last_seen
		FROM shapes WHERE app_id=? ORDER BY last_seen DESC`,
		appID)
	if err != nil {
		return nil, fmt.Errorf("recorder shapes query: %w", err)
	}
	defer rows.Close()

	var out []ShapeRow
	for rows.Next() {
		var r ShapeRow
		var firstNS, lastNS int64
		if err := rows.Scan(
			&r.AppID, &r.ShapeHash, &r.RootType, &r.Phase,
			&r.Count, &firstNS, &lastNS,
		); err != nil {
			return nil, fmt.Errorf("recorder shapes scan: %w", err)
		}
		r.FirstSeen = time.Unix(0, firstNS).UTC()
		r.LastSeen = time.Unix(0, lastNS).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// Exemplars returns the distinct Raw strings stored for a given
// (app_id, shape_hash) pair.
func (s *Store) Exemplars(appID, shapeHash string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT raw FROM exemplars WHERE app_id=? AND shape_hash=?`,
		appID, shapeHash)
	if err != nil {
		return nil, fmt.Errorf("recorder exemplars query: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("recorder exemplars scan: %w", err)
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

// DropOld deletes shapes whose last_seen is older than RetentionDays before now,
// and their associated exemplars. Returns the number of shape rows deleted.
//
// Mirror of pkg/coldstore.DropOldDays: ERRORS.md records cold.db growing
// unbounded when pruning was not wired — this store enforces the same bound.
func (s *Store) DropOld(now time.Time) (int64, error) {
	cutoff := now.Add(-time.Duration(s.retentionDays) * 24 * time.Hour).UnixNano()

	// Delete exemplars for shapes that are about to be pruned.
	if _, err := s.db.Exec(`
		DELETE FROM exemplars WHERE EXISTS (
			SELECT 1 FROM shapes
			WHERE shapes.app_id    = exemplars.app_id
			  AND shapes.shape_hash = exemplars.shape_hash
			  AND shapes.last_seen  < ?
		)`, cutoff); err != nil {
		return 0, fmt.Errorf("recorder drop old exemplars: %w", err)
	}

	res, err := s.db.Exec(`DELETE FROM shapes WHERE last_seen < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("recorder drop old shapes: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error { return s.db.Close() }

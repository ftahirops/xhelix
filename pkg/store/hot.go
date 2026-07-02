// Package store implements the hot, warm, and cold persistence
// tiers for events.
//
// In Phase 0 only the hot tier exists, backed by SQLite (modernc.org
// pure-Go driver, no CGo). Warm/cold tiers land in later phases.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	_ "modernc.org/sqlite"

	"github.com/xhelix/xhelix/pkg/model"
)

// HotStore is a 24-hour ring of recent events on local disk.
type HotStore struct {
	db   *sql.DB
	path string

	// Async write-behind path (opt-in via StartWriter). When enabled, the
	// hot-path caller uses Submit — a non-blocking enqueue — instead of the
	// synchronous Insert, so a SQLite stall can never block the single pipeline
	// dispatch goroutine (which would back-pressure sensors into event drops).
	// The hot store is a recent-events query cache; the cold store and forensic
	// chain are the durable paths, so dropping under sustained write pressure is
	// acceptable here. On overflow we drop OLDEST (keep the most recent events,
	// which is what dashboards and RCA query), mirroring the coldstore queue.
	writeMu   sync.Mutex
	writeQ    []model.Event
	writeCap  int
	writerOn  atomic.Bool
	wake      chan struct{} // buffered(1): nudge the writer to drain early
	writeDone chan struct{}
	submitted atomic.Uint64
	written   atomic.Uint64
	dropped   atomic.Uint64
}

// OpenHot opens (or creates) the SQLite-backed hot store at path.
//
// path may be ":memory:" for tests.
func OpenHot(path string) (*HotStore, error) {
	dsn := path
	if path != ":memory:" {
		// journal_size_limit caps the WAL file: after each checkpoint
		// SQLite truncates it back to 64 MiB instead of leaving it at
		// the high-water-mark forever (a burst once grew hot.db-wal to
		// 3.5 GiB on disk while holding only ~573 live frames —
		// 2026-06-18). busy_timeout makes writers (esp. the retention
		// Prune) wait for the lock instead of failing instantly with
		// SQLITE_BUSY ("hot prune (time) failed ... database is locked"),
		// which had stalled retention and let the table grow unbounded.
		// Matches the coldstore DSN.
		// auto_vacuum(incremental): freed pages (from retention DELETEs)
		// go to a freelist that PRAGMA incremental_vacuum reclaims in
		// place — no full-rewrite VACUUM, which took an exclusive lock
		// for tens of seconds and dropped concurrent inserts with
		// SQLITE_BUSY (2026-06-18). NOTE: this only takes effect on a
		// fresh DB; an existing auto_vacuum=NONE file must be converted
		// once with `PRAGMA auto_vacuum=INCREMENTAL; VACUUM;`.
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)" +
			"&_pragma=synchronous(NORMAL)" +
			"&_pragma=busy_timeout(5000)" +
			"&_pragma=journal_size_limit(67108864)" +
			"&_pragma=auto_vacuum(incremental)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open hot store: %w", err)
	}
	if path != ":memory:" {
		// One-time conversion of a legacy auto_vacuum=NONE file to
		// INCREMENTAL, so PruneBySize's incremental_vacuum actually reclaims
		// disk. The DSN pragma above only affects freshly-created DBs; a
		// daemon upgraded in place would otherwise never shrink hot.db.
		convertToIncrementalVacuum(db)
	}
	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &HotStore{db: db, path: path}, nil
}

// convertToIncrementalVacuum upgrades a legacy auto_vacuum=NONE database to
// INCREMENTAL (mode 2). auto_vacuum can only be changed by setting the pragma
// and then running a full VACUUM; on a fresh DB the DSN pragma already did
// this, so we only pay the (expensive, one-time) VACUUM when the file predates
// the pragma. Best-effort: on error (e.g. insufficient free disk for the
// rewrite) we log and continue — retention DROP/DELETE still work, only the
// in-place page reclaim is unavailable until the conversion succeeds.
func convertToIncrementalVacuum(db *sql.DB) {
	var mode int
	if err := db.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return
	}
	if mode == 2 { // already INCREMENTAL
		return
	}
	if _, err := db.Exec(`PRAGMA auto_vacuum=INCREMENTAL`); err != nil {
		return
	}
	if _, err := db.Exec(`VACUUM`); err != nil {
		return
	}
}

// Close stops the async writer (draining the queue once) and releases the
// underlying database handle.
func (h *HotStore) Close() error {
	if h.writerOn.Load() {
		h.writerOn.Store(false)
		h.nudge()
		if h.writeDone != nil {
			<-h.writeDone // wait for the writer goroutine to drain and exit
		}
	}
	return h.db.Close()
}

// Insert appends an event to the store. Older events are pruned by
// Prune(); we don't auto-prune on every insert to keep writes cheap.
func (h *HotStore) Insert(ctx context.Context, e model.Event) error {
	tagJSON, _ := json.Marshal(e.Tags)
	_, err := h.db.ExecContext(ctx, `
		INSERT INTO events (id, ts, sensor, severity, host, pid, comm, image, rule, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		e.ID.String(), e.Time.UnixNano(), e.Sensor, e.Severity.String(),
		e.Host, e.PID, e.Comm, e.Image, e.Rule, string(tagJSON),
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	return nil
}

// Count returns the total number of events currently stored.
func (h *HotStore) Count(ctx context.Context) (int64, error) {
	var n int64
	err := h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
	return n, err
}

// Prune deletes events older than the given UNIX-nanosecond cutoff.
// Returns the number of rows deleted.
func (h *HotStore) Prune(ctx context.Context, cutoffNs int64) (int64, error) {
	res, err := h.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, cutoffNs)
	if err != nil {
		return 0, fmt.Errorf("prune: %w", err)
	}
	return res.RowsAffected()
}

// RecentByPID returns events for a given pid, newest first, up to
// limit rows. Used by the TUI history view.
func (h *HotStore) RecentByPID(ctx context.Context, pid uint32, limit int) ([]model.Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := h.db.QueryContext(ctx, `
		SELECT id, ts, sensor, severity, pid, comm, image, rule, tags
		FROM events WHERE pid = ? ORDER BY ts DESC LIMIT ?`, pid, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var e model.Event
		var idS, sev, tagsS string
		var nsTs int64
		if err := rows.Scan(&idS, &nsTs, &e.Sensor, &sev, &e.PID, &e.Comm, &e.Image, &e.Rule, &tagsS); err != nil {
			return out, err
		}
		_ = json.Unmarshal([]byte(tagsS), &e.Tags)
		_ = idS
		_ = sev
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecentBySensor returns events for a given sensor name, newest first.
// Used by the TUI DNS view (sensor="dnsresolver" or similar).
func (h *HotStore) RecentBySensor(ctx context.Context, sensor string, limit int) ([]model.Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := h.db.QueryContext(ctx, `
		SELECT id, ts, sensor, severity, pid, comm, image, rule, tags
		FROM events WHERE sensor = ? ORDER BY ts DESC LIMIT ?`, sensor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var e model.Event
		var idS, sev, tagsS string
		var nsTs int64
		if err := rows.Scan(&idS, &nsTs, &e.Sensor, &sev, &e.PID, &e.Comm, &e.Image, &e.Rule, &tagsS); err != nil {
			return out, err
		}
		_ = json.Unmarshal([]byte(tagsS), &e.Tags)
		_ = idS
		_ = sev
		out = append(out, e)
	}
	return out, rows.Err()
}

// FileSize returns the on-disk size of the SQLite database file in
// bytes. Returns 0 with no error for the :memory: backend.
func (h *HotStore) FileSize() (int64, error) {
	if h.path == "" || h.path == ":memory:" {
		return 0, nil
	}
	st, err := os.Stat(h.path)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// PruneBySize enforces a maximum on-disk byte cap. When the file is
// over maxBytes, deletes the oldest 25% of events and runs VACUUM to
// reclaim space (SQLite does not return pages to the filesystem
// without VACUUM). Returns the number of rows deleted.
//
// The 25% chunk avoids running VACUUM on every tick under steady-state
// pressure — once we're back under the cap, we stay under it for a
// while before needing to prune again.
//
// Empty path / :memory: backend → no-op.
func (h *HotStore) PruneBySize(ctx context.Context, maxBytes int64) (int64, error) {
	if h.path == "" || h.path == ":memory:" || maxBytes <= 0 {
		return 0, nil
	}
	size, err := h.FileSize()
	if err != nil {
		return 0, err
	}
	if size <= maxBytes {
		return 0, nil
	}
	// Pick the 25th-percentile timestamp; delete everything below it.
	var cutoff int64
	row := h.db.QueryRowContext(ctx, `
		SELECT ts FROM events ORDER BY ts ASC
		LIMIT 1 OFFSET (SELECT COUNT(*) FROM events) / 4
	`)
	if err := row.Scan(&cutoff); err != nil {
		// Probably an empty table; nothing to do.
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("size prune scan: %w", err)
	}
	res, err := h.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("size prune delete: %w", err)
	}
	n, _ := res.RowsAffected()
	// Reclaim the pages the DELETE just freed. With auto_vacuum=
	// INCREMENTAL these sit on a freelist; incremental_vacuum moves them
	// to the end and truncates the file IN PLACE — no full rewrite, so
	// it holds the write lock only briefly instead of the tens-of-seconds
	// exclusive lock a full VACUUM took (which timed out and dropped
	// concurrent inserts, 2026-06-18). On a DB still in auto_vacuum=NONE
	// (pre-conversion) this is a cheap no-op rather than an error.
	if _, err := h.db.ExecContext(ctx, `PRAGMA incremental_vacuum`); err != nil {
		return n, fmt.Errorf("size prune incremental_vacuum: %w", err)
	}
	return n, nil
}

// PruneStats is the result of a combined Prune + PruneBySize cycle.
type PruneStats struct {
	ByTimeRows int64
	BySizeRows int64
	FileBytes  int64
}

// schemaMigrations is the ordered list of forward-only schema migrations.
// Element i moves the database from user_version i to user_version i+1. The
// current schema version is len(schemaMigrations).
//
// RULES: append only. Never edit, delete, or reorder an existing entry — a
// deployed daemon may already have applied it. A new column/index/table is a
// new element (e.g. `ALTER TABLE events ADD COLUMN ...`). Existing databases
// (pre-migration, user_version=0) safely re-run v1 because its DDL uses
// IF NOT EXISTS; it only stamps the version.
var schemaMigrations = []string{
	// v0 -> v1: initial events table + query indexes.
	`CREATE TABLE IF NOT EXISTS events (
		id        TEXT PRIMARY KEY,
		ts        INTEGER NOT NULL,
		sensor    TEXT NOT NULL,
		severity  TEXT NOT NULL,
		host      TEXT,
		pid       INTEGER,
		comm      TEXT,
		image     TEXT,
		rule      TEXT,
		tags      TEXT
	);
	CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
	CREATE INDEX IF NOT EXISTS events_sensor_ts ON events(sensor, ts);
	CREATE INDEX IF NOT EXISTS events_pid_ts ON events(pid, ts);`,
}

// initSchema brings the database up to the current schema version by applying
// every migration newer than the stored PRAGMA user_version, in order. It is
// idempotent: a fully-migrated DB does nothing.
func initSchema(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for v < len(schemaMigrations) {
		if _, err := db.Exec(schemaMigrations[v]); err != nil {
			return fmt.Errorf("apply schema migration v%d->v%d: %w", v, v+1, err)
		}
		v++
		// user_version cannot be parameterized; v is an int we fully control.
		if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v)); err != nil {
			return fmt.Errorf("stamp schema version %d: %w", v, err)
		}
	}
	return nil
}

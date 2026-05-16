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

	_ "modernc.org/sqlite"

	"github.com/xhelix/xhelix/pkg/model"
)

// HotStore is a 24-hour ring of recent events on local disk.
type HotStore struct {
	db   *sql.DB
	path string
}

// OpenHot opens (or creates) the SQLite-backed hot store at path.
//
// path may be ":memory:" for tests.
func OpenHot(path string) (*HotStore, error) {
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open hot store: %w", err)
	}
	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &HotStore{db: db, path: path}, nil
}

// Close releases the underlying database handle.
func (h *HotStore) Close() error {
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

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
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
		CREATE INDEX IF NOT EXISTS events_pid_ts ON events(pid, ts);
	`)
	return err
}

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Cache is a tiny SQLite mirror so the UI keeps working when the
// daemon socket is briefly unreachable (e.g. xhelix restart).
//
// Schema: two tables — activities + alerts — each stores the
// daemon's JSON verbatim with an indexed timestamp. We don't
// re-derive schema; the daemon's shape is the source of truth.
//
// Pure-Go, modernc.org/sqlite, CGO-free.
type Cache struct {
	db  *sql.DB
	log *slog.Logger
	mu  sync.Mutex
}

// OpenCache opens or creates the mynetgate cache at path. path
// may be ":memory:" for tests.
func OpenCache(path string, log *slog.Logger) (*Cache, error) {
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("cache open: %w", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS activities (
			id      INTEGER PRIMARY KEY AUTOINCREMENT,
			fetched INTEGER NOT NULL,
			data    TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_act_fetched ON activities(fetched);
		CREATE TABLE IF NOT EXISTS alerts (
			id      INTEGER PRIMARY KEY AUTOINCREMENT,
			fetched INTEGER NOT NULL,
			data    TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_alerts_fetched ON alerts(fetched);
	`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("cache schema: %w", err)
	}
	return &Cache{db: db, log: log}, nil
}

// Close releases the database.
func (c *Cache) Close() error { return c.db.Close() }

// StoreActivities replaces the activities cache with the given
// JSON payload. We replace rather than append so the cache always
// reflects the most-recent daemon response (the UI doesn't want
// stale duplicates).
func (c *Cache) StoreActivities(raw json.RawMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM activities`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO activities (fetched, data) VALUES (?, ?)`,
		time.Now().Unix(), string(raw)); err != nil {
		return err
	}
	return tx.Commit()
}

// LoadActivities returns the last-cached activities payload, or
// nil if nothing has been cached yet.
func (c *Cache) LoadActivities() json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	var data string
	err := c.db.QueryRow(`SELECT data FROM activities ORDER BY id DESC LIMIT 1`).Scan(&data)
	if err != nil {
		return nil
	}
	return json.RawMessage(data)
}

// StoreAlerts and LoadAlerts mirror the activities pair for the
// alerts payload.
func (c *Cache) StoreAlerts(raw json.RawMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM alerts`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO alerts (fetched, data) VALUES (?, ?)`,
		time.Now().Unix(), string(raw)); err != nil {
		return err
	}
	return tx.Commit()
}

// LoadAlerts returns the last-cached alerts payload.
func (c *Cache) LoadAlerts() json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	var data string
	err := c.db.QueryRow(`SELECT data FROM alerts ORDER BY id DESC LIMIT 1`).Scan(&data)
	if err != nil {
		return nil
	}
	return json.RawMessage(data)
}

// Prune removes cache rows older than `age`. Called periodically.
func (c *Cache) Prune(ctx context.Context, age time.Duration) error {
	cutoff := time.Now().Add(-age).Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	// modernc.org/sqlite executes a single statement per Exec call;
	// running both deletes via one multi-statement string silently
	// drops the second. Split them.
	if _, err := c.db.ExecContext(ctx, `DELETE FROM activities WHERE fetched < ?`, cutoff); err != nil {
		return err
	}
	if _, err := c.db.ExecContext(ctx, `DELETE FROM alerts WHERE fetched < ?`, cutoff); err != nil {
		return err
	}
	return nil
}

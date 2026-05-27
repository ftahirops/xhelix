// Package longwindow implements Phase H.2 long-horizon correlation.
//
// The existing pkg/correlator handles sub-minute / sub-hour sequence
// rules in memory. For slow-burn attacker behaviour (low-rate beacons,
// recon over days, periodic data egress) we need a disk-backed sliding
// window — keeping millions of in-memory sessions for 24h is not the
// answer.
//
// Model: every interesting event is recorded as a (group, tag, ts)
// tuple. A Threshold rule asks "did at least N distinct events match
// (group=G, tag=T) within the last W hours?" — evaluated periodically
// by a poller goroutine. Matches emit alerts on the bus.
//
// Honest non-promise: this is for breadth (distinct-IPs, distinct-
// processes, count-over-time), not for sequence reconstruction. The
// in-memory correlator stays the right tool for "A then B within
// 30s". Rules pick whichever fits.
package longwindow

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed event journal. Safe for concurrent use.
type Store struct {
	mu   sync.Mutex
	db   *sql.DB
	path string
}

// OpenStore opens or creates a long-window store at path. Use
// ":memory:" for tests.
func OpenStore(path string) (*Store, error) {
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("longwindow.OpenStore: %w", err)
	}
	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("longwindow.OpenStore: schema: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

// Close releases the underlying handle.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

// Path returns the on-disk path.
func (s *Store) Path() string { return s.path }

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			ts_ns  INTEGER NOT NULL,
			grp    TEXT NOT NULL,
			tag    TEXT NOT NULL,
			value  TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_events_q ON events(tag, grp, ts_ns);
		CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_ns);
	`)
	return err
}

// Record appends one observation. value is optional — set for
// distinct-count queries (e.g. distinct destination IPs); empty
// otherwise.
func (s *Store) Record(t time.Time, group, tag, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO events(ts_ns, grp, tag, value) VALUES(?, ?, ?, ?)`,
		t.UnixNano(), group, tag, value)
	return err
}

// Count returns the number of events matching (tag, group) seen in
// the window ending at `at`.
func (s *Store) Count(tag, group string, window time.Duration, at time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	since := at.Add(-window).UnixNano()
	row := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE tag=? AND grp=? AND ts_ns>=?`,
		tag, group, since)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// DistinctCount returns the number of distinct `value` columns
// matching (tag, group) within window. Use for rules like "≥5
// distinct destination IPs in 24h from this process".
func (s *Store) DistinctCount(tag, group string, window time.Duration, at time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	since := at.Add(-window).UnixNano()
	row := s.db.QueryRow(`SELECT COUNT(DISTINCT value) FROM events WHERE tag=? AND grp=? AND ts_ns>=?`,
		tag, group, since)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// Groups returns the distinct group keys with at least one event for
// `tag` within `window` ending at `at`. Used by the poller to know
// which groups to evaluate thresholds for.
func (s *Store) Groups(tag string, window time.Duration, at time.Time) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	since := at.Add(-window).UnixNano()
	rows, err := s.db.Query(`SELECT DISTINCT grp FROM events WHERE tag=? AND ts_ns>=?`,
		tag, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Sweep deletes events older than `keep`. Run periodically (default
// every hour) to bound disk usage. Returns rows removed.
func (s *Store) Sweep(keep time.Duration, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.Add(-keep).UnixNano()
	res, err := s.db.Exec(`DELETE FROM events WHERE ts_ns < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Size returns approximate row count for observability.
func (s *Store) Size() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`SELECT COUNT(*) FROM events`)
	var n int64
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

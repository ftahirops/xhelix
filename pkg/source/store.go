package source

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/xhelix/xhelix/pkg/lineage"
)

// Store is the SQLite-backed persistent anchor store.
//
// Schema is intentionally minimal — anchor identity + parent linkage +
// the kind-specific fields needed to answer "who was this and where did
// they come from". Detailed graph edges land in pkg/source/graph (T04).
//
// Driver: modernc.org/sqlite (pure-Go, no CGo) — same as pkg/store/hot.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens or creates the anchor store at path. path == ":memory:"
// works for tests; persistent stores typically live at
// /var/lib/xhelix/source.db.
func Open(path string) (*Store, error) {
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("source.Open: %w", err)
	}
	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("source.Open: %w", err)
	}
	if err := initGraphSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("source.Open: graph schema: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the on-disk path (":memory:" for in-memory stores).
func (s *Store) Path() string { return s.path }

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS source_anchors (
			id           INTEGER PRIMARY KEY,
			kind         INTEGER NOT NULL,
			parent_id    INTEGER NOT NULL DEFAULT 0,
			created_ns   INTEGER NOT NULL,
			host         TEXT    NOT NULL DEFAULT '',
			actor        TEXT    NOT NULL DEFAULT '',
			uid          INTEGER NOT NULL DEFAULT 0,
			login_uid    INTEGER NOT NULL DEFAULT 0,
			source_ip    TEXT    NOT NULL DEFAULT '',
			source_port  INTEGER NOT NULL DEFAULT 0,
			ssh_key_hash TEXT    NOT NULL DEFAULT '',
			unit         TEXT    NOT NULL DEFAULT '',
			detail       TEXT    NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_anchors_created ON source_anchors (created_ns);
		CREATE INDEX IF NOT EXISTS idx_anchors_parent  ON source_anchors (parent_id);
		CREATE INDEX IF NOT EXISTS idx_anchors_kind    ON source_anchors (kind);
		CREATE INDEX IF NOT EXISTS idx_anchors_actor   ON source_anchors (actor);
	`)
	return err
}

// Put inserts (or replaces by ID) an Anchor.
func (s *Store) Put(ctx context.Context, a Anchor) error {
	if a.ID == 0 {
		return fmt.Errorf("source.Put: anchor ID is 0")
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO source_anchors
		(id, kind, parent_id, created_ns, host, actor, uid, login_uid,
		 source_ip, source_port, ssh_key_hash, unit, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		uint64(a.ID), uint8(a.Kind), uint64(a.ParentAnchorID),
		a.CreatedAt.UnixNano(),
		a.Host, a.Actor, a.UID, a.LoginUID,
		a.SourceIP, a.SourcePort, a.SSHKeyHash, a.Unit, a.Detail,
	)
	if err != nil {
		return fmt.Errorf("source.Put: %w", err)
	}
	return nil
}

// Get returns a single anchor by ID. Returns sql.ErrNoRows if not found.
func (s *Store) Get(ctx context.Context, id lineage.LineageID) (Anchor, error) {
	row := s.db.QueryRowContext(ctx, selectCols+` WHERE id = ?`, uint64(id))
	return scanAnchor(row)
}

// List returns up to limit anchors, newest first. limit <= 0 → 100.
func (s *Store) List(ctx context.Context, limit int) ([]Anchor, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, selectCols+` ORDER BY created_ns DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("source.List: %w", err)
	}
	return scanAnchors(rows)
}

// Children returns anchors whose ParentAnchorID == id, oldest first.
// Used to walk pivot chains (e.g. all sudos that descended from an SSH
// session anchor).
func (s *Store) Children(ctx context.Context, id lineage.LineageID) ([]Anchor, error) {
	rows, err := s.db.QueryContext(ctx,
		selectCols+` WHERE parent_id = ? ORDER BY created_ns ASC`,
		uint64(id),
	)
	if err != nil {
		return nil, fmt.Errorf("source.Children: %w", err)
	}
	return scanAnchors(rows)
}

// Count returns the total number of anchors in the store.
func (s *Store) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM source_anchors`).Scan(&n)
	return n, err
}

// SweepOlderThan deletes anchors whose CreatedAt is before cutoff.
// Returns rows removed. Pivot chains containing children newer than
// cutoff are NOT preserved — caller is expected to retention-tier the
// graph edges (T04), not the anchors themselves.
func (s *Store) SweepOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM source_anchors WHERE created_ns < ?`,
		cutoff.UnixNano(),
	)
	if err != nil {
		return 0, fmt.Errorf("source.SweepOlderThan: %w", err)
	}
	return res.RowsAffected()
}

const selectCols = `SELECT id, kind, parent_id, created_ns, host, actor,
	uid, login_uid, source_ip, source_port, ssh_key_hash, unit, detail
	FROM source_anchors`

// scanner abstracts *sql.Row and *sql.Rows for shared scan logic.
type scanner interface {
	Scan(dest ...any) error
}

func scanAnchor(s scanner) (Anchor, error) {
	var a Anchor
	var idOut, parentID, uid, loginUID, sourcePort uint64
	var kind uint8
	var createdNs int64
	err := s.Scan(
		&idOut, &kind, &parentID, &createdNs,
		&a.Host, &a.Actor, &uid, &loginUID,
		&a.SourceIP, &sourcePort, &a.SSHKeyHash, &a.Unit, &a.Detail,
	)
	if err != nil {
		return Anchor{}, err
	}
	a.ID = lineage.LineageID(idOut)
	a.Kind = Kind(kind)
	a.ParentAnchorID = lineage.LineageID(parentID)
	a.CreatedAt = time.Unix(0, createdNs).UTC()
	a.UID = uint32(uid)
	a.LoginUID = uint32(loginUID)
	a.SourcePort = uint16(sourcePort)
	return a, nil
}

func scanAnchors(rows *sql.Rows) ([]Anchor, error) {
	defer rows.Close()
	out := []Anchor{}
	for rows.Next() {
		a, err := scanAnchor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

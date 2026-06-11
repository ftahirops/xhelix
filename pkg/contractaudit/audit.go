// Package contractaudit is an append-only, hash-chained audit log for
// security-relevant control actions on the behavioral compiler (arm,
// disarm, restart, mode change, delete, breaker reset, app create).
//
// Every record links to the previous one via a SHA-256 chain
// (hash = sha256(prev_hash | canonical(record))), so any deletion or
// in-place edit of a row breaks verification — Verify() names the first
// broken link. This gives tamper-evidence without the full Ed25519 batch
// chain machinery (pkg/chain), which is sized for the high-volume event
// stream, not the low-volume control plane.
package contractaudit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Entry is one audit record. ID/Seq/PrevHash/Hash are assigned by the
// store on Record; callers fill the rest.
type Entry struct {
	Seq       int64     `json:"seq"`
	Time      time.Time `json:"time"`
	Role      string    `json:"role"`       // viewer|operator|admin
	TokenName string    `json:"token_name"` // which credential acted
	SourceIP  string    `json:"source_ip"`
	Action    string    `json:"action"`  // arm|disarm|restart|mode_change|delete|create|breaker_reset
	App       string    `json:"app"`
	Detail    string    `json:"detail,omitempty"`  // units, old→new mode, rolled-back, …
	Outcome   string    `json:"outcome"`           // ok | error: …
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// Store is the SQLite-backed audit log. Safe for concurrent use; writes
// are serialized so the hash chain stays consistent.
type Store struct {
	db *sql.DB

	mu       sync.Mutex
	lastHash string
	lastSeq  int64
}

// Open opens (or creates) the audit store and recovers the chain tip.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("contractaudit: open: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("contractaudit: schema: %w", err)
	}
	s := &Store{db: db}
	if err := s.recoverTip(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// Record appends an entry, computing its chain hash. Returns the stored
// entry with Seq/PrevHash/Hash populated. Never fails silently — a write
// error is returned so the caller can surface it.
func (s *Store) Record(e Entry) (Entry, error) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	e.Seq = s.lastSeq + 1
	e.PrevHash = s.lastHash
	e.Hash = chainHash(e)

	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO audit (seq, ts, role, token_name, source_ip, action, app, detail, outcome, prev_hash, hash)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		e.Seq, e.Time.UnixNano(), e.Role, e.TokenName, e.SourceIP,
		e.Action, e.App, e.Detail, e.Outcome, e.PrevHash, e.Hash,
	)
	if err != nil {
		return Entry{}, fmt.Errorf("contractaudit: insert: %w", err)
	}
	s.lastSeq = e.Seq
	s.lastHash = e.Hash
	return e, nil
}

// List returns the most recent entries (newest first), capped at limit.
func (s *Store) List(limit int) ([]Entry, error) {
	return s.query(`SELECT seq, ts, role, token_name, source_ip, action, app, detail, outcome, prev_hash, hash
		FROM audit ORDER BY seq DESC LIMIT ?`, clampLimit(limit))
}

// ListForApp returns recent entries for one app (newest first).
func (s *Store) ListForApp(app string, limit int) ([]Entry, error) {
	return s.query(`SELECT seq, ts, role, token_name, source_ip, action, app, detail, outcome, prev_hash, hash
		FROM audit WHERE app=? ORDER BY seq DESC LIMIT ?`, app, clampLimit(limit))
}

// VerifyResult is the outcome of a chain integrity walk.
type VerifyResult struct {
	OK          bool   `json:"ok"`
	Checked     int64  `json:"checked"`
	BrokenAtSeq int64  `json:"broken_at_seq,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// Verify walks the entire chain in order and confirms each row's hash and
// its linkage to the prior row. Names the first broken seq on failure.
func (s *Store) Verify() (VerifyResult, error) {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT seq, ts, role, token_name, source_ip, action, app, detail, outcome, prev_hash, hash
		 FROM audit ORDER BY seq ASC`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()

	prev := ""
	var checked int64
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return VerifyResult{}, err
		}
		if e.PrevHash != prev {
			return VerifyResult{OK: false, Checked: checked, BrokenAtSeq: e.Seq,
				Detail: "prev_hash linkage broken (row deleted or reordered)"}, nil
		}
		if chainHash(e) != e.Hash {
			return VerifyResult{OK: false, Checked: checked, BrokenAtSeq: e.Seq,
				Detail: "row hash mismatch (record was edited)"}, nil
		}
		prev = e.Hash
		checked++
	}
	return VerifyResult{OK: true, Checked: checked}, rows.Err()
}

func (s *Store) recoverTip() error {
	row := s.db.QueryRowContext(context.Background(),
		`SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`)
	var seq int64
	var hash string
	switch err := row.Scan(&seq, &hash); err {
	case nil:
		s.lastSeq, s.lastHash = seq, hash
	case sql.ErrNoRows:
		s.lastSeq, s.lastHash = 0, "" // genesis
	default:
		return fmt.Errorf("contractaudit: recover tip: %w", err)
	}
	return nil
}

func (s *Store) query(q string, args ...any) ([]Entry, error) {
	rows, err := s.db.QueryContext(context.Background(), q, args...)
	if err != nil {
		return nil, fmt.Errorf("contractaudit: query: %w", err)
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanEntry(r scanner) (Entry, error) {
	var e Entry
	var tsNano int64
	if err := r.Scan(&e.Seq, &tsNano, &e.Role, &e.TokenName, &e.SourceIP,
		&e.Action, &e.App, &e.Detail, &e.Outcome, &e.PrevHash, &e.Hash); err != nil {
		return Entry{}, err
	}
	e.Time = time.Unix(0, tsNano).UTC()
	return e, nil
}

// chainHash is the canonical, deterministic hash over an entry's content
// plus its predecessor's hash. Field order and the '|' separator are part
// of the contract — changing them invalidates existing chains.
func chainHash(e Entry) string {
	var b strings.Builder
	b.WriteString(e.PrevHash)
	b.WriteByte('|')
	b.WriteString(strconv.FormatInt(e.Seq, 10))
	b.WriteByte('|')
	b.WriteString(strconv.FormatInt(e.Time.UnixNano(), 10))
	for _, f := range []string{e.Role, e.TokenName, e.SourceIP, e.Action, e.App, e.Detail, e.Outcome} {
		b.WriteByte('|')
		b.WriteString(f)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func clampLimit(n int) int {
	if n <= 0 || n > 1000 {
		return 200
	}
	return n
}

const schema = `
CREATE TABLE IF NOT EXISTS audit (
  seq        INTEGER PRIMARY KEY,
  ts         INTEGER NOT NULL,
  role       TEXT NOT NULL,
  token_name TEXT NOT NULL,
  source_ip  TEXT NOT NULL,
  action     TEXT NOT NULL,
  app        TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '',
  outcome    TEXT NOT NULL,
  prev_hash  TEXT NOT NULL,
  hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_app ON audit(app);
`

// Package contractpropose stores CI-submitted deploy proposals (P7).
//
// In the registry-driven model a "deploy" is a proposed change to an app's
// declaration (e.g. a new service binary after a release). CI POSTs the
// proposed declaration; xhelix stores it as PENDING with the compiled
// target hash. An admin reviews the behavioral diff and approves (the
// declaration is applied to the registry) or rejects. CI polls status.
//
// Proposals carry only the declaration content — compilation and diffing
// happen in the web layer against the live registry, so the proposal store
// stays free of the compiler/registry packages.
package contractpropose

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Status is the lifecycle state of a proposal.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

// Proposal is one CI-submitted deploy proposal.
type Proposal struct {
	ID              string    `json:"id"`
	App             string    `json:"app"`
	Status          Status    `json:"status"`
	Submitter       string    `json:"submitter"` // role/credential that proposed
	SourceIP        string    `json:"source_ip"`
	Reason          string    `json:"reason"` // "deploy v1.4.4 git:abc123"
	TargetSHA       string    `json:"target_sha"`
	DeclarationJSON []byte    `json:"-"` // proposed appregistry.App, opaque here
	CreatedAt       time.Time `json:"created_at"`
	DecidedAt       time.Time `json:"decided_at,omitempty"`
	DecidedBy       string    `json:"decided_by,omitempty"`
}

// Store persists proposals.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the proposal store.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("contractpropose: open: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("contractpropose: schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// Create stores a new pending proposal, assigning a random ID.
func (s *Store) Create(p Proposal) (Proposal, error) {
	if p.App == "" {
		return Proposal{}, errors.New("contractpropose: app required")
	}
	id, err := randID()
	if err != nil {
		return Proposal{}, err
	}
	p.ID = id
	p.Status = StatusPending
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	_, err = s.db.ExecContext(context.Background(),
		`INSERT INTO proposals (id, app, status, submitter, source_ip, reason, target_sha, declaration_json, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		p.ID, p.App, string(p.Status), p.Submitter, p.SourceIP, p.Reason,
		p.TargetSHA, string(p.DeclarationJSON), p.CreatedAt.Unix(),
	)
	if err != nil {
		return Proposal{}, fmt.Errorf("contractpropose: insert: %w", err)
	}
	return p, nil
}

// Get returns one proposal scoped to an app (so an ID from one app can't
// address another's proposal).
func (s *Store) Get(app, id string) (*Proposal, bool) {
	row := s.db.QueryRowContext(context.Background(),
		`SELECT id, app, status, submitter, source_ip, reason, target_sha, declaration_json, created_at, decided_at, decided_by
		 FROM proposals WHERE app=? AND id=?`, app, id)
	p, err := scan(row)
	if err != nil {
		return nil, false
	}
	return p, true
}

// ListForApp returns proposals for an app, newest first.
func (s *Store) ListForApp(app string, limit int) ([]Proposal, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT id, app, status, submitter, source_ip, reason, target_sha, declaration_json, created_at, decided_at, decided_by
		 FROM proposals WHERE app=? ORDER BY created_at DESC LIMIT ?`, app, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Proposal
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// Decide sets a terminal status (approved/rejected) on a pending proposal.
// Fails if the proposal isn't pending, so a decision can't be double-applied.
func (s *Store) Decide(app, id string, status Status, by string) error {
	if status != StatusApproved && status != StatusRejected {
		return fmt.Errorf("contractpropose: invalid decision %q", status)
	}
	res, err := s.db.ExecContext(context.Background(),
		`UPDATE proposals SET status=?, decided_at=?, decided_by=?
		 WHERE app=? AND id=? AND status=?`,
		string(status), time.Now().Unix(), by, app, id, string(StatusPending))
	if err != nil {
		return fmt.Errorf("contractpropose: decide: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("contractpropose: proposal not found or not pending")
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scan(r scanner) (*Proposal, error) {
	var p Proposal
	var status, decl string
	var created int64
	var decided sql.NullInt64
	var decidedBy sql.NullString
	if err := r.Scan(&p.ID, &p.App, &status, &p.Submitter, &p.SourceIP, &p.Reason,
		&p.TargetSHA, &decl, &created, &decided, &decidedBy); err != nil {
		return nil, err
	}
	p.Status = Status(status)
	p.DeclarationJSON = []byte(decl)
	p.CreatedAt = time.Unix(created, 0)
	if decided.Valid {
		p.DecidedAt = time.Unix(decided.Int64, 0)
	}
	if decidedBy.Valid {
		p.DecidedBy = decidedBy.String
	}
	return &p, nil
}

func randID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("contractpropose: id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

const schema = `
CREATE TABLE IF NOT EXISTS proposals (
  id               TEXT PRIMARY KEY,
  app              TEXT NOT NULL,
  status           TEXT NOT NULL,
  submitter        TEXT NOT NULL DEFAULT '',
  source_ip        TEXT NOT NULL DEFAULT '',
  reason           TEXT NOT NULL DEFAULT '',
  target_sha       TEXT NOT NULL DEFAULT '',
  declaration_json TEXT NOT NULL,
  created_at       INTEGER NOT NULL,
  decided_at       INTEGER,
  decided_by       TEXT
);
CREATE INDEX IF NOT EXISTS idx_proposals_app ON proposals(app);
`

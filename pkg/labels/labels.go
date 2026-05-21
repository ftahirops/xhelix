// Package labels is the local verdict store. Operators label
// alerts as TP / FP / unknown via `xhelixctl alerts label`; the
// labels accumulate in /var/lib/xhelix/labels.db (SQLite). The
// store is the ground-truth input to:
//
//   - per-rule FP-rate measurement (ALERTS_AND_FP_PLAN §4)
//   - the soak gate's "rule day-N clean → enforce eligible"
//     promotion logic
//   - the replay tool's regression detection (does a rule edit
//     stop the labelled FPs while keeping the labelled TPs?)
//
// Design: append-only writes, idempotent on (event_id), small
// schema. No assumption about how many alerts exist — the store
// only holds labels, not the alerts themselves (those stay in
// alerts.jsonl + cold.db).
//
// CGO_ENABLED=0 — modernc.org/sqlite via the same driver as the
// rest of xhelix.
package labels

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Verdict is the operator's call on an alert.
type Verdict string

const (
	VerdictUnknown Verdict = "unknown"
	VerdictTP      Verdict = "tp"
	VerdictFP      Verdict = "fp"
	VerdictBenign  Verdict = "benign" // alert is correct that something happened but it's not malicious
)

// Validate returns nil iff v is a known verdict.
func (v Verdict) Validate() error {
	switch v {
	case VerdictUnknown, VerdictTP, VerdictFP, VerdictBenign:
		return nil
	}
	return fmt.Errorf("unknown verdict %q (want tp|fp|benign|unknown)", v)
}

// Label is one operator verdict on one alert.
type Label struct {
	EventID    string    // ULID from alerts.jsonl event.id
	RuleID     string    // rule_id at the time of labelling
	Verdict    Verdict
	Tag        string    // free-text operator tag (e.g. "ansible-deploy", "node-jit")
	By         string    // who labelled — defaults to os.Getenv("USER")
	At         time.Time // when
	HostClass  string    // optional host classification (dev_ws, prod_web, prod_db)
	RuleVer    string    // rule version at label time (git-commit-derived if available)
	Notes      string    // free-text
}

// Store is the labels DB. Safe for concurrent use.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the labels DB at path. Path "" or
// ":memory:" gives an in-memory DB (for tests).
func Open(path string) (*Store, error) {
	if path == "" {
		path = ":memory:"
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open labels db: %w", err)
	}
	if _, err := db.Exec(schemaDDL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

const schemaDDL = `
CREATE TABLE IF NOT EXISTS labels (
    event_id    TEXT PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    verdict     TEXT NOT NULL CHECK (verdict IN ('tp','fp','benign','unknown')),
    tag         TEXT NOT NULL DEFAULT '',
    by          TEXT NOT NULL DEFAULT '',
    at_unix     INTEGER NOT NULL,
    host_class  TEXT NOT NULL DEFAULT '',
    rule_ver    TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS labels_rule_verdict ON labels(rule_id, verdict);
CREATE INDEX IF NOT EXISTS labels_at ON labels(at_unix);
`

// Put writes (or replaces) a label.
func (s *Store) Put(l Label) error {
	if l.EventID == "" {
		return errors.New("EventID required")
	}
	if err := l.Verdict.Validate(); err != nil {
		return err
	}
	if l.At.IsZero() {
		l.At = time.Now().UTC()
	}
	_, err := s.db.Exec(`
INSERT INTO labels (event_id, rule_id, verdict, tag, by, at_unix, host_class, rule_ver, notes)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(event_id) DO UPDATE SET
  rule_id    = excluded.rule_id,
  verdict    = excluded.verdict,
  tag        = excluded.tag,
  by         = excluded.by,
  at_unix    = excluded.at_unix,
  host_class = excluded.host_class,
  rule_ver   = excluded.rule_ver,
  notes      = excluded.notes
`, l.EventID, l.RuleID, string(l.Verdict), l.Tag, l.By, l.At.Unix(),
		l.HostClass, l.RuleVer, l.Notes)
	return err
}

// Get returns the label for an event_id, or (Label{}, false) if
// no label has been recorded.
func (s *Store) Get(eventID string) (Label, bool, error) {
	row := s.db.QueryRow(`
SELECT event_id, rule_id, verdict, tag, by, at_unix, host_class, rule_ver, notes
FROM labels WHERE event_id = ?
`, eventID)
	var l Label
	var atUnix int64
	var v string
	err := row.Scan(&l.EventID, &l.RuleID, &v, &l.Tag, &l.By, &atUnix,
		&l.HostClass, &l.RuleVer, &l.Notes)
	if errors.Is(err, sql.ErrNoRows) {
		return Label{}, false, nil
	}
	if err != nil {
		return Label{}, false, err
	}
	l.Verdict = Verdict(v)
	l.At = time.Unix(atUnix, 0).UTC()
	return l, true, nil
}

// Stats summarizes label counts per rule_id.
type Stats struct {
	RuleID         string
	TP, FP, Benign int
	Unknown        int
	FirstAt, LastAt time.Time
}

// PerRule returns aggregate stats per rule_id over a time window.
// If since.IsZero() the window is the whole DB.
func (s *Store) PerRule(since time.Time) ([]Stats, error) {
	q := `
SELECT rule_id,
       SUM(CASE WHEN verdict='tp' THEN 1 ELSE 0 END)      AS tp,
       SUM(CASE WHEN verdict='fp' THEN 1 ELSE 0 END)      AS fp,
       SUM(CASE WHEN verdict='benign' THEN 1 ELSE 0 END)  AS benign,
       SUM(CASE WHEN verdict='unknown' THEN 1 ELSE 0 END) AS unknown,
       MIN(at_unix), MAX(at_unix)
FROM labels
`
	args := []any{}
	if !since.IsZero() {
		q += ` WHERE at_unix >= ?`
		args = append(args, since.Unix())
	}
	q += ` GROUP BY rule_id ORDER BY (tp+fp+benign+unknown) DESC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Stats
	for rows.Next() {
		var st Stats
		var first, last int64
		if err := rows.Scan(&st.RuleID, &st.TP, &st.FP, &st.Benign,
			&st.Unknown, &first, &last); err != nil {
			return nil, err
		}
		st.FirstAt = time.Unix(first, 0).UTC()
		st.LastAt = time.Unix(last, 0).UTC()
		out = append(out, st)
	}
	return out, rows.Err()
}

// FPSet returns the (rule_id, tag) pairs that are known FPs in
// the window. Replay uses this to compute "did my rule change kill
// the FPs without dropping TPs?".
type FPKey struct {
	RuleID string
	Tag    string
}

func (s *Store) FPSet(since time.Time) (map[FPKey]int, error) {
	q := `
SELECT rule_id, tag, COUNT(*) FROM labels
WHERE verdict = 'fp'
`
	args := []any{}
	if !since.IsZero() {
		q += ` AND at_unix >= ?`
		args = append(args, since.Unix())
	}
	q += ` GROUP BY rule_id, tag`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[FPKey]int{}
	for rows.Next() {
		var k FPKey
		var n int
		if err := rows.Scan(&k.RuleID, &k.Tag, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// Count returns the total number of labels in the DB. Useful for
// stats/health endpoints.
func (s *Store) Count() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM labels`).Scan(&n)
	return n, err
}

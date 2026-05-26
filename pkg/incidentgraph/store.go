package incidentgraph

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed audit + recovery store for incidents.
//
// The in-memory engine is the working set; the store is the audit
// trail. Pattern matches pkg/source: pure-Go modernc.org/sqlite, WAL
// mode, NORMAL synchronous, 5s busy timeout.
//
// Two tables:
//
//   incidents       — one row per incident, latest state
//   incident_events — append-only audit of state transitions (open,
//                     update, close, sweep)
//
// On daemon restart, OpenStore + LoadOpen can rehydrate the engine's
// open set so incidents survive crash.
type Store struct {
	db   *sql.DB
	path string
}

// OpenStore opens/creates an incident store at path. ":memory:" for
// tests.
func OpenStore(path string) (*Store, error) {
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("incidentgraph.OpenStore: %w", err)
	}
	if err := initIncidentSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("incidentgraph.OpenStore: schema: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the on-disk path.
func (s *Store) Path() string { return s.path }

func initIncidentSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS incidents (
			id           TEXT PRIMARY KEY,
			started_ns   INTEGER NOT NULL,
			updated_ns   INTEGER NOT NULL,
			severity     TEXT    NOT NULL,
			confidence   REAL    NOT NULL,
			intent       TEXT    NOT NULL,
			summary      TEXT    NOT NULL,
			closed       INTEGER NOT NULL DEFAULT 0,
			close_reason TEXT    NOT NULL DEFAULT '',
			closed_ns    INTEGER NOT NULL DEFAULT 0,
			payload_json TEXT    NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents (updated_ns);
		CREATE INDEX IF NOT EXISTS idx_incidents_open    ON incidents (closed, updated_ns);

		CREATE TABLE IF NOT EXISTS incident_events (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			incident_id   TEXT    NOT NULL,
			ts_ns         INTEGER NOT NULL,
			kind          TEXT    NOT NULL,
			detail        TEXT    NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_inc_events_inc ON incident_events (incident_id, ts_ns);
	`)
	return err
}

// Upsert writes the incident's latest state. Idempotent on incident.ID.
func (s *Store) Upsert(inc Incident) error {
	payload, err := json.Marshal(inc)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO incidents (id, started_ns, updated_ns, severity, confidence,
			intent, summary, closed, close_reason, closed_ns, payload_json)
		VALUES (?,?,?,?,?,?,?,0,'',0,?)
		ON CONFLICT(id) DO UPDATE SET
			updated_ns=excluded.updated_ns,
			severity=excluded.severity,
			confidence=excluded.confidence,
			intent=excluded.intent,
			summary=excluded.summary,
			payload_json=excluded.payload_json
		WHERE incidents.closed=0
	`,
		inc.ID, inc.StartedAt.UnixNano(), inc.UpdatedAt.UnixNano(),
		string(inc.Severity), inc.Confidence,
		string(inc.Intent), inc.Summary, string(payload),
	)
	return err
}

// MarkClosed marks the row closed and records an audit event. Returns
// false if no such open incident existed.
func (s *Store) MarkClosed(id, reason string, at time.Time) (bool, error) {
	res, err := s.db.Exec(`
		UPDATE incidents
		SET closed=1, close_reason=?, closed_ns=?
		WHERE id=? AND closed=0
	`, reason, at.UnixNano(), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	_, _ = s.db.Exec(`INSERT INTO incident_events (incident_id, ts_ns, kind, detail) VALUES (?,?,?,?)`,
		id, at.UnixNano(), "close", reason)
	return true, nil
}

// LoadOpen returns all currently-open incidents (closed=0), most
// recent first. Used at daemon startup to rehydrate the in-memory
// engine.
func (s *Store) LoadOpen() ([]Incident, error) {
	rows, err := s.db.Query(`SELECT payload_json FROM incidents WHERE closed=0 ORDER BY updated_ns DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var inc Incident
		if err := json.Unmarshal([]byte(payload), &inc); err != nil {
			slog.Warn("incidentgraph.LoadOpen: skip malformed payload", "err", err)
			continue
		}
		out = append(out, inc)
	}
	return out, rows.Err()
}

// LoadAll returns recent incidents (open + closed) up to limit, most
// recent first. Used by `xhelixctl incidents list --all`.
func (s *Store) LoadAll(limit int) ([]Incident, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT payload_json FROM incidents ORDER BY updated_ns DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var inc Incident
		if err := json.Unmarshal([]byte(payload), &inc); err != nil {
			continue
		}
		out = append(out, inc)
	}
	return out, rows.Err()
}

// Get returns one incident by ID (open or closed).
func (s *Store) Get(id string) (Incident, bool, error) {
	row := s.db.QueryRow(`SELECT payload_json FROM incidents WHERE id=?`, id)
	var payload string
	if err := row.Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return Incident{}, false, nil
		}
		return Incident{}, false, err
	}
	var inc Incident
	if err := json.Unmarshal([]byte(payload), &inc); err != nil {
		return Incident{}, false, err
	}
	return inc, true, nil
}

// PersistingEngine wraps an in-memory Engine and writes every
// mutation through to a Store. Cheap (one INSERT-or-UPDATE per
// observe) — measured at ~50µs/event on dev hardware. If write
// throughput becomes a concern, add a coalescing flusher in a
// follow-on.
type PersistingEngine struct {
	Engine
	store *Store
}

// NewPersistingEngine wraps base with persistence. On startup,
// hydrates the in-memory engine from the store.
func NewPersistingEngine(base Engine, store *Store) (*PersistingEngine, error) {
	open, err := store.LoadOpen()
	if err != nil {
		return nil, fmt.Errorf("hydrate: %w", err)
	}
	// Restore the working set directly via Seed. Observe is now
	// enrich-only, so it would NOT restore a routing map from a
	// synthetic event — we have to insert directly.
	type seeder interface{ Seed(Incident) }
	if sd, ok := base.(seeder); ok {
		for _, inc := range open {
			sd.Seed(inc)
		}
	}
	return &PersistingEngine{Engine: base, store: store}, nil
}

func (e *PersistingEngine) Observe(ev Event) {
	e.Engine.Observe(ev)
	e.flushFor(ev.SourceID, ev.LineageID)
}

func (e *PersistingEngine) ObserveAlert(a Alert) {
	e.Engine.ObserveAlert(a)
	e.flushFor(a.SourceID, a.LineageID)
}

func (e *PersistingEngine) ObserveVerifierResult(ev Event, vr VerifierResult) {
	e.Engine.ObserveVerifierResult(ev, vr)
	e.flushFor(ev.SourceID, ev.LineageID)
}

func (e *PersistingEngine) Close(id, reason string) bool {
	ok := e.Engine.Close(id, reason)
	if ok {
		_, _ = e.store.MarkClosed(id, reason, time.Now())
	}
	return ok
}

// flushFor writes the currently-routed incident to disk after a
// mutation. O(1) — resolves via the engine's routing API rather
// than scanning Snapshot, so per-event cost stays bounded as the
// open set grows.
func (e *PersistingEngine) flushFor(sourceID, lineageID uint64) {
	r, ok := e.Engine.(router)
	if !ok {
		return
	}
	inc, found := r.RouteSnapshot(sourceID, lineageID)
	if !found {
		return
	}
	if err := e.store.Upsert(inc); err != nil {
		slog.Warn("incidentgraph.Upsert failed", "id", inc.ID, "err", err)
	}
}

// router is the optional fast-path interface implementations satisfy
// to expose their routing maps for O(1) persist flush. memEngine
// satisfies it.
type router interface {
	RouteSnapshot(sourceID, lineageID uint64) (Incident, bool)
}

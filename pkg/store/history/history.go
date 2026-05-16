// Package history is the SQLite-backed narrative network history
// store specified in docs/NETWORK_TELEMETRY_AND_HISTORY.md.
//
// Five tables: sessions, processes, activities, dns_queries, flows.
// Each is append-mostly. A background pruner trims by per-table
// retention windows (flows 7 days, dns 14 days, activities 90 days).
//
// This package is intentionally minimal: schema migrations, typed
// insert helpers, retention prune. Queryable views (per-binary
// fanout, country aggregations, etc.) live in pkg/netquery and
// are pure SQL on top of this schema.
//
// Driver: modernc.org/sqlite (CGO-free), same as pkg/store/hot.
package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the history database handle.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens or creates the history database at path.
// path may be ":memory:" for tests.
func Open(path string) (*Store, error) {
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open history store: %w", err)
	}
	if err := applySchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// DB returns the underlying sql.DB for callers that need raw
// queries (e.g. pkg/netquery). Use sparingly — prefer the typed
// helpers below.
func (s *Store) DB() *sql.DB { return s.db }

// ── Session ────────────────────────────────────────────────────

// Session represents one user/system/container session.
type Session struct {
	ID           int64
	Kind         string // "login" | "system_boot" | "container_start"
	Subject      string // username / hostname / container id
	CGroupClass  string
	StartedAt    time.Time
	EndedAt      *time.Time // nil if still active
}

// InsertSession adds a new session row and returns its assigned id.
func (s *Store) InsertSession(ctx context.Context, sess Session) (int64, error) {
	var ended *int64
	if sess.EndedAt != nil {
		v := sess.EndedAt.Unix()
		ended = &v
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (kind, subject, cgroup_class, started_at, ended_at)
		VALUES (?, ?, ?, ?, ?)
	`, sess.Kind, sess.Subject, sess.CGroupClass, sess.StartedAt.Unix(), ended)
	if err != nil {
		return 0, fmt.Errorf("insert session: %w", err)
	}
	return res.LastInsertId()
}

// EndSession sets ended_at for an existing session id.
func (s *Store) EndSession(ctx context.Context, id int64, when time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET ended_at = ? WHERE id = ? AND ended_at IS NULL`,
		when.Unix(), id)
	return err
}

// ── Process ────────────────────────────────────────────────────

// Process represents one observed process.
type Process struct {
	ID           int64
	SessionID    int64 // 0 if unknown
	PID          uint32
	PPID         uint32
	Comm         string
	Exe          string
	ExeSHA       string
	CGroupClass  string
	Unit         string
	UserID       string
	StartedAt    time.Time
	EndedAt      *time.Time
}

// InsertProcess adds a process row and returns its assigned id.
func (s *Store) InsertProcess(ctx context.Context, p Process) (int64, error) {
	var ended *int64
	if p.EndedAt != nil {
		v := p.EndedAt.Unix()
		ended = &v
	}
	var sessID *int64
	if p.SessionID != 0 {
		v := p.SessionID
		sessID = &v
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO processes (session_id, pid, ppid, comm, exe, exe_sha,
			cgroup_class, unit, user_id, started_at, ended_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, sessID, p.PID, p.PPID, p.Comm, p.Exe, p.ExeSHA,
		p.CGroupClass, p.Unit, p.UserID, p.StartedAt.Unix(), ended)
	if err != nil {
		return 0, fmt.Errorf("insert process: %w", err)
	}
	return res.LastInsertId()
}

// EndProcess sets ended_at for an existing process id.
func (s *Store) EndProcess(ctx context.Context, id int64, when time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE processes SET ended_at = ? WHERE id = ? AND ended_at IS NULL`,
		when.Unix(), id)
	return err
}

// ── Activity ───────────────────────────────────────────────────

// Activity is one clustered network activity (per-page-load /
// per-app-burst). Populated by pkg/activity (Phase B).
type Activity struct {
	ID           int64
	ProcessID    int64
	StartedAt    time.Time
	EndedAt      time.Time
	PrimaryHost  string
	RelatedHosts []string
	PrimaryIP    string
	RelatedIPs   []string
	Countries    []string
	ASNs         []string
	BytesIn      uint64
	BytesOut     uint64
	FlowCount    int
	Verdict      string // "green" | "amber" | "red" | "opaque"
	VerdictScore float64
	Reasons      []string
	Protocols    string // "tcp,udp" etc.
}

// InsertActivity adds an activity row and returns its assigned id.
func (s *Store) InsertActivity(ctx context.Context, a Activity) (int64, error) {
	rh, _ := json.Marshal(a.RelatedHosts)
	ri, _ := json.Marshal(a.RelatedIPs)
	cn, _ := json.Marshal(a.Countries)
	as, _ := json.Marshal(a.ASNs)
	rs, _ := json.Marshal(a.Reasons)
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO activities (process_id, started_at, ended_at,
			primary_host, related_hosts, primary_ip, related_ips,
			countries, asns, bytes_in, bytes_out, flow_count,
			verdict, verdict_score, reasons, protocols)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, a.ProcessID, a.StartedAt.Unix(), a.EndedAt.Unix(),
		a.PrimaryHost, string(rh), a.PrimaryIP, string(ri),
		string(cn), string(as), a.BytesIn, a.BytesOut, a.FlowCount,
		a.Verdict, a.VerdictScore, string(rs), a.Protocols)
	if err != nil {
		return 0, fmt.Errorf("insert activity: %w", err)
	}
	return res.LastInsertId()
}

// ── DNS query ──────────────────────────────────────────────────

// DNSQuery is one resolution observation.
type DNSQuery struct {
	ID        int64
	ProcessID int64
	AskedAt   time.Time
	QName     string
	QType     string
	Answers   []string
	Upstream  string
	Encrypted bool
}

// InsertDNSQuery appends a DNS observation.
func (s *Store) InsertDNSQuery(ctx context.Context, q DNSQuery) (int64, error) {
	ans, _ := json.Marshal(q.Answers)
	enc := 0
	if q.Encrypted {
		enc = 1
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO dns_queries (process_id, asked_at, qname, qtype,
			answers, upstream, encrypted)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, q.ProcessID, q.AskedAt.Unix(), q.QName, q.QType,
		string(ans), q.Upstream, enc)
	if err != nil {
		return 0, fmt.Errorf("insert dns: %w", err)
	}
	return res.LastInsertId()
}

// ── Flow ───────────────────────────────────────────────────────

// Flow is one raw L4 flow (TCP/UDP/ICMP).
type Flow struct {
	ID         int64
	ActivityID int64 // 0 = not yet clustered
	ProcessID  int64
	Proto      string // "tcp" | "udp" | "icmp"
	SrcIP      string
	SrcPort    uint16
	DstIP      string
	DstPort    uint16
	State      string
	OpenedAt   time.Time
	ClosedAt   *time.Time
	BytesIn    uint64
	BytesOut   uint64
	DNSQName   string
	Country    string
	ASN        string
}

// InsertFlow appends a raw flow.
func (s *Store) InsertFlow(ctx context.Context, f Flow) (int64, error) {
	var closed *int64
	if f.ClosedAt != nil {
		v := f.ClosedAt.Unix()
		closed = &v
	}
	var actID *int64
	if f.ActivityID != 0 {
		v := f.ActivityID
		actID = &v
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO flows (activity_id, process_id, proto, src_ip, src_port,
			dst_ip, dst_port, state, opened_at, closed_at, bytes_in, bytes_out,
			dns_qname, country, asn)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, actID, f.ProcessID, f.Proto, f.SrcIP, f.SrcPort,
		f.DstIP, f.DstPort, f.State, f.OpenedAt.Unix(), closed,
		f.BytesIn, f.BytesOut, f.DNSQName, f.Country, f.ASN)
	if err != nil {
		return 0, fmt.Errorf("insert flow: %w", err)
	}
	return res.LastInsertId()
}

// ── Counts ─────────────────────────────────────────────────────

// Counts returns row counts for status reporting.
type Counts struct {
	Sessions   int64
	Processes  int64
	Activities int64
	DNSQueries int64
	Flows      int64
}

// Counts returns row counts across all tables.
func (s *Store) Counts(ctx context.Context) (Counts, error) {
	var c Counts
	rows := []struct {
		out  *int64
		stmt string
	}{
		{&c.Sessions, `SELECT COUNT(*) FROM sessions`},
		{&c.Processes, `SELECT COUNT(*) FROM processes`},
		{&c.Activities, `SELECT COUNT(*) FROM activities`},
		{&c.DNSQueries, `SELECT COUNT(*) FROM dns_queries`},
		{&c.Flows, `SELECT COUNT(*) FROM flows`},
	}
	for _, r := range rows {
		if err := s.db.QueryRowContext(ctx, r.stmt).Scan(r.out); err != nil {
			return c, err
		}
	}
	return c, nil
}

// ── Retention ──────────────────────────────────────────────────

// Retention configures per-table data retention. Zero means
// "use default". Defaults: flows 7d, dns 14d, activities 90d,
// processes 90d, sessions 90d.
type Retention struct {
	Flows      time.Duration
	DNS        time.Duration
	Activities time.Duration
	Processes  time.Duration
	Sessions   time.Duration
}

// DefaultRetention is the documented default schedule.
func DefaultRetention() Retention {
	return Retention{
		Flows:      7 * 24 * time.Hour,
		DNS:        14 * 24 * time.Hour,
		Activities: 90 * 24 * time.Hour,
		Processes:  90 * 24 * time.Hour,
		Sessions:   90 * 24 * time.Hour,
	}
}

// PruneResult tallies what Prune removed.
type PruneResult struct {
	Flows      int64
	DNSQueries int64
	Activities int64
	Processes  int64
	Sessions   int64
}

// Prune deletes rows older than the configured retention windows,
// relative to `now`. Returns the per-table delete counts. Safe to
// call on a running daemon; runs as five separate DELETEs.
func (s *Store) Prune(ctx context.Context, r Retention, now time.Time) (PruneResult, error) {
	if r.Flows == 0 {
		r = DefaultRetention()
	}
	var res PruneResult
	type prune struct {
		out    *int64
		stmt   string
		cutoff int64
	}
	jobs := []prune{
		{&res.Flows, `DELETE FROM flows WHERE opened_at < ?`,
			now.Add(-r.Flows).Unix()},
		{&res.DNSQueries, `DELETE FROM dns_queries WHERE asked_at < ?`,
			now.Add(-r.DNS).Unix()},
		{&res.Activities, `DELETE FROM activities WHERE ended_at < ?`,
			now.Add(-r.Activities).Unix()},
		{&res.Processes, `DELETE FROM processes WHERE ended_at IS NOT NULL AND ended_at < ?`,
			now.Add(-r.Processes).Unix()},
		{&res.Sessions, `DELETE FROM sessions WHERE ended_at IS NOT NULL AND ended_at < ?`,
			now.Add(-r.Sessions).Unix()},
	}
	for _, j := range jobs {
		r, err := s.db.ExecContext(ctx, j.stmt, j.cutoff)
		if err != nil {
			return res, fmt.Errorf("prune: %w", err)
		}
		n, _ := r.RowsAffected()
		*j.out = n
	}
	return res, nil
}

// ── Schema ─────────────────────────────────────────────────────

// applySchema creates all tables and indices if absent. Idempotent.
func applySchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS sessions (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			kind          TEXT NOT NULL,
			subject       TEXT,
			cgroup_class  TEXT,
			started_at    INTEGER NOT NULL,
			ended_at      INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_subject ON sessions(subject)`,

		`CREATE TABLE IF NOT EXISTS processes (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id    INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
			pid           INTEGER NOT NULL,
			ppid          INTEGER,
			comm          TEXT,
			exe           TEXT,
			exe_sha       TEXT,
			cgroup_class  TEXT,
			unit          TEXT,
			user_id       TEXT,
			started_at    INTEGER NOT NULL,
			ended_at      INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_proc_session  ON processes(session_id)`,
		`CREATE INDEX IF NOT EXISTS idx_proc_started  ON processes(started_at)`,
		`CREATE INDEX IF NOT EXISTS idx_proc_exe      ON processes(exe)`,
		`CREATE INDEX IF NOT EXISTS idx_proc_exe_sha  ON processes(exe_sha)`,

		`CREATE TABLE IF NOT EXISTS activities (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			process_id    INTEGER NOT NULL REFERENCES processes(id) ON DELETE CASCADE,
			started_at    INTEGER NOT NULL,
			ended_at      INTEGER NOT NULL,
			primary_host  TEXT,
			related_hosts TEXT,
			primary_ip    TEXT,
			related_ips   TEXT,
			countries     TEXT,
			asns          TEXT,
			bytes_in      INTEGER DEFAULT 0,
			bytes_out     INTEGER DEFAULT 0,
			flow_count    INTEGER DEFAULT 0,
			verdict       TEXT,
			verdict_score REAL,
			reasons       TEXT,
			protocols     TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_act_proc     ON activities(process_id)`,
		`CREATE INDEX IF NOT EXISTS idx_act_started  ON activities(started_at)`,
		`CREATE INDEX IF NOT EXISTS idx_act_verdict  ON activities(verdict)`,
		`CREATE INDEX IF NOT EXISTS idx_act_host     ON activities(primary_host)`,

		`CREATE TABLE IF NOT EXISTS dns_queries (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			process_id  INTEGER REFERENCES processes(id) ON DELETE CASCADE,
			asked_at    INTEGER NOT NULL,
			qname       TEXT NOT NULL,
			qtype       TEXT,
			answers     TEXT,
			upstream    TEXT,
			encrypted   INTEGER DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_proc   ON dns_queries(process_id)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_qname  ON dns_queries(qname)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_asked  ON dns_queries(asked_at)`,

		`CREATE TABLE IF NOT EXISTS flows (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			activity_id  INTEGER REFERENCES activities(id) ON DELETE SET NULL,
			process_id   INTEGER REFERENCES processes(id) ON DELETE CASCADE,
			proto        TEXT NOT NULL,
			src_ip       TEXT,
			src_port     INTEGER,
			dst_ip       TEXT,
			dst_port     INTEGER,
			state        TEXT,
			opened_at    INTEGER NOT NULL,
			closed_at    INTEGER,
			bytes_in     INTEGER DEFAULT 0,
			bytes_out    INTEGER DEFAULT 0,
			dns_qname    TEXT,
			country      TEXT,
			asn          TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_flow_activity ON flows(activity_id)`,
		`CREATE INDEX IF NOT EXISTS idx_flow_process  ON flows(process_id)`,
		`CREATE INDEX IF NOT EXISTS idx_flow_dst      ON flows(dst_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_flow_opened   ON flows(opened_at)`,
		`CREATE INDEX IF NOT EXISTS idx_flow_country  ON flows(country)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("schema stmt: %w", err)
		}
	}
	return nil
}

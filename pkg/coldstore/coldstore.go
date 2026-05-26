// Package coldstore is the durable event store. Events flow through a
// bounded write-behind queue into SQLite tables partitioned by UTC day.
//
// Why per-day tables: pruning a day = DROP TABLE (instant). Indices
// stay small. Queries that span days UNION the per-day tables; queries
// scoped to a single day touch one small table.
//
// Why write-behind: the rule engine, alert bus, and dispatch loop
// cannot tolerate disk latency on the hot path. The Submit call
// drops the event into an in-memory ring; a flusher goroutine batches
// rows and writes them in transactions. On overflow we drop OLDEST
// (not newest) — a noisy bursty sensor must not bury an ongoing
// investigation's recent context.
//
// Constraints:
//   - CGO_ENABLED=0 → modernc.org/sqlite driver
//   - WAL mode + synchronous=NORMAL for durability/throughput balance
//   - Targets: 30k events/s sustained, no growth in queue under load
package coldstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"github.com/xhelix/xhelix/pkg/model"
)

// Options configures the Store.
type Options struct {
	// Path is the on-disk DB file. The directory is created with
	// 0o750 if missing. Required.
	Path string

	// QueueSize is the in-memory write-behind queue capacity.
	// Submit drops the oldest entry when full. Default: 262144 (256k).
	QueueSize int

	// BatchSize is the maximum rows per write transaction. Default: 1000.
	BatchSize int

	// FlushInterval forces a flush even if the batch is not full.
	// Default: 1 s.
	FlushInterval time.Duration

	// RetentionDays caps how many day-partition tables are kept.
	// DropOldDays() removes every events_YYYYMMDD whose UTC day is
	// older than RetentionDays days ago. 0 = use default (14 days).
	// Negative = no pruning (keep forever — disk-fill risk).
	//
	// Per ERRORS.md: cold.db grew unbounded because per-day tables
	// were created but never dropped. The Witness contract from
	// pkg/configaudit requires this knob to have a consumer.
	RetentionDays int
}

// Store is the cold-store handle. Construct with New, call Start to
// begin flushing, Submit per event, Close on shutdown.
type Store struct {
	db   *sql.DB
	path string

	queueSize     int
	batchSize     int
	flushInterval time.Duration
	retentionDays int

	queueMu   sync.Mutex
	queue     []*model.Event // ring buffer-ish — append, drop-oldest on overflow
	queueCond *sync.Cond

	// Daily partition state.
	currentTableMu sync.Mutex
	currentTable   string // events_YYYYMMDD; lazily created

	// Counters.
	submitted atomic.Uint64
	dropped   atomic.Uint64
	written   atomic.Uint64
	batches   atomic.Uint64
	flushErrs atomic.Uint64
	rotations atomic.Uint64

	started atomic.Bool
	closed  atomic.Bool
	done    chan struct{}
}

// New opens the SQLite database, applies pragmas, and prepares the
// store. Does not start the flusher — call Start.
func New(opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("coldstore: Path is required")
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = 256 * 1024
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 1000
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = time.Second
	}
	if opts.RetentionDays == 0 {
		opts.RetentionDays = 14
	}

	// Use _pragma URL params so the pragmas are applied on every
	// connection in the pool. modernc.org/sqlite supports this.
	dsn := opts.Path + "?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=journal_size_limit(67108864)" + // 64 MB
		"&_pragma=temp_store(MEMORY)" +
		"&_pragma=busy_timeout(5000)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("coldstore open: %w", err)
	}
	// SQLite is single-writer; pooling more than 1 doesn't help and
	// invites lock contention.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("coldstore ping: %w", err)
	}

	s := &Store{
		db:            db,
		path:          opts.Path,
		queueSize:     opts.QueueSize,
		batchSize:     opts.BatchSize,
		flushInterval: opts.FlushInterval,
		retentionDays: opts.RetentionDays,
		queue:         make([]*model.Event, 0, opts.QueueSize),
		done:          make(chan struct{}),
	}
	s.queueCond = sync.NewCond(&s.queueMu)

	// Pre-create today's table so the first event lands without
	// extra schema work.
	if _, err := s.ensureTableForUTC(time.Now().UTC()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Start launches the flusher goroutine. Safe to call once.
func (s *Store) Start(ctx context.Context) {
	if !s.started.CompareAndSwap(false, true) {
		return
	}
	go s.runFlusher(ctx)
}

// Close stops the flusher (drains the queue once) and closes the DB.
func (s *Store) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(s.done)
	// Wake the flusher in case it's blocked on the condvar.
	s.queueMu.Lock()
	s.queueCond.Broadcast()
	s.queueMu.Unlock()
	// Best-effort final flush in the calling goroutine.
	_ = s.flushOnce()
	return s.db.Close()
}

// Submit enqueues an event for durable write. Never blocks; if the
// queue is full, drops the oldest entry and bumps the dropped counter.
func (s *Store) Submit(e *model.Event) {
	if e == nil || s.closed.Load() {
		return
	}
	s.submitted.Add(1)
	s.queueMu.Lock()
	if len(s.queue) >= s.queueSize {
		// Drop oldest by reslicing — keep the tail.
		s.queue = s.queue[1:]
		s.dropped.Add(1)
	}
	s.queue = append(s.queue, e)
	// Signal if a flusher is waiting.
	if len(s.queue) >= s.batchSize {
		s.queueCond.Signal()
	}
	s.queueMu.Unlock()
}

// runFlusher loops until ctx or Close signals shutdown, flushing
// either when a full batch is available or on each ticker tick.
func (s *Store) runFlusher(ctx context.Context) {
	t := time.NewTicker(s.flushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = s.flushOnce()
			return
		case <-s.done:
			return
		case <-t.C:
			_ = s.flushOnce()
		}
	}
}

// flushOnce pulls up to batchSize events off the queue and writes
// them in one transaction. Returns nil if there was nothing to write.
func (s *Store) flushOnce() error {
	s.queueMu.Lock()
	if len(s.queue) == 0 {
		s.queueMu.Unlock()
		return nil
	}
	n := s.batchSize
	if n > len(s.queue) {
		n = len(s.queue)
	}
	batch := make([]*model.Event, n)
	copy(batch, s.queue[:n])
	s.queue = s.queue[n:]
	s.queueMu.Unlock()

	// Group by UTC day so a batch never spans tables.
	// Common case: one day, single transaction.
	var (
		curDay  string
		curRows []*model.Event
	)
	flushRows := func() error {
		if len(curRows) == 0 {
			return nil
		}
		table, err := s.ensureTableForName(curDay)
		if err != nil {
			return err
		}
		if err := s.writeBatch(table, curRows); err != nil {
			s.flushErrs.Add(1)
			return err
		}
		s.written.Add(uint64(len(curRows)))
		s.batches.Add(1)
		return nil
	}
	for _, e := range batch {
		day := dayKey(e.Time.UTC())
		if day != curDay {
			if err := flushRows(); err != nil {
				return err
			}
			curDay = day
			curRows = curRows[:0]
		}
		curRows = append(curRows, e)
	}
	return flushRows()
}

// writeBatch executes the prepared INSERT for each row in a single
// transaction.
func (s *Store) writeBatch(table string, rows []*model.Event) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(fmt.Sprintf(
		`INSERT INTO %s (id, time_ns, sensor, severity, verdict, host, pid, tid, comm, uid, gid, cgroup_id, container, image, parent_pid, rule, tags_json) `+
			`VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, table))
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, e := range rows {
		tagsJSON, _ := json.Marshal(e.Tags)
		if _, err := stmt.Exec(
			e.ID.String(), e.Time.UnixNano(), e.Sensor, int(e.Severity), int(e.Verdict),
			e.Host, e.PID, e.TID, e.Comm, e.UID, e.GID, e.CGroupID,
			e.Container, e.Image, e.ParentPID, e.Rule, string(tagsJSON),
		); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return err
		}
	}
	_ = stmt.Close()
	return tx.Commit()
}

// ensureTableForUTC creates the table for the given UTC day if it
// doesn't already exist, and returns its name. Cheap on repeat calls
// because the cached currentTable short-circuits the DDL.
func (s *Store) ensureTableForUTC(t time.Time) (string, error) {
	return s.ensureTableForName(dayKey(t))
}

func (s *Store) ensureTableForName(day string) (string, error) {
	table := "events_" + day
	s.currentTableMu.Lock()
	cached := s.currentTable
	s.currentTableMu.Unlock()
	if cached == table {
		return table, nil
	}
	stmt := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id TEXT PRIMARY KEY,
		time_ns INTEGER NOT NULL,
		sensor TEXT NOT NULL,
		severity INTEGER NOT NULL,
		verdict INTEGER,
		host TEXT,
		pid INTEGER,
		tid INTEGER,
		comm TEXT,
		uid INTEGER,
		gid INTEGER,
		cgroup_id INTEGER,
		container TEXT,
		image TEXT,
		parent_pid INTEGER,
		rule TEXT,
		tags_json TEXT
	) WITHOUT ROWID;
	CREATE INDEX IF NOT EXISTS %s_time ON %s (time_ns);
	CREATE INDEX IF NOT EXISTS %s_sensor ON %s (sensor, severity);
	CREATE INDEX IF NOT EXISTS %s_pid ON %s (pid);
	`, table, table, table, table, table, table, table)
	if _, err := s.db.Exec(stmt); err != nil {
		return "", fmt.Errorf("coldstore create %s: %w", table, err)
	}
	s.currentTableMu.Lock()
	if s.currentTable != table {
		if s.currentTable != "" {
			s.rotations.Add(1)
		}
		s.currentTable = table
	}
	s.currentTableMu.Unlock()
	return table, nil
}

// dayKey formats a UTC time as YYYYMMDD.
func dayKey(t time.Time) string {
	return t.UTC().Format("20060102")
}

// Stats is the snapshot for health.snapshot and operator dashboards.
type Stats struct {
	Path             string `json:"path"`
	QueueSize        int    `json:"queue_size"`
	QueueCap         int    `json:"queue_cap"`
	BatchSize        int    `json:"batch_size"`
	Submitted        uint64 `json:"submitted"`
	Written          uint64 `json:"written"`
	Dropped          uint64 `json:"dropped"`
	Batches          uint64 `json:"batches"`
	FlushErrs        uint64 `json:"flush_errs"`
	DayRotations     uint64 `json:"day_rotations"`
	CurrentTable     string `json:"current_table"`
}

// Stats returns a counter snapshot.
func (s *Store) Stats() Stats {
	s.queueMu.Lock()
	qlen := len(s.queue)
	s.queueMu.Unlock()
	s.currentTableMu.Lock()
	cur := s.currentTable
	s.currentTableMu.Unlock()
	return Stats{
		Path:         s.path,
		QueueSize:    qlen,
		QueueCap:     s.queueSize,
		BatchSize:    s.batchSize,
		Submitted:    s.submitted.Load(),
		Written:      s.written.Load(),
		Dropped:      s.dropped.Load(),
		Batches:      s.batches.Load(),
		FlushErrs:    s.flushErrs.Load(),
		DayRotations: s.rotations.Load(),
		CurrentTable: cur,
	}
}

// EventFilter is the simple query API; v1 supports time-range + sensor.
type EventFilter struct {
	SinceUnixNS int64
	UntilUnixNS int64 // 0 = no upper bound
	Sensor      string
	Severity    int // -1 = any
	Limit       int // 0 → 100
}

// Query returns events matching filter from the day-tables that
// overlap the time range. Result is ordered by time_ns descending
// (most recent first) and capped at filter.Limit.
//
// This is deliberately simple — operator UI / RCA work in P5 will
// graduate to a richer query layer (likely a small DSL or SQL
// directly against the same tables).
func (s *Store) Query(filter EventFilter) ([]model.Event, error) {
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.SinceUnixNS == 0 {
		// Default: last hour
		filter.SinceUnixNS = time.Now().Add(-time.Hour).UnixNano()
	}
	if filter.UntilUnixNS == 0 {
		filter.UntilUnixNS = time.Now().UnixNano()
	}

	// Walk every day-table in range. SQLite has no UNION ALL across
	// dynamically named tables in a single prepared statement, so
	// we iterate. Round to start-of-day so we visit each calendar
	// day exactly once even when the range straddles midnight.
	sinceT := time.Unix(0, filter.SinceUnixNS).UTC()
	untilT := time.Unix(0, filter.UntilUnixNS).UTC()
	since := time.Date(sinceT.Year(), sinceT.Month(), sinceT.Day(), 0, 0, 0, 0, time.UTC)
	until := time.Date(untilT.Year(), untilT.Month(), untilT.Day(), 0, 0, 0, 0, time.UTC)
	var out []model.Event
	for day := since; !day.After(until); day = day.Add(24 * time.Hour) {
		table := "events_" + dayKey(day)
		if !s.tableExists(table) {
			continue
		}
		q := fmt.Sprintf(`SELECT id, time_ns, sensor, severity, verdict, host, pid, tid, comm, uid, gid, cgroup_id, container, image, parent_pid, rule, tags_json `+
			`FROM %s WHERE time_ns BETWEEN ? AND ?`, table)
		args := []any{filter.SinceUnixNS, filter.UntilUnixNS}
		if filter.Sensor != "" {
			q += ` AND sensor = ?`
			args = append(args, filter.Sensor)
		}
		if filter.Severity >= 0 {
			q += ` AND severity = ?`
			args = append(args, filter.Severity)
		}
		q += ` ORDER BY time_ns DESC LIMIT ?`
		args = append(args, filter.Limit-len(out))

		rows, err := s.db.Query(q, args...)
		if err != nil {
			return nil, fmt.Errorf("coldstore query %s: %w", table, err)
		}
		for rows.Next() {
			var e model.Event
			var idStr, tagsJSON string
			var timeNS int64
			var sev, verd int
			if err := rows.Scan(&idStr, &timeNS, &e.Sensor, &sev, &verd,
				&e.Host, &e.PID, &e.TID, &e.Comm, &e.UID, &e.GID, &e.CGroupID,
				&e.Container, &e.Image, &e.ParentPID, &e.Rule, &tagsJSON); err != nil {
				rows.Close()
				return nil, err
			}
			e.Time = time.Unix(0, timeNS).UTC()
			e.Severity = model.Severity(sev)
			e.Verdict = model.Verdict(verd)
			_ = json.Unmarshal([]byte(tagsJSON), &e.Tags)
			out = append(out, e)
			if len(out) >= filter.Limit {
				break
			}
		}
		rows.Close()
		if len(out) >= filter.Limit {
			break
		}
	}
	return out, nil
}

// tableExists is cheap and called from the query path.
func (s *Store) tableExists(table string) bool {
	var name string
	err := s.db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`,
		table,
	).Scan(&name)
	return err == nil
}

// RetentionDays returns the configured retention horizon in days.
func (s *Store) RetentionDays() int { return s.retentionDays }

// DropOldDays removes every events_YYYYMMDD partition whose UTC day
// is older than RetentionDays days before now. Returns the names of
// tables dropped (useful for logging) and the count.
//
// Safe to call repeatedly: DROP TABLE IF EXISTS is idempotent, and
// the day-table enumeration is cheap (sqlite_master query).
//
// Negative retention = no-op (operator opted to keep everything;
// audit chain off-host mirror is expected to be the long-term store).
func (s *Store) DropOldDays(now time.Time) ([]string, error) {
	if s.retentionDays < 0 {
		return nil, nil
	}
	cutoff := now.UTC().AddDate(0, 0, -s.retentionDays)
	cutoffKey := dayKey(cutoff) // YYYYMMDD; lexicographic compare works

	rows, err := s.db.Query(
		`SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'events_________'`,
	)
	if err != nil {
		return nil, fmt.Errorf("coldstore enum tables: %w", err)
	}
	var candidates []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, fmt.Errorf("coldstore scan table name: %w", err)
		}
		candidates = append(candidates, name)
	}
	rows.Close()

	var dropped []string
	for _, name := range candidates {
		// events_YYYYMMDD — extract the 8-char suffix
		if len(name) != len("events_")+8 {
			continue
		}
		dayPart := name[len("events_"):]
		// Don't drop the currently-active table even if it's at the
		// boundary; the flush path may be mid-batch.
		s.currentTableMu.Lock()
		isCurrent := s.currentTable == name
		s.currentTableMu.Unlock()
		if isCurrent {
			continue
		}
		if dayPart >= cutoffKey {
			continue // within retention window
		}
		if _, err := s.db.Exec(`DROP TABLE IF EXISTS ` + name); err != nil {
			return dropped, fmt.Errorf("coldstore drop %s: %w", name, err)
		}
		dropped = append(dropped, name)
	}
	return dropped, nil
}

// AbsPath returns the resolved absolute DB path. Useful for the
// LocalAPI handler so operators can see exactly which file is in use.
// DropDaysOverSize drops the OLDEST day partitions until the on-disk
// file size is at or below maxBytes. Never drops the currently-active
// table. Returns the names dropped.
//
// This is the BACKSTOP that runs alongside DropOldDays. Retention-based
// pruning can still leave disk full if event volume is high (the
// 2026-05-25 incident: 18GB in 24h at 12-18M events/day pushed disk to
// 98% inside the retention window). Size-based pruning is the safety
// net: if the file exceeds maxBytes despite retention, drop oldest
// days until it doesn't, even if retention would have kept them.
//
// maxBytes <= 0 disables size pruning. Recommended: 5-10 GB on a
// 100GB rootfs after accounting for the chain (~10GB), hot store
// (~500MB), and other state.
func (s *Store) DropDaysOverSize(maxBytes int64) ([]string, error) {
	if maxBytes <= 0 {
		return nil, nil
	}
	dbPath := s.AbsPath()
	fi, err := os.Stat(dbPath)
	if err != nil {
		return nil, fmt.Errorf("coldstore stat: %w", err)
	}
	if fi.Size() <= maxBytes {
		return nil, nil
	}

	rows, err := s.db.Query(
		`SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'events_________' ORDER BY name ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("coldstore enum tables: %w", err)
	}
	var candidates []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, fmt.Errorf("coldstore scan: %w", err)
		}
		candidates = append(candidates, name)
	}
	rows.Close()

	var dropped []string
	for _, name := range candidates {
		s.currentTableMu.Lock()
		isCurrent := s.currentTable == name
		s.currentTableMu.Unlock()
		if isCurrent {
			continue
		}
		if _, err := s.db.Exec(`DROP TABLE IF EXISTS ` + name); err != nil {
			return dropped, fmt.Errorf("coldstore drop %s: %w", name, err)
		}
		dropped = append(dropped, name)
		// Re-stat after each drop. SQLite needs VACUUM to fully reclaim,
		// but DROP TABLE frees pages to the free-list which limits
		// further growth. Stop as soon as we're under budget OR we've
		// dropped everything except the current table.
		if fi2, err := os.Stat(dbPath); err == nil && fi2.Size() <= maxBytes {
			break
		}
	}
	return dropped, nil
}

func (s *Store) AbsPath() string {
	abs, err := filepath.Abs(s.path)
	if err != nil {
		return s.path
	}
	return abs
}

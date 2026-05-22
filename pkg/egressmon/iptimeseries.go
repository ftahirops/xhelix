package egressmon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// IPTimeSeries is a per-IP bytes-in/bytes-out store, bucketed by
// time. Designed for "show me a graph of every IP's traffic in/out
// over the last 30 days." Independent of the per-lineage observer
// (which is bytes-out only and lineage-keyed).
//
// Bucket size: default 5 minutes. Trade-off: smaller buckets =
// finer-grained graphs but bigger DB. 5 min × 288 buckets/day ×
// 30 days × (avg 50 IPs) ≈ 430K rows; SQLite handles this trivially.
//
// Retention: rows older than RetentionDays are pruned by Sweep.
// Default 30 days.
type IPTimeSeries struct {
	db             *sql.DB
	bucketSize     time.Duration
	retentionDays  int

	mu    sync.Mutex
	// In-memory accumulator. We flush every BucketSize tick so the
	// hot path takes a single map increment, not a SQL exec.
	pending map[bucketKey]*pendingBytes
}

type bucketKey struct {
	bucketTs int64 // unix seconds, aligned to bucket boundary
	ip       string
}

type pendingBytes struct {
	bytesOut uint64
	bytesIn  uint64
}

// IPTimeSeriesConfig configures the store.
type IPTimeSeriesConfig struct {
	DBPath        string        // SQLite path; ":memory:" for tests
	BucketSize    time.Duration // default 5 min
	RetentionDays int           // default 30
}

// NewIPTimeSeries opens/creates the store.
func NewIPTimeSeries(cfg IPTimeSeriesConfig) (*IPTimeSeries, error) {
	if cfg.BucketSize <= 0 {
		cfg.BucketSize = 5 * time.Minute
	}
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 30
	}
	dsn := cfg.DBPath
	if dsn != ":memory:" {
		dsn = "file:" + dsn + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open ip_timeseries: %w", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS ip_timeseries (
			bucket_ts  INTEGER NOT NULL,
			ip         TEXT NOT NULL,
			bytes_out  INTEGER NOT NULL DEFAULT 0,
			bytes_in   INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (bucket_ts, ip)
		) WITHOUT ROWID;
		CREATE INDEX IF NOT EXISTS ip_ts_ip ON ip_timeseries(ip, bucket_ts);
	`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init ip_timeseries: %w", err)
	}
	return &IPTimeSeries{
		db:            db,
		bucketSize:    cfg.BucketSize,
		retentionDays: cfg.RetentionDays,
		pending:       map[bucketKey]*pendingBytes{},
	}, nil
}

// Close releases resources after a final flush.
func (ts *IPTimeSeries) Close() error {
	_ = ts.Flush()
	return ts.db.Close()
}

// RecordOut adds bytes-out to the current bucket for ip.
func (ts *IPTimeSeries) RecordOut(ip net.IP, bytes uint64, at time.Time) {
	if bytes == 0 || ip == nil {
		return
	}
	key := bucketKey{bucketTs: ts.bucketStart(at), ip: ip.String()}
	ts.mu.Lock()
	p := ts.pending[key]
	if p == nil {
		p = &pendingBytes{}
		ts.pending[key] = p
	}
	p.bytesOut += bytes
	ts.mu.Unlock()
}

// RecordIn adds bytes-in to the current bucket for ip.
func (ts *IPTimeSeries) RecordIn(ip net.IP, bytes uint64, at time.Time) {
	if bytes == 0 || ip == nil {
		return
	}
	key := bucketKey{bucketTs: ts.bucketStart(at), ip: ip.String()}
	ts.mu.Lock()
	p := ts.pending[key]
	if p == nil {
		p = &pendingBytes{}
		ts.pending[key] = p
	}
	p.bytesIn += bytes
	ts.mu.Unlock()
}

// Flush persists the in-memory accumulator to SQLite and resets it.
// Idempotent — safe to call from a ticker AND on shutdown.
func (ts *IPTimeSeries) Flush() error {
	ts.mu.Lock()
	if len(ts.pending) == 0 {
		ts.mu.Unlock()
		return nil
	}
	pending := ts.pending
	ts.pending = map[bucketKey]*pendingBytes{}
	ts.mu.Unlock()

	tx, err := ts.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO ip_timeseries (bucket_ts, ip, bytes_out, bytes_in)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(bucket_ts, ip) DO UPDATE SET
			bytes_out = bytes_out + excluded.bytes_out,
			bytes_in  = bytes_in  + excluded.bytes_in
	`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	for k, p := range pending {
		if _, err := stmt.Exec(k.bucketTs, k.ip, p.bytesOut, p.bytesIn); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return err
		}
	}
	_ = stmt.Close()
	return tx.Commit()
}

// Sweep removes rows older than retention. Cheap, run hourly.
func (ts *IPTimeSeries) Sweep() error {
	cutoff := time.Now().Add(-time.Duration(ts.retentionDays) * 24 * time.Hour).Unix()
	_, err := ts.db.Exec(`DELETE FROM ip_timeseries WHERE bucket_ts < ?`, cutoff)
	return err
}

// Point is one bucketed sample for graph rendering.
type Point struct {
	BucketTs time.Time
	BytesOut uint64
	BytesIn  uint64
}

// Series returns the per-bucket points for ip between since and
// until (inclusive). Caller-owned slice. Sorted ascending by time.
// Includes the current in-memory pending bucket so live graphs are
// up-to-date without waiting for a flush.
func (ts *IPTimeSeries) Series(ip net.IP, since, until time.Time) ([]Point, error) {
	if ip == nil {
		return nil, errors.New("Series: nil ip")
	}
	ipS := ip.String()
	rows, err := ts.db.Query(`
		SELECT bucket_ts, bytes_out, bytes_in FROM ip_timeseries
		WHERE ip = ? AND bucket_ts BETWEEN ? AND ?
		ORDER BY bucket_ts
	`, ipS, since.Unix(), until.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Point
	seen := map[int64]*Point{}
	for rows.Next() {
		var bts int64
		var bo, bi uint64
		if err := rows.Scan(&bts, &bo, &bi); err != nil {
			return out, err
		}
		p := Point{
			BucketTs: time.Unix(bts, 0).UTC(),
			BytesOut: bo, BytesIn: bi,
		}
		out = append(out, p)
		seen[bts] = &out[len(out)-1]
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	// Overlay in-memory pending bucket if present and in range.
	ts.mu.Lock()
	for k, p := range ts.pending {
		if k.ip != ipS {
			continue
		}
		if k.bucketTs < since.Unix() || k.bucketTs > until.Unix() {
			continue
		}
		if existing, ok := seen[k.bucketTs]; ok {
			existing.BytesOut += p.bytesOut
			existing.BytesIn += p.bytesIn
		} else {
			out = append(out, Point{
				BucketTs: time.Unix(k.bucketTs, 0).UTC(),
				BytesOut: p.bytesOut, BytesIn: p.bytesIn,
			})
		}
	}
	ts.mu.Unlock()
	return out, nil
}

// TopIPs returns the N IPs with the most bytes-out in the given
// window. Used by the analytics CLI / TUI to pick which IPs to graph.
func (ts *IPTimeSeries) TopIPs(since, until time.Time, n int) ([]IPSummary, error) {
	if n <= 0 {
		n = 25
	}
	rows, err := ts.db.Query(`
		SELECT ip, SUM(bytes_out), SUM(bytes_in)
		FROM ip_timeseries
		WHERE bucket_ts BETWEEN ? AND ?
		GROUP BY ip
		ORDER BY SUM(bytes_out) DESC
		LIMIT ?
	`, since.Unix(), until.Unix(), n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPSummary
	for rows.Next() {
		var s IPSummary
		if err := rows.Scan(&s.IP, &s.BytesOut, &s.BytesIn); err != nil {
			return out, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// IPSummary is a per-IP rollup for the window.
type IPSummary struct {
	IP       string
	BytesOut uint64
	BytesIn  uint64
}

// StartFlushLoop runs Flush + Sweep on a ticker until ctx cancels.
// Default cadence: Flush every BucketSize/2, Sweep every hour.
func (ts *IPTimeSeries) StartFlushLoop(ctx context.Context) {
	flushTick := time.NewTicker(ts.bucketSize / 2)
	sweepTick := time.NewTicker(time.Hour)
	go func() {
		defer flushTick.Stop()
		defer sweepTick.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = ts.Flush()
				return
			case <-flushTick.C:
				_ = ts.Flush()
			case <-sweepTick.C:
				_ = ts.Sweep()
			}
		}
	}()
}

func (ts *IPTimeSeries) bucketStart(t time.Time) int64 {
	sec := t.Unix()
	bs := int64(ts.bucketSize / time.Second)
	return (sec / bs) * bs
}

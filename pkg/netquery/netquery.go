// Package netquery is the named-query layer over pkg/store/history.
//
// It exists so the UI / CLI / my-net-gate API don't all have to
// re-invent the same aggregations: "top destinations by bytes",
// "traffic distribution by app", "unknown-process traffic",
// "connections to country X" — every shape an operator would
// ask `ss -tnp` plus a SQL prompt to produce.
//
// All functions take a *sql.DB (the history store's DB() handle)
// and return strongly-typed rows. No state, no goroutines.
package netquery

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ── Filters ───────────────────────────────────────────────────

// Filter narrows every query to a time window plus optional
// dimensions. Leave a field empty to skip that filter.
type Filter struct {
	Since, Until time.Time
	CGroupClass  string // "user" | "system" | "container"
	Exe          string
	Country      string
	Verdict      string
	OnlyKnown    bool // exclude rows where process_id is null
	OnlyUnknown  bool // include only rows where process_id is null
}

func (f Filter) where(args *[]any) string {
	w := "1=1"
	if !f.Since.IsZero() {
		w += " AND opened_at >= ?"
		*args = append(*args, f.Since.Unix())
	}
	if !f.Until.IsZero() {
		w += " AND opened_at <= ?"
		*args = append(*args, f.Until.Unix())
	}
	if f.Country != "" {
		w += " AND country = ?"
		*args = append(*args, f.Country)
	}
	if f.OnlyKnown {
		w += " AND process_id IS NOT NULL AND process_id != 0"
	}
	if f.OnlyUnknown {
		w += " AND (process_id IS NULL OR process_id = 0)"
	}
	return w
}

// ── Row types ─────────────────────────────────────────────────

// AppDistribution is one (exe, traffic) bucket.
type AppDistribution struct {
	Exe        string
	CGroupClass string
	Connections int64
	BytesIn     int64
	BytesOut    int64
}

// HostDistribution is one (dst_ip, traffic) bucket.
type HostDistribution struct {
	DstIP       string
	Country     string
	ASN         string
	QName       string // canonical resolved name, if known
	Connections int64
	BytesIn     int64
	BytesOut    int64
}

// CountryDistribution is one (country, traffic) bucket.
type CountryDistribution struct {
	Country     string
	Connections int64
	BytesIn     int64
	BytesOut    int64
}

// ProcessFlow is one process's full network footprint over the
// window — counts and totals across all its flows. Matches the
// `ss -tnp` per-process aggregation the user asked for.
type ProcessFlow struct {
	PID         uint32
	Comm        string
	Exe         string
	CGroupClass string
	Connections int64
	BytesIn     int64
	BytesOut    int64
	Countries   int64 // distinct country count
	Hosts       int64 // distinct dst_ip count
}

// HistoryPoint is one bucket of a time-series rollup.
type HistoryPoint struct {
	Time     time.Time
	BytesIn  int64
	BytesOut int64
	Flows    int64
}

// ── Queries ───────────────────────────────────────────────────

// TopApps returns the top N applications by total bytes (in+out),
// descending. Use Filter{} for all-time + all-classes.
func TopApps(ctx context.Context, db *sql.DB, f Filter, n int) ([]AppDistribution, error) {
	args := []any{}
	q := `
		SELECT p.exe, p.cgroup_class,
		       COUNT(*) AS conns,
		       COALESCE(SUM(f.bytes_in),0)  AS bin,
		       COALESCE(SUM(f.bytes_out),0) AS bout
		FROM flows f
		LEFT JOIN processes p ON p.id = f.process_id
		WHERE ` + f.where(&args)
	if f.CGroupClass != "" {
		q += " AND p.cgroup_class = ?"
		args = append(args, f.CGroupClass)
	}
	if f.Exe != "" {
		q += " AND p.exe = ?"
		args = append(args, f.Exe)
	}
	q += `
		GROUP BY p.exe, p.cgroup_class
		ORDER BY (bin + bout) DESC
		LIMIT ?`
	args = append(args, n)
	return queryApps(ctx, db, q, args)
}

// TopHosts returns the top N destination IPs by total bytes.
func TopHosts(ctx context.Context, db *sql.DB, f Filter, n int) ([]HostDistribution, error) {
	args := []any{}
	q := `
		SELECT f.dst_ip,
		       COALESCE(f.country,'') AS country,
		       COALESCE(f.asn,'') AS asn,
		       COALESCE(MAX(f.dns_qname),'') AS qname,
		       COUNT(*) AS conns,
		       COALESCE(SUM(f.bytes_in),0)  AS bin,
		       COALESCE(SUM(f.bytes_out),0) AS bout
		FROM flows f
		WHERE ` + f.where(&args) + `
		GROUP BY f.dst_ip, f.country, f.asn
		ORDER BY (bin + bout) DESC
		LIMIT ?`
	args = append(args, n)
	return queryHosts(ctx, db, q, args)
}

// TopCountries returns the top N destination countries.
func TopCountries(ctx context.Context, db *sql.DB, f Filter, n int) ([]CountryDistribution, error) {
	args := []any{}
	q := `
		SELECT COALESCE(country,'(unknown)') AS country,
		       COUNT(*) AS conns,
		       COALESCE(SUM(bytes_in),0)  AS bin,
		       COALESCE(SUM(bytes_out),0) AS bout
		FROM flows
		WHERE ` + f.where(&args) + `
		GROUP BY country
		ORDER BY (bin + bout) DESC
		LIMIT ?`
	args = append(args, n)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CountryDistribution
	for rows.Next() {
		var c CountryDistribution
		if err := rows.Scan(&c.Country, &c.Connections, &c.BytesIn, &c.BytesOut); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ByProcess returns one row per (pid, exe) showing each process's
// total network footprint. The `ss -tnp` shape, expanded.
func ByProcess(ctx context.Context, db *sql.DB, f Filter) ([]ProcessFlow, error) {
	args := []any{}
	q := `
		SELECT COALESCE(p.pid, 0), COALESCE(p.comm,''), COALESCE(p.exe,''),
		       COALESCE(p.cgroup_class,''),
		       COUNT(*) AS conns,
		       COALESCE(SUM(f.bytes_in),0)  AS bin,
		       COALESCE(SUM(f.bytes_out),0) AS bout,
		       COUNT(DISTINCT f.country) AS countries,
		       COUNT(DISTINCT f.dst_ip)  AS hosts
		FROM flows f
		LEFT JOIN processes p ON p.id = f.process_id
		WHERE ` + f.where(&args)
	if f.CGroupClass != "" {
		q += " AND p.cgroup_class = ?"
		args = append(args, f.CGroupClass)
	}
	q += `
		GROUP BY p.pid, p.comm, p.exe, p.cgroup_class
		ORDER BY (bin + bout) DESC`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProcessFlow
	for rows.Next() {
		var p ProcessFlow
		if err := rows.Scan(&p.PID, &p.Comm, &p.Exe, &p.CGroupClass,
			&p.Connections, &p.BytesIn, &p.BytesOut,
			&p.Countries, &p.Hosts); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UnknownTraffic returns flows whose process_id is NULL —
// connections xhelix observed but could not attribute. Critical
// for spotting kernel-thread or transient-process exfil that
// would otherwise vanish in the by-app rollup.
func UnknownTraffic(ctx context.Context, db *sql.DB, f Filter) ([]HostDistribution, error) {
	f.OnlyUnknown = true
	return TopHosts(ctx, db, f, 1000)
}

// TimeSeries returns bucketed (BytesIn, BytesOut, Flows) over
// a time window. bucket=time.Minute / Hour / Day are sensible.
func TimeSeries(ctx context.Context, db *sql.DB, f Filter, bucket time.Duration) ([]HistoryPoint, error) {
	if bucket <= 0 {
		bucket = time.Minute
	}
	args := []any{}
	q := fmt.Sprintf(`
		SELECT (opened_at / %d) * %d AS bkt,
		       COALESCE(SUM(bytes_in),0),
		       COALESCE(SUM(bytes_out),0),
		       COUNT(*)
		FROM flows
		WHERE %s
		GROUP BY bkt
		ORDER BY bkt`,
		int64(bucket.Seconds()), int64(bucket.Seconds()), f.where(&args))
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistoryPoint
	for rows.Next() {
		var bkt int64
		var p HistoryPoint
		if err := rows.Scan(&bkt, &p.BytesIn, &p.BytesOut, &p.Flows); err != nil {
			return nil, err
		}
		p.Time = time.Unix(bkt, 0)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ── shared scan helpers ───────────────────────────────────────

func queryApps(ctx context.Context, db *sql.DB, q string, args []any) ([]AppDistribution, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppDistribution
	for rows.Next() {
		var a AppDistribution
		var exe, class sql.NullString
		if err := rows.Scan(&exe, &class, &a.Connections, &a.BytesIn, &a.BytesOut); err != nil {
			return nil, err
		}
		a.Exe = exe.String
		a.CGroupClass = class.String
		if a.Exe == "" {
			a.Exe = "(unknown)"
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func queryHosts(ctx context.Context, db *sql.DB, q string, args []any) ([]HostDistribution, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostDistribution
	for rows.Next() {
		var h HostDistribution
		if err := rows.Scan(&h.DstIP, &h.Country, &h.ASN, &h.QName,
			&h.Connections, &h.BytesIn, &h.BytesOut); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

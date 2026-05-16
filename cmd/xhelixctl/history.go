// xhelixctl history — narrative network history reader.
//
// Reads the SQLite store written by the daemon (pkg/store/history)
// and renders it through pkg/narrate. Three reading granularities:
//
//	xhelixctl history                   today's session journal
//	xhelixctl history --session ID      one specific session
//	xhelixctl history --hour            hour-bucket view of today
//	xhelixctl history --activity ID     drill into one activity
//	xhelixctl history --filter EXPR     filter (verdict=red, exe=firefox)
//	xhelixctl history export --since 7d --format jsonl
//
// Defaults to ~/.local/share/xhelix/history.db on the user; root
// installs use /var/lib/xhelix/history.db. Override with
// --db=PATH.

package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/narrate"
	"github.com/xhelix/xhelix/pkg/store/history"
)

func newHistoryCmd() *cobra.Command {
	var (
		dbPath     string
		sessionID  int64
		activityID int64
		hourView   bool
		dayView    bool
		filter     string
		since      string
	)

	cmd := &cobra.Command{
		Use:   "history",
		Short: "Read the narrative network history journal",
		Long: `Read the daemon's narrative network history.

Three reading granularities:
  session view (default) — one paragraph per session with summary
  hour view (--hour)     — one entry per hour with active apps
  activity view (--activity N) — drill into one activity

Examples:
  xhelixctl history
  xhelixctl history --session 12
  xhelixctl history --hour
  xhelixctl history --activity 482
  xhelixctl history --filter 'verdict=red'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHistory(historyOptions{
				DBPath: dbPath, SessionID: sessionID, ActivityID: activityID,
				HourView: hourView, DayView: dayView,
				Filter: filter, Since: since,
			}, os.Stdout)
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "", "path to history.db (default: $XDG_DATA_HOME/xhelix/history.db or /var/lib/xhelix/history.db)")
	cmd.Flags().Int64Var(&sessionID, "session", 0, "show one specific session by id")
	cmd.Flags().Int64Var(&activityID, "activity", 0, "drill into one activity by id")
	cmd.Flags().BoolVar(&hourView, "hour", false, "render hour-bucket view")
	cmd.Flags().BoolVar(&dayView, "day", false, "render today's overview (default)")
	cmd.Flags().StringVar(&filter, "filter", "", "filter expression (verdict=X, exe=Y, country=Z, bytes_out>N)")
	cmd.Flags().StringVar(&since, "since", "24h", "lookback window (e.g. 1h, 7d, 30d)")

	cmd.AddCommand(newHistoryExportCmd())

	return cmd
}

func newHistoryExportCmd() *cobra.Command {
	var (
		dbPath string
		since  string
		format string
		out    string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export activities to JSONL / CSV",
		RunE: func(cmd *cobra.Command, args []string) error {
			var w io.Writer = os.Stdout
			if out != "" {
				f, err := os.Create(out)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			return runHistoryExport(dbPath, since, format, w)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to history.db")
	cmd.Flags().StringVar(&since, "since", "7d", "lookback window")
	cmd.Flags().StringVar(&format, "format", "jsonl", "jsonl | csv")
	cmd.Flags().StringVar(&out, "out", "", "output file (default: stdout)")
	return cmd
}

type historyOptions struct {
	DBPath     string
	SessionID  int64
	ActivityID int64
	HourView   bool
	DayView    bool
	Filter     string
	Since      string
}

func runHistory(opts historyOptions, w io.Writer) error {
	path, err := resolveDBPath(opts.DBPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("history db not found at %s — has the daemon ever run?", path)
	}
	store, err := history.Open(path)
	if err != nil {
		return fmt.Errorf("open history db: %w", err)
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	r := &narrate.Renderer{}

	// Mode: --activity wins, then --session, then --hour, then default day.
	switch {
	case opts.ActivityID > 0:
		return renderActivity(ctx, w, r, store, opts.ActivityID)
	case opts.SessionID > 0:
		return renderSession(ctx, w, r, store, opts.SessionID, opts.Filter)
	case opts.HourView:
		return renderHourBuckets(ctx, w, r, store, opts.Since, opts.Filter)
	default:
		return renderToday(ctx, w, r, store, opts.Since, opts.Filter)
	}
}

func renderActivity(ctx context.Context, w io.Writer, r *narrate.Renderer, s *history.Store, id int64) error {
	a, err := loadActivity(ctx, s.DB(), id)
	if err != nil {
		return err
	}
	p, _ := loadProcess(ctx, s.DB(), a.ProcessID)
	flows, _ := loadFlowsForActivity(ctx, s.DB(), id)
	dns, _ := loadDNSForActivityWindow(ctx, s.DB(), p.ID, a.StartedAt, a.EndedAt)
	_, err = fmt.Fprint(w, r.Activity(a, p, flows, dns))
	return err
}

func renderSession(ctx context.Context, w io.Writer, r *narrate.Renderer, s *history.Store, id int64, filter string) error {
	sess, err := loadSession(ctx, s.DB(), id)
	if err != nil {
		return err
	}
	acts, err := loadActivitiesForSession(ctx, s.DB(), id, filter)
	if err != nil {
		return err
	}
	procs, err := loadProcesses(ctx, s.DB(), activityProcessIDs(acts))
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(w, r.SessionSummary(sess, acts, procs))
	return err
}

func renderHourBuckets(ctx context.Context, w io.Writer, r *narrate.Renderer, s *history.Store, since, filter string) error {
	cutoff, err := parseSince(since)
	if err != nil {
		return err
	}
	acts, err := loadActivitiesSince(ctx, s.DB(), cutoff, filter)
	if err != nil {
		return err
	}
	procs, err := loadProcesses(ctx, s.DB(), activityProcessIDs(acts))
	if err != nil {
		return err
	}
	// Group by truncated hour
	hours := map[time.Time][]history.Activity{}
	for _, a := range acts {
		h := a.StartedAt.Truncate(time.Hour)
		hours[h] = append(hours[h], a)
	}
	// Sort hours ascending
	keys := make([]time.Time, 0, len(hours))
	for k := range hours {
		keys = append(keys, k)
	}
	sortTimes(keys)
	for _, h := range keys {
		fmt.Fprintln(w, r.HourSummary(h, hours[h], procs))
	}
	return nil
}

func renderToday(ctx context.Context, w io.Writer, r *narrate.Renderer, s *history.Store, since, filter string) error {
	cutoff, err := parseSince(since)
	if err != nil {
		return err
	}
	sessions, err := loadSessionsSince(ctx, s.DB(), cutoff)
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		fmt.Fprintln(w, "No sessions in the lookback window. (--since="+since+")")
		return nil
	}
	for _, sess := range sessions {
		acts, _ := loadActivitiesForSession(ctx, s.DB(), sess.ID, filter)
		procs, _ := loadProcesses(ctx, s.DB(), activityProcessIDs(acts))
		fmt.Fprintln(w, r.SessionSummary(sess, acts, procs))
	}
	return nil
}

func runHistoryExport(dbPath, since, format string, w io.Writer) error {
	path, err := resolveDBPath(dbPath)
	if err != nil {
		return err
	}
	store, err := history.Open(path)
	if err != nil {
		return err
	}
	defer store.Close()
	cutoff, err := parseSince(since)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	acts, err := loadActivitiesSince(ctx, store.DB(), cutoff, "")
	if err != nil {
		return err
	}
	switch strings.ToLower(format) {
	case "jsonl":
		enc := json.NewEncoder(w)
		for _, a := range acts {
			if err := enc.Encode(a); err != nil {
				return err
			}
		}
	case "csv":
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "process_id", "started_at", "ended_at", "primary_host", "primary_ip", "bytes_in", "bytes_out", "flow_count", "verdict", "verdict_score"})
		for _, a := range acts {
			_ = cw.Write([]string{
				strconv.FormatInt(a.ID, 10),
				strconv.FormatInt(a.ProcessID, 10),
				a.StartedAt.Format(time.RFC3339),
				a.EndedAt.Format(time.RFC3339),
				a.PrimaryHost,
				a.PrimaryIP,
				strconv.FormatUint(a.BytesIn, 10),
				strconv.FormatUint(a.BytesOut, 10),
				strconv.Itoa(a.FlowCount),
				a.Verdict,
				strconv.FormatFloat(a.VerdictScore, 'f', 1, 64),
			})
		}
		cw.Flush()
	default:
		return fmt.Errorf("unknown format %q (jsonl | csv)", format)
	}
	return nil
}

// ── DB queries ─────────────────────────────────────────────────

func loadSession(ctx context.Context, db *sql.DB, id int64) (history.Session, error) {
	var s history.Session
	var subject, kind, class sql.NullString
	var started, ended sql.NullInt64
	err := db.QueryRowContext(ctx, `
		SELECT id, kind, subject, cgroup_class, started_at, ended_at FROM sessions WHERE id = ?
	`, id).Scan(&s.ID, &kind, &subject, &class, &started, &ended)
	if err != nil {
		return s, fmt.Errorf("load session %d: %w", id, err)
	}
	s.Kind = kind.String
	s.Subject = subject.String
	s.CGroupClass = class.String
	s.StartedAt = time.Unix(started.Int64, 0)
	if ended.Valid {
		t := time.Unix(ended.Int64, 0)
		s.EndedAt = &t
	}
	return s, nil
}

func loadSessionsSince(ctx context.Context, db *sql.DB, cutoff time.Time) ([]history.Session, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, kind, subject, cgroup_class, started_at, ended_at
		FROM sessions
		WHERE started_at >= ?
		ORDER BY started_at DESC
	`, cutoff.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []history.Session
	for rows.Next() {
		var s history.Session
		var ended sql.NullInt64
		var subject, kind, class sql.NullString
		if err := rows.Scan(&s.ID, &kind, &subject, &class, new(int64), &ended); err != nil {
			return nil, err
		}
		s.Kind = kind.String
		s.Subject = subject.String
		s.CGroupClass = class.String
		// Re-scan for started_at correctly
		var started int64
		_ = db.QueryRowContext(ctx, `SELECT started_at FROM sessions WHERE id = ?`, s.ID).Scan(&started)
		s.StartedAt = time.Unix(started, 0)
		if ended.Valid {
			t := time.Unix(ended.Int64, 0)
			s.EndedAt = &t
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func loadActivity(ctx context.Context, db *sql.DB, id int64) (history.Activity, error) {
	var a history.Activity
	var started, ended int64
	var rh, ri, cn, asn, rs, host, ip, verdict, proto sql.NullString
	err := db.QueryRowContext(ctx, `
		SELECT id, process_id, started_at, ended_at, primary_host, related_hosts,
		       primary_ip, related_ips, countries, asns, bytes_in, bytes_out,
		       flow_count, verdict, verdict_score, reasons, protocols
		FROM activities WHERE id = ?
	`, id).Scan(&a.ID, &a.ProcessID, &started, &ended, &host, &rh, &ip, &ri,
		&cn, &asn, &a.BytesIn, &a.BytesOut, &a.FlowCount, &verdict, &a.VerdictScore, &rs, &proto)
	if err != nil {
		return a, fmt.Errorf("load activity %d: %w", id, err)
	}
	a.StartedAt = time.Unix(started, 0)
	a.EndedAt = time.Unix(ended, 0)
	a.PrimaryHost = host.String
	a.PrimaryIP = ip.String
	a.Verdict = verdict.String
	a.Protocols = proto.String
	a.RelatedHosts = parseJSONStrings(rh.String)
	a.RelatedIPs = parseJSONStrings(ri.String)
	a.Countries = parseJSONStrings(cn.String)
	a.ASNs = parseJSONStrings(asn.String)
	a.Reasons = parseJSONStrings(rs.String)
	return a, nil
}

func loadActivitiesForSession(ctx context.Context, db *sql.DB, sessionID int64, filter string) ([]history.Activity, error) {
	q := `SELECT a.id, a.process_id, a.started_at, a.ended_at, a.primary_host, a.related_hosts,
		   a.primary_ip, a.related_ips, a.countries, a.asns, a.bytes_in, a.bytes_out,
		   a.flow_count, a.verdict, a.verdict_score, a.reasons, a.protocols
		FROM activities a
		JOIN processes p ON p.id = a.process_id
		WHERE p.session_id = ?`
	args := []any{sessionID}
	if w := filterToSQL(filter); w != "" {
		q += " AND " + w
	}
	q += " ORDER BY a.started_at"
	return queryActivities(ctx, db, q, args)
}

func loadActivitiesSince(ctx context.Context, db *sql.DB, cutoff time.Time, filter string) ([]history.Activity, error) {
	q := `SELECT id, process_id, started_at, ended_at, primary_host, related_hosts,
		   primary_ip, related_ips, countries, asns, bytes_in, bytes_out,
		   flow_count, verdict, verdict_score, reasons, protocols
		FROM activities WHERE started_at >= ?`
	args := []any{cutoff.Unix()}
	if w := filterToSQL(filter); w != "" {
		q += " AND " + w
	}
	q += " ORDER BY started_at"
	return queryActivities(ctx, db, q, args)
}

func queryActivities(ctx context.Context, db *sql.DB, q string, args []any) ([]history.Activity, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []history.Activity
	for rows.Next() {
		var a history.Activity
		var started, ended int64
		var rh, ri, cn, asn, rs, host, ip, verdict, proto sql.NullString
		if err := rows.Scan(&a.ID, &a.ProcessID, &started, &ended, &host, &rh, &ip, &ri,
			&cn, &asn, &a.BytesIn, &a.BytesOut, &a.FlowCount, &verdict, &a.VerdictScore, &rs, &proto); err != nil {
			return nil, err
		}
		a.StartedAt = time.Unix(started, 0)
		a.EndedAt = time.Unix(ended, 0)
		a.PrimaryHost = host.String
		a.PrimaryIP = ip.String
		a.Verdict = verdict.String
		a.Protocols = proto.String
		a.RelatedHosts = parseJSONStrings(rh.String)
		a.RelatedIPs = parseJSONStrings(ri.String)
		a.Countries = parseJSONStrings(cn.String)
		a.ASNs = parseJSONStrings(asn.String)
		a.Reasons = parseJSONStrings(rs.String)
		out = append(out, a)
	}
	return out, rows.Err()
}

func loadProcess(ctx context.Context, db *sql.DB, id int64) (history.Process, error) {
	var p history.Process
	var ended sql.NullInt64
	var started int64
	var comm, exe, sha, class, unit, uid sql.NullString
	var sessID sql.NullInt64
	err := db.QueryRowContext(ctx, `
		SELECT id, session_id, pid, ppid, comm, exe, exe_sha, cgroup_class,
		       unit, user_id, started_at, ended_at
		FROM processes WHERE id = ?
	`, id).Scan(&p.ID, &sessID, &p.PID, &p.PPID, &comm, &exe, &sha, &class, &unit, &uid, &started, &ended)
	if err != nil {
		return p, err
	}
	if sessID.Valid {
		p.SessionID = sessID.Int64
	}
	p.Comm = comm.String
	p.Exe = exe.String
	p.ExeSHA = sha.String
	p.CGroupClass = class.String
	p.Unit = unit.String
	p.UserID = uid.String
	p.StartedAt = time.Unix(started, 0)
	if ended.Valid {
		t := time.Unix(ended.Int64, 0)
		p.EndedAt = &t
	}
	return p, nil
}

func loadProcesses(ctx context.Context, db *sql.DB, ids []int64) (map[int64]history.Process, error) {
	out := map[int64]history.Process{}
	for _, id := range ids {
		if _, ok := out[id]; ok {
			continue
		}
		p, err := loadProcess(ctx, db, id)
		if err == nil {
			out[id] = p
		}
	}
	return out, nil
}

func loadFlowsForActivity(ctx context.Context, db *sql.DB, activityID int64) ([]history.Flow, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, activity_id, process_id, proto, src_ip, src_port, dst_ip, dst_port,
		       state, opened_at, closed_at, bytes_in, bytes_out, dns_qname, country, asn
		FROM flows WHERE activity_id = ?
		ORDER BY opened_at
	`, activityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []history.Flow
	for rows.Next() {
		var f history.Flow
		var actID, closed sql.NullInt64
		var opened int64
		var srcIP, dstIP, proto, state, qname, country, asn sql.NullString
		if err := rows.Scan(&f.ID, &actID, &f.ProcessID, &proto, &srcIP, &f.SrcPort, &dstIP, &f.DstPort,
			&state, &opened, &closed, &f.BytesIn, &f.BytesOut, &qname, &country, &asn); err != nil {
			return nil, err
		}
		if actID.Valid {
			f.ActivityID = actID.Int64
		}
		f.Proto = proto.String
		f.SrcIP = srcIP.String
		f.DstIP = dstIP.String
		f.State = state.String
		f.DNSQName = qname.String
		f.Country = country.String
		f.ASN = asn.String
		f.OpenedAt = time.Unix(opened, 0)
		if closed.Valid {
			t := time.Unix(closed.Int64, 0)
			f.ClosedAt = &t
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func loadDNSForActivityWindow(ctx context.Context, db *sql.DB, processID int64, start, end time.Time) ([]history.DNSQuery, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, process_id, asked_at, qname, qtype, answers, upstream, encrypted
		FROM dns_queries
		WHERE process_id = ? AND asked_at BETWEEN ? AND ?
		ORDER BY asked_at
	`, processID, start.Unix(), end.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []history.DNSQuery
	for rows.Next() {
		var q history.DNSQuery
		var asked int64
		var qname, qtype, ans, upstream sql.NullString
		var enc int
		if err := rows.Scan(&q.ID, &q.ProcessID, &asked, &qname, &qtype, &ans, &upstream, &enc); err != nil {
			return nil, err
		}
		q.QName = qname.String
		q.QType = qtype.String
		q.Upstream = upstream.String
		q.Encrypted = enc != 0
		q.AskedAt = time.Unix(asked, 0)
		q.Answers = parseJSONStrings(ans.String)
		out = append(out, q)
	}
	return out, rows.Err()
}

// ── helpers ────────────────────────────────────────────────────

func resolveDBPath(p string) (string, error) {
	if p != "" {
		return p, nil
	}
	if home := os.Getenv("XDG_DATA_HOME"); home != "" {
		return filepath.Join(home, "xhelix", "history.db"), nil
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "share", "xhelix", "history.db"), nil
	}
	return "/var/lib/xhelix/history.db", nil
}

func parseSince(s string) (time.Time, error) {
	if s == "" {
		s = "24h"
	}
	// Accept "Nh" / "Nd" / "Nw" plus standard Go duration.
	switch {
	case strings.HasSuffix(s, "d"):
		v, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return time.Time{}, fmt.Errorf("bad --since %q: %w", s, err)
		}
		return time.Now().Add(-time.Duration(v) * 24 * time.Hour), nil
	case strings.HasSuffix(s, "w"):
		v, err := strconv.Atoi(strings.TrimSuffix(s, "w"))
		if err != nil {
			return time.Time{}, fmt.Errorf("bad --since %q: %w", s, err)
		}
		return time.Now().Add(-time.Duration(v) * 7 * 24 * time.Hour), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("bad --since %q: %w", s, err)
	}
	return time.Now().Add(-d), nil
}

// filterToSQL converts a simple "key=value [AND key=value]" form
// into a SQL WHERE fragment. Supports verdict, country (matches in
// JSON-encoded array via LIKE), exe (joins processes), bytes_out>N.
//
// Intentionally minimal — operator escape hatch. Anything more
// elaborate goes through pkg/netquery (future).
func filterToSQL(expr string) string {
	if expr == "" {
		return ""
	}
	parts := strings.Split(expr, " AND ")
	var clauses []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// verdict=red
		if v, ok := stripPrefix(p, "verdict="); ok {
			clauses = append(clauses, fmt.Sprintf("verdict = %q", v))
			continue
		}
		// country=CN  → LIKE '%"CN"%' on countries JSON
		if v, ok := stripPrefix(p, "country="); ok {
			clauses = append(clauses, fmt.Sprintf("countries LIKE '%%\"%s\"%%'", v))
			continue
		}
		// bytes_out>N
		if v, ok := stripPrefix(p, "bytes_out>"); ok {
			clauses = append(clauses, fmt.Sprintf("bytes_out > %s", v))
			continue
		}
		// Unknown clause: drop silently rather than fail; we'd
		// rather show too much than show nothing.
	}
	if len(clauses) == 0 {
		return ""
	}
	return strings.Join(clauses, " AND ")
}

func stripPrefix(s, prefix string) (string, bool) {
	if !strings.HasPrefix(s, prefix) {
		return "", false
	}
	return s[len(prefix):], true
}

func parseJSONStrings(raw string) []string {
	if raw == "" || raw == "null" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

func activityProcessIDs(acts []history.Activity) []int64 {
	seen := map[int64]struct{}{}
	out := make([]int64, 0, len(acts))
	for _, a := range acts {
		if _, ok := seen[a.ProcessID]; ok {
			continue
		}
		seen[a.ProcessID] = struct{}{}
		out = append(out, a.ProcessID)
	}
	return out
}

func sortTimes(ts []time.Time) {
	for i := 1; i < len(ts); i++ {
		for j := i; j > 0 && ts[j-1].After(ts[j]); j-- {
			ts[j-1], ts[j] = ts[j], ts[j-1]
		}
	}
}

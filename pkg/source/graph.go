package source

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/lineage"
)

// EventKind classifies what a source-attributed event represents. Used
// for filtering and color-grouping in the correlation-graph UI.
type EventKind string

const (
	KindSpawn         EventKind = "spawn"          // process spawn
	KindExec          EventKind = "exec"           // execve into new image
	KindExit          EventKind = "exit"           // process exit
	KindFileRead      EventKind = "file_read"      // open for read
	KindFileWrite     EventKind = "file_write"     // write/create/truncate
	KindFileExec      EventKind = "file_exec"      // open with O_EXEC
	KindNetConnect    EventKind = "net_connect"    // outbound TCP
	KindNetListen     EventKind = "net_listen"     // bind+listen
	KindNetAccept     EventKind = "net_accept"     // inbound TCP accept
	KindDNSQuery      EventKind = "dns_query"      // outbound DNS
	KindSecretAccess  EventKind = "secret_access"  // credbroker / fangate
	KindCapChange     EventKind = "cap_change"     // capset
	KindNSChange      EventKind = "ns_change"      // unshare/setns
	KindPtrace        EventKind = "ptrace"         // ptrace attach
	KindMemfdExec     EventKind = "memfd_exec"     // execveat on memfd
	KindPersistence   EventKind = "persistence"    // write to cron/systemd/authorized_keys
	KindIdentity      EventKind = "identity"       // PAM / sudo / setuid event
)

// Severity classifies how operationally interesting an event is. The
// graph UI uses this to set color intensity within a group.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarn     Severity = "warn"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// GraphEvent is one row in the source-attributed event store. It is
// the unit of detail behind every "petal" in the correlation-graph
// visualization.
//
// Fields are sparse: a file event has TargetPath; a net event has
// TargetHost+TargetPort or TargetSocket; an exec event has TargetImage.
// Empty fields are omitted from query results to keep payloads small.
type GraphEvent struct {
	ID               int64             // auto-increment row id
	SourceAnchorID   lineage.LineageID // the originating session anchor
	CausalSetHash    uint64            // for Ambiguous detection (0 if not set)
	Time             time.Time         // event wall-clock
	PID              uint32
	ParentPID        uint32
	Kind             EventKind
	TargetPath       string            // for file ops + exec
	TargetHost       string            // for net_connect / accept
	TargetPort       uint16
	TargetSocket     string            // for unix-socket connects
	TargetImage      string            // for exec / spawn
	Comm             string            // short process name
	UID              uint32
	Severity         Severity          // info / warn / high / critical
	Detail           string            // small JSON blob, optional
}

// initGraphSchema adds the source_events table and its indexes. Called
// once at store open. Safe to invoke repeatedly (uses CREATE IF NOT
// EXISTS).
func initGraphSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS source_events (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			source_anchor_id INTEGER NOT NULL,
			causal_set_hash INTEGER NOT NULL DEFAULT 0,
			time_ns         INTEGER NOT NULL,
			pid             INTEGER NOT NULL DEFAULT 0,
			parent_pid      INTEGER NOT NULL DEFAULT 0,
			kind            TEXT    NOT NULL,
			target_path     TEXT    NOT NULL DEFAULT '',
			target_host     TEXT    NOT NULL DEFAULT '',
			target_port     INTEGER NOT NULL DEFAULT 0,
			target_socket   TEXT    NOT NULL DEFAULT '',
			target_image    TEXT    NOT NULL DEFAULT '',
			comm            TEXT    NOT NULL DEFAULT '',
			uid             INTEGER NOT NULL DEFAULT 0,
			severity        TEXT    NOT NULL DEFAULT 'info',
			detail          TEXT    NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_se_anchor_time ON source_events (source_anchor_id, time_ns);
		CREATE INDEX IF NOT EXISTS idx_se_pid_time    ON source_events (pid, time_ns);
		CREATE INDEX IF NOT EXISTS idx_se_kind_time   ON source_events (kind, time_ns);
	`)
	return err
}

// RecordEvent appends a GraphEvent to source_events. Append-only; no
// upsert semantics. Returns the row id.
//
// Empty SourceAnchorID is rejected — graph events without source
// attribution are useless to the correlation-graph UI.
func (s *Store) RecordEvent(ctx context.Context, ev GraphEvent) (int64, error) {
	if ev.SourceAnchorID == 0 {
		return 0, fmt.Errorf("source.RecordEvent: SourceAnchorID is 0")
	}
	if ev.Kind == "" {
		return 0, fmt.Errorf("source.RecordEvent: Kind is empty")
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	if ev.Severity == "" {
		ev.Severity = SeverityInfo
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO source_events
		(source_anchor_id, causal_set_hash, time_ns, pid, parent_pid, kind,
		 target_path, target_host, target_port, target_socket, target_image,
		 comm, uid, severity, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		uint64(ev.SourceAnchorID), int64(ev.CausalSetHash), ev.Time.UnixNano(),
		ev.PID, ev.ParentPID, string(ev.Kind),
		ev.TargetPath, ev.TargetHost, ev.TargetPort, ev.TargetSocket, ev.TargetImage,
		ev.Comm, ev.UID, string(ev.Severity), ev.Detail,
	)
	if err != nil {
		return 0, fmt.Errorf("source.RecordEvent: %w", err)
	}
	return res.LastInsertId()
}

// ─────────────────────────────────────────────────────────────────────
// Query types
// ─────────────────────────────────────────────────────────────────────

// TimeWindow selects events within [Start, End). Both zero = no bound.
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

func (w TimeWindow) String() string {
	if w.Start.IsZero() && w.End.IsZero() {
		return "all"
	}
	return fmt.Sprintf("%s..%s", w.Start.Format(time.RFC3339), w.End.Format(time.RFC3339))
}

// SpineNode is one node on the process-tree backbone: either the root
// SourceAnchor or a process that descended from it. Always rendered by
// the UI. Spine nodes are NEVER evicted by the memory budget — they're
// the skeleton.
type SpineNode struct {
	NodeKey      string            // "src-42" or "p-200"
	Kind         string            // "source" / "process"
	Label        string            // human-readable
	AnchorID     lineage.LineageID // for source nodes
	PID          uint32            // for process nodes
	ParentPID    uint32
	ParentNodeKey string           // for tree edges
	Comm         string
	UID          uint32
	FirstSeen    time.Time
	LastSeen     time.Time
}

// GroupNode is a collapsed aggregation of events of one kind attached
// to one process. Rendered as a "petal" off its parent SpineNode.
//
// Default UI behavior: render the petal with `(Count)` label; on click,
// fetch + render the underlying GraphEvents as leaf nodes.
type GroupNode struct {
	NodeKey       string            // "g-200-files" / "g-200-net" etc.
	Kind          EventKind         // file_read / net_connect / secret_access ...
	ParentNodeKey string            // the process this petal hangs off
	Count         int
	HighSeverity  bool              // any event in the group is high/critical → red glow
	Summary       string            // short human text e.g. "23 reads, 1 write"
	FirstSeen     time.Time
	LastSeen      time.Time
}

// SpineForDepth is SpineFor with a depth cap. Returns the source anchor
// + only processes within maxDepth hops of root. maxDepth <= 0 means
// unlimited (legacy SpineFor behavior).
//
// rootPID (when non-zero) overrides the source-anchor root: BFS starts
// at the spine node with PID = rootPID, returning its descendants. Used
// by the /subtree endpoint to expand a sub-tree on demand.
func (s *Store) SpineForDepth(ctx context.Context, anchorID lineage.LineageID, window TimeWindow, maxDepth int, rootPID uint32) ([]SpineNode, error) {
	// Fetch ALL spine nodes for this anchor first (we filter by BFS depth in-memory).
	all, err := s.SpineFor(ctx, anchorID, window)
	if err != nil {
		return nil, err
	}
	if maxDepth <= 0 && rootPID == 0 {
		return all, nil
	}
	// Build parent → children adjacency.
	childrenByKey := map[string][]int{}
	indexByKey := map[string]int{}
	for i, n := range all {
		indexByKey[n.NodeKey] = i
		childrenByKey[n.ParentNodeKey] = append(childrenByKey[n.ParentNodeKey], i)
	}
	// Find BFS start: the source if rootPID==0, else the matching PID.
	startKey := ""
	if rootPID == 0 {
		if len(all) > 0 {
			startKey = all[0].NodeKey
		}
	} else {
		for _, n := range all {
			if n.PID == rootPID {
				startKey = n.NodeKey
				break
			}
		}
		if startKey == "" {
			return nil, fmt.Errorf("rootPID %d not in spine for anchor %d", rootPID, uint64(anchorID))
		}
	}
	// BFS with depth tracking.
	type qe struct {
		key   string
		depth int
	}
	q := []qe{{key: startKey, depth: 0}}
	out := []SpineNode{}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		idx, ok := indexByKey[cur.key]
		if !ok {
			continue
		}
		out = append(out, all[idx])
		if maxDepth > 0 && cur.depth >= maxDepth {
			continue
		}
		for _, ci := range childrenByKey[cur.key] {
			q = append(q, qe{key: all[ci].NodeKey, depth: cur.depth + 1})
		}
	}
	return out, nil
}

// SpineFor returns the SourceAnchor + every process that has events
// attributed to it under that anchor within window. Order: source
// first, then processes in chronological FirstSeen order.
//
// The Spine is the tree skeleton the UI always renders. It is bounded
// by len(distinct PIDs) in the window — typically <50 even for busy
// sessions because process churn is observed at the kernel level.
func (s *Store) SpineFor(ctx context.Context, anchorID lineage.LineageID, window TimeWindow) ([]SpineNode, error) {
	if anchorID == 0 {
		return nil, fmt.Errorf("SpineFor: anchorID is 0")
	}
	// 1. The anchor itself.
	anchor, err := s.Get(ctx, anchorID)
	if err != nil {
		return nil, fmt.Errorf("anchor lookup: %w", err)
	}
	spine := []SpineNode{{
		NodeKey:   fmt.Sprintf("src-%d", uint64(anchor.ID)),
		Kind:      "source",
		Label:     fmt.Sprintf("#%d %s · %s", uint64(anchor.ID), anchor.Actor, anchor.Kind),
		AnchorID:  anchor.ID,
		Comm:      anchor.Kind.String(),
		UID:       anchor.UID,
		FirstSeen: anchor.CreatedAt,
		LastSeen:  anchor.CreatedAt,
	}}

	// 2. Distinct processes for the anchor inside the window.
	q := `
		SELECT pid, MAX(parent_pid), MAX(comm), MAX(uid),
		       MIN(time_ns), MAX(time_ns)
		FROM source_events
		WHERE source_anchor_id = ? AND pid != 0
	`
	args := []any{uint64(anchorID)}
	if !window.Start.IsZero() {
		q += " AND time_ns >= ?"
		args = append(args, window.Start.UnixNano())
	}
	if !window.End.IsZero() {
		q += " AND time_ns < ?"
		args = append(args, window.End.UnixNano())
	}
	q += " GROUP BY pid ORDER BY MIN(time_ns) ASC"

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("spine query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var pid, parentPID, uid uint32
		var firstNs, lastNs int64
		var comm string
		if err := rows.Scan(&pid, &parentPID, &comm, &uid, &firstNs, &lastNs); err != nil {
			return nil, err
		}
		parentKey := spine[0].NodeKey // default: directly under source
		if parentPID != 0 {
			// We'll resolve parent-key after the full set is loaded below.
			parentKey = fmt.Sprintf("p-%d", parentPID)
		}
		spine = append(spine, SpineNode{
			NodeKey:       fmt.Sprintf("p-%d", pid),
			Kind:          "process",
			Label:         fmt.Sprintf("%s (%d)", comm, pid),
			PID:           pid,
			ParentPID:     parentPID,
			ParentNodeKey: parentKey,
			Comm:          comm,
			UID:           uid,
			FirstSeen:     time.Unix(0, firstNs).UTC(),
			LastSeen:      time.Unix(0, lastNs).UTC(),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 3. Re-parent any process whose parent_pid isn't itself in the spine
	// — those become direct children of the source anchor (orphan-reparent
	// rule, same as Linux PID 1 reparenting).
	known := make(map[uint32]bool, len(spine))
	for _, n := range spine[1:] {
		known[n.PID] = true
	}
	for i := 1; i < len(spine); i++ {
		if !known[spine[i].ParentPID] {
			spine[i].ParentNodeKey = spine[0].NodeKey
		}
	}
	return spine, nil
}

// GroupsFor returns one GroupNode per (pid, kind) aggregation within
// window. These are the collapsed "petals" the UI renders attached to
// each spine process. Click any petal → call GroupEvents to expand.
func (s *Store) GroupsFor(ctx context.Context, anchorID lineage.LineageID, window TimeWindow) ([]GroupNode, error) {
	if anchorID == 0 {
		return nil, fmt.Errorf("GroupsFor: anchorID is 0")
	}
	q := `
		SELECT pid, kind, COUNT(*), MIN(time_ns), MAX(time_ns),
		       MAX(CASE WHEN severity IN ('high','critical') THEN 1 ELSE 0 END)
		FROM source_events
		WHERE source_anchor_id = ?
	`
	args := []any{uint64(anchorID)}
	if !window.Start.IsZero() {
		q += " AND time_ns >= ?"
		args = append(args, window.Start.UnixNano())
	}
	if !window.End.IsZero() {
		q += " AND time_ns < ?"
		args = append(args, window.End.UnixNano())
	}
	q += " GROUP BY pid, kind ORDER BY pid ASC, MIN(time_ns) ASC"

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("groups query: %w", err)
	}
	defer rows.Close()
	var out []GroupNode
	for rows.Next() {
		var pid uint32
		var kind string
		var count int
		var firstNs, lastNs int64
		var highSev int
		if err := rows.Scan(&pid, &kind, &count, &firstNs, &lastNs, &highSev); err != nil {
			return nil, err
		}
		out = append(out, GroupNode{
			NodeKey:       fmt.Sprintf("g-%d-%s", pid, kind),
			Kind:          EventKind(kind),
			ParentNodeKey: fmt.Sprintf("p-%d", pid),
			Count:         count,
			HighSeverity:  highSev == 1,
			Summary:       summarizeGroup(EventKind(kind), count),
			FirstSeen:     time.Unix(0, firstNs).UTC(),
			LastSeen:      time.Unix(0, lastNs).UTC(),
		})
	}
	return out, rows.Err()
}

// summarizeGroup returns a one-line operator-readable label for a
// (kind, count) pair. Kept simple — the UI side panel shows the full
// breakdown when the petal is expanded.
func summarizeGroup(kind EventKind, count int) string {
	noun := map[EventKind]string{
		KindFileRead:     "file reads",
		KindFileWrite:    "file writes",
		KindFileExec:     "file execs",
		KindNetConnect:   "outbound connects",
		KindNetListen:    "listening sockets",
		KindNetAccept:    "inbound accepts",
		KindDNSQuery:     "DNS queries",
		KindSecretAccess: "secret accesses",
		KindCapChange:    "capability changes",
		KindNSChange:     "namespace changes",
		KindPtrace:       "ptrace events",
		KindMemfdExec:    "memfd execs",
		KindPersistence:  "persistence writes",
		KindSpawn:        "spawns",
		KindExec:         "exec transitions",
		KindExit:         "exits",
		KindIdentity:     "identity events",
	}[kind]
	if noun == "" {
		noun = string(kind)
	}
	if count == 1 {
		return fmt.Sprintf("1 %s", strings.TrimSuffix(noun, "s"))
	}
	return fmt.Sprintf("%d %s", count, noun)
}

// GroupEvents returns up to limit events of (anchorID, pid, kind) ordered
// chronologically. Cursor pagination via offset. Used when an operator
// clicks a petal to expand it.
func (s *Store) GroupEvents(
	ctx context.Context,
	anchorID lineage.LineageID,
	pid uint32,
	kind EventKind,
	window TimeWindow,
	limit, offset int,
) ([]GraphEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	q := `
		SELECT id, source_anchor_id, causal_set_hash, time_ns, pid, parent_pid, kind,
		       target_path, target_host, target_port, target_socket, target_image,
		       comm, uid, severity, detail
		FROM source_events
		WHERE source_anchor_id = ? AND pid = ? AND kind = ?
	`
	args := []any{uint64(anchorID), pid, string(kind)}
	if !window.Start.IsZero() {
		q += " AND time_ns >= ?"
		args = append(args, window.Start.UnixNano())
	}
	if !window.End.IsZero() {
		q += " AND time_ns < ?"
		args = append(args, window.End.UnixNano())
	}
	q += " ORDER BY time_ns ASC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("group events: %w", err)
	}
	defer rows.Close()
	var out []GraphEvent
	for rows.Next() {
		var ev GraphEvent
		var anchorRaw uint64
		var hashRaw int64
		var timeNs int64
		var kindStr, sev string
		if err := rows.Scan(
			&ev.ID, &anchorRaw, &hashRaw, &timeNs, &ev.PID, &ev.ParentPID, &kindStr,
			&ev.TargetPath, &ev.TargetHost, &ev.TargetPort, &ev.TargetSocket, &ev.TargetImage,
			&ev.Comm, &ev.UID, &sev, &ev.Detail,
		); err != nil {
			return nil, err
		}
		ev.SourceAnchorID = lineage.LineageID(anchorRaw)
		ev.CausalSetHash = uint64(hashRaw)
		ev.Time = time.Unix(0, timeNs).UTC()
		ev.Kind = EventKind(kindStr)
		ev.Severity = Severity(sev)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// EventCount returns the total event count for an anchor in window.
// Used by the UI to render the timeline density histogram.
func (s *Store) EventCount(ctx context.Context, anchorID lineage.LineageID, window TimeWindow) (int, error) {
	q := `SELECT COUNT(*) FROM source_events WHERE source_anchor_id = ?`
	args := []any{uint64(anchorID)}
	if !window.Start.IsZero() {
		q += " AND time_ns >= ?"
		args = append(args, window.Start.UnixNano())
	}
	if !window.End.IsZero() {
		q += " AND time_ns < ?"
		args = append(args, window.End.UnixNano())
	}
	var n int
	if err := s.db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// SweepEventsOlderThan deletes source_events older than cutoff. Retention
// policy mirrors the v2 scope: 7 days raw on endpoint by default. Caller
// drives the schedule.
func (s *Store) SweepEventsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM source_events WHERE time_ns < ?`, cutoff.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("sweep events: %w", err)
	}
	return res.RowsAffected()
}

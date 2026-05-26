package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/lineage"
)

// NewHTTPHandler returns an http.Handler exposing the source-graph API.
// Mount under a prefix such as "/api/v1/source/" via the daemon's mux.
//
// Routes (all GET):
//
//   /api/v1/source/{id}/graph?window=...&filters=...&max_nodes=...
//       Returns NDJSON stream: meta, spine nodes, group nodes,
//       derived edges, end. Each line is one JSON object.
//
//   /api/v1/source/{id}/group/{group_id}?limit=...&offset=...
//       Returns paginated GraphEvents (full leaf detail). NDJSON.
//
//   /api/v1/source/{id}/events/count?window=...
//       Returns {"count": N, "window": "..."}.
//
// The handler is intentionally read-only — no mutations possible from
// the HTTP surface. Authentication / authorisation is the daemon's
// responsibility (mount behind the protected enterprise UI).
func NewHTTPHandler(store *Store) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/v1/source/", &graphRouter{store: store})
	return mux
}

type graphRouter struct {
	store *Store
}

func (g *graphRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "only GET supported")
		return
	}
	if g.store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "source store not configured")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/source/"), "/")
	if len(parts) < 2 {
		writeJSONError(w, http.StatusNotFound, "missing route")
		return
	}
	idStr, sub := parts[0], parts[1]
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid anchor id: "+idStr)
		return
	}
	anchorID := lineage.LineageID(id)

	switch {
	case sub == "graph" && len(parts) == 2:
		g.handleGraph(w, r, anchorID, 0) // root PID 0 = whole anchor
	case sub == "subtree" && len(parts) == 3:
		// /api/v1/source/{id}/subtree/{pid} — expand a process subtree
		rootPID, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid pid: "+parts[2])
			return
		}
		g.handleGraph(w, r, anchorID, uint32(rootPID))
	case sub == "group" && len(parts) == 3:
		g.handleGroup(w, r, anchorID, parts[2])
	case sub == "events" && len(parts) == 3 && parts[2] == "count":
		g.handleEventCount(w, r, anchorID)
	default:
		writeJSONError(w, http.StatusNotFound, "unknown sub-route: "+sub)
	}
}

// ─────────────────────────────────────────────────────────────────────
// /graph — NDJSON stream of meta + spine + groups + edges + end
// ─────────────────────────────────────────────────────────────────────
func (g *graphRouter) handleGraph(w http.ResponseWriter, r *http.Request, anchorID lineage.LineageID, rootPID uint32) {
	q := r.URL.Query()
	window, werr := parseWindow(q.Get("window"), q.Get("from"), q.Get("to"))
	if werr != nil {
		writeJSONError(w, http.StatusBadRequest, "window: "+werr.Error())
		return
	}
	filterSet := parseFilters(q.Get("filters"))
	maxNodes, _ := strconv.Atoi(q.Get("max_nodes"))
	if maxNodes <= 0 {
		maxNodes = 500
	}
	depth, _ := strconv.Atoi(q.Get("depth"))
	if depth <= 0 {
		depth = 3 // default: show 3 levels from root
	}
	if q.Get("depth") == "all" || q.Get("depth") == "0" {
		depth = 0 // unlimited
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	spine, err := g.store.SpineForDepth(ctx, anchorID, window, depth, rootPID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "spine: "+err.Error())
		return
	}
	groups, err := g.store.GroupsFor(ctx, anchorID, window)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "groups: "+err.Error())
		return
	}
	// Restrict groups to those whose parent process is in the visible spine.
	visibleKeys := make(map[string]bool, len(spine))
	for _, s := range spine {
		visibleKeys[s.NodeKey] = true
	}
	{
		kept := groups[:0]
		for _, gr := range groups {
			if !visibleKeys[gr.ParentNodeKey] {
				continue
			}
			if filterSet != nil && !filterSet[gr.Kind] {
				continue
			}
			kept = append(kept, gr)
		}
		groups = kept
	}
	total, err := g.store.EventCount(ctx, anchorID, window)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "count: "+err.Error())
		return
	}

	layout := Layout(spine, groups)

	// Streaming NDJSON response.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Accel-Buffering", "no") // tell nginx not to buffer
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	emit := func(v any) bool {
		if err := enc.Encode(v); err != nil {
			return false
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}

	// 1. meta — source_id as STRING because uint64 exceeds JS Number.MAX_SAFE_INTEGER
	if !emit(map[string]any{
		"type":         "meta",
		"source_id":    fmt.Sprintf("%d", uint64(anchorID)),
		"window":       window.String(),
		"total_events": total,
		"max_nodes":    maxNodes,
		"spine_count":  len(layout.Spine),
		"group_count":  len(layout.Groups),
	}) {
		return
	}

	// 2. spine nodes
	for _, s := range layout.Spine {
		if !emit(map[string]any{
			"type":            "spine",
			"id":              s.NodeKey,
			"kind":            s.Kind,
			"label":           s.Label,
			"x":               s.X,
			"y":               s.Y,
			"pid":             s.PID,
			"parent_node_key": s.ParentNodeKey,
			"comm":            s.Comm,
			"uid":             s.UID,
			"first_seen":      timeRFC(s.FirstSeen),
			"last_seen":       timeRFC(s.LastSeen),
		}) {
			return
		}
	}

	// 3. group nodes
	for _, gr := range layout.Groups {
		if !emit(map[string]any{
			"type":            "group",
			"id":              gr.NodeKey,
			"kind":            string(gr.Kind),
			"parent_node_key": gr.ParentNodeKey,
			"count":           gr.Count,
			"summary":         gr.Summary,
			"high_severity":   gr.HighSeverity,
			"x":               gr.X,
			"y":               gr.Y,
			"first_seen":      timeRFC(gr.FirstSeen),
			"last_seen":       timeRFC(gr.LastSeen),
		}) {
			return
		}
	}

	// 4. derived edges (spine→parent + group→parent)
	for _, s := range layout.Spine {
		if s.ParentNodeKey == "" || s.ParentNodeKey == s.NodeKey {
			continue
		}
		if !emit(map[string]any{
			"type": "edge",
			"kind": "spine",
			"src":  s.ParentNodeKey,
			"dst":  s.NodeKey,
		}) {
			return
		}
	}
	for _, gr := range layout.Groups {
		if !emit(map[string]any{
			"type": "edge",
			"kind": "petal",
			"src":  gr.ParentNodeKey,
			"dst":  gr.NodeKey,
		}) {
			return
		}
	}

	// 5. end
	_ = emit(map[string]any{
		"type":     "end",
		"rendered": len(layout.Spine) + len(layout.Groups),
	})
}

// ─────────────────────────────────────────────────────────────────────
// /group/{gid} — paginated leaf events for an expanded petal
// ─────────────────────────────────────────────────────────────────────
func (g *graphRouter) handleGroup(w http.ResponseWriter, r *http.Request, anchorID lineage.LineageID, groupID string) {
	pid, kind, perr := parseGroupID(groupID)
	if perr != nil {
		writeJSONError(w, http.StatusBadRequest, "group id: "+perr.Error())
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	window, werr := parseWindow(q.Get("window"), q.Get("from"), q.Get("to"))
	if werr != nil {
		writeJSONError(w, http.StatusBadRequest, "window: "+werr.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	events, err := g.store.GroupEvents(ctx, anchorID, pid, kind, window, limit, offset)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "events: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	emit := func(v any) bool {
		if err := enc.Encode(v); err != nil {
			return false
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}

	if !emit(map[string]any{
		"type":      "meta",
		"source_id": fmt.Sprintf("%d", uint64(anchorID)),
		"pid":       pid,
		"kind":      string(kind),
		"window":    window.String(),
		"returned":  len(events),
		"offset":    offset,
	}) {
		return
	}
	for _, ev := range events {
		if !emit(map[string]any{
			"type":             "event",
			"id":               ev.ID,
			"time":             timeRFC(ev.Time),
			"pid":              ev.PID,
			"parent_pid":       ev.ParentPID,
			"kind":             string(ev.Kind),
			"target_path":      ev.TargetPath,
			"target_host":      ev.TargetHost,
			"target_port":      ev.TargetPort,
			"target_socket":    ev.TargetSocket,
			"target_image":     ev.TargetImage,
			"comm":             ev.Comm,
			"uid":              ev.UID,
			"severity":         string(ev.Severity),
			"causal_set_hash":  fmt.Sprintf("%016x", ev.CausalSetHash),
		}) {
			return
		}
	}
	_ = emit(map[string]any{"type": "end", "returned": len(events)})
}

// ─────────────────────────────────────────────────────────────────────
// /events/count
// ─────────────────────────────────────────────────────────────────────
func (g *graphRouter) handleEventCount(w http.ResponseWriter, r *http.Request, anchorID lineage.LineageID) {
	q := r.URL.Query()
	window, werr := parseWindow(q.Get("window"), q.Get("from"), q.Get("to"))
	if werr != nil {
		writeJSONError(w, http.StatusBadRequest, "window: "+werr.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	count, err := g.store.EventCount(ctx, anchorID, window)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"source_id": fmt.Sprintf("%d", uint64(anchorID)),
		"window":    window.String(),
		"count":     count,
	})
}

// ─────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────

// parseWindow handles three input forms:
//
//   window=5m / 15m / 1h / 6h / 24h / all — relative to now (now-D, now)
//   from=RFC3339 to=RFC3339              — explicit absolute range
//   (none)                                — unbounded
//
// Returned TimeWindow zero-time fields signal "no bound".
func parseWindow(window, from, to string) (TimeWindow, error) {
	if from != "" || to != "" {
		var w TimeWindow
		if from != "" {
			t, err := time.Parse(time.RFC3339, from)
			if err != nil {
				return w, fmt.Errorf("from: %w", err)
			}
			w.Start = t
		}
		if to != "" {
			t, err := time.Parse(time.RFC3339, to)
			if err != nil {
				return w, fmt.Errorf("to: %w", err)
			}
			w.End = t
		}
		return w, nil
	}
	if window == "" || window == "all" {
		return TimeWindow{}, nil
	}
	d, err := time.ParseDuration(window)
	if err != nil {
		return TimeWindow{}, errors.New("expected 5m/15m/1h/6h/24h/all or explicit from/to")
	}
	now := time.Now().UTC()
	return TimeWindow{Start: now.Add(-d), End: now}, nil
}

// parseFilters returns nil (no filter — all kinds pass) for empty
// input, or a set of allowed EventKind values.
func parseFilters(s string) map[EventKind]bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	out := map[EventKind]bool{}
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		out[EventKind(raw)] = true
	}
	return out
}

// parseGroupID parses "g-{pid}-{kind}" into its components.
func parseGroupID(s string) (uint32, EventKind, error) {
	if !strings.HasPrefix(s, "g-") {
		return 0, "", fmt.Errorf("expected group id like g-PID-KIND, got %q", s)
	}
	rest := strings.TrimPrefix(s, "g-")
	dash := strings.IndexByte(rest, '-')
	if dash <= 0 || dash == len(rest)-1 {
		return 0, "", fmt.Errorf("malformed group id %q", s)
	}
	pid, err := strconv.ParseUint(rest[:dash], 10, 32)
	if err != nil {
		return 0, "", fmt.Errorf("bad pid in %q: %w", s, err)
	}
	return uint32(pid), EventKind(rest[dash+1:]), nil
}

func timeRFC(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg, "code": code})
}

// AllEventKinds returns the canonical list of EventKind values in
// stable sorted order. Useful for filter-bar UIs that need a known set.
func AllEventKinds() []EventKind {
	kinds := []EventKind{
		KindSpawn, KindExec, KindExit,
		KindFileRead, KindFileWrite, KindFileExec,
		KindNetConnect, KindNetListen, KindNetAccept, KindDNSQuery,
		KindSecretAccess, KindCapChange, KindNSChange,
		KindPtrace, KindMemfdExec,
		KindPersistence, KindIdentity,
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	return kinds
}

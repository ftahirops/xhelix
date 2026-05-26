package source

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// helper: spin up an httptest server backed by a seeded store.
func newGraphTestServer(t *testing.T) (*httptest.Server, *Store) {
	t.Helper()
	s, _, _ := seedAnchorWithEvents(t)
	srv := httptest.NewServer(NewHTTPHandler(s))
	t.Cleanup(srv.Close)
	return srv, s
}

// helper: read NDJSON stream from response body into a slice of maps.
func readNDJSON(t *testing.T, resp *http.Response) []map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var out []map[string]any
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("ndjson decode: %v -- line: %s", err, line)
		}
		out = append(out, m)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner err: %v", err)
	}
	return out
}

func TestHTTP_Graph_FullSession(t *testing.T) {
	srv, _ := newGraphTestServer(t)
	// depth=all so the test corpus's 4-deep tree is fully returned.
	resp, err := http.Get(srv.URL + "/api/v1/source/42/graph?depth=all")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "ndjson") {
		t.Errorf("content-type=%q, want ndjson", resp.Header.Get("Content-Type"))
	}
	msgs := readNDJSON(t, resp)
	if len(msgs) == 0 {
		t.Fatal("empty stream")
	}

	// First message must be meta.
	if msgs[0]["type"] != "meta" {
		t.Errorf("first msg type=%v, want meta", msgs[0]["type"])
	}
	// source_id is serialised as a STRING because uint64 can exceed
	// JavaScript's Number.MAX_SAFE_INTEGER (2^53 - 1).
	if msgs[0]["source_id"].(string) != "42" {
		t.Errorf("meta.source_id=%v, want \"42\"", msgs[0]["source_id"])
	}

	// Last message must be end.
	last := msgs[len(msgs)-1]
	if last["type"] != "end" {
		t.Errorf("last msg type=%v, want end", last["type"])
	}

	// Verify counts: source + 4 process spine nodes + 9 groups.
	counts := map[string]int{}
	for _, m := range msgs {
		if t, ok := m["type"].(string); ok {
			counts[t]++
		}
	}
	if counts["spine"] != 5 {
		t.Errorf("spine count=%d, want 5 (source + 4 processes)", counts["spine"])
	}
	if counts["group"] != 9 {
		t.Errorf("group count=%d, want 9", counts["group"])
	}
	// Edges: 4 spine→parent + 9 group→parent = 13.
	if counts["edge"] != 13 {
		t.Errorf("edge count=%d, want 13", counts["edge"])
	}
}

func TestHTTP_Graph_WithFilters(t *testing.T) {
	srv, _ := newGraphTestServer(t)
	// Only file_read groups.
	resp, _ := http.Get(srv.URL + "/api/v1/source/42/graph?filters=file_read")
	msgs := readNDJSON(t, resp)
	groupKinds := map[string]int{}
	for _, m := range msgs {
		if m["type"] == "group" {
			if k, ok := m["kind"].(string); ok {
				groupKinds[k]++
			}
		}
	}
	for k := range groupKinds {
		if k != "file_read" {
			t.Errorf("filter=file_read should drop %s, got %d", k, groupKinds[k])
		}
	}
	if groupKinds["file_read"] == 0 {
		t.Error("filter=file_read should keep file_read groups")
	}
}

func TestHTTP_Graph_WithWindow(t *testing.T) {
	srv, _ := newGraphTestServer(t)
	// Past 5 minutes — should return empty since seeded events are from
	// 2026-05-23 14:00 UTC (older than 5 minutes from now).
	resp, _ := http.Get(srv.URL + "/api/v1/source/42/graph?window=5m")
	msgs := readNDJSON(t, resp)
	groupCount := 0
	for _, m := range msgs {
		if m["type"] == "group" {
			groupCount++
		}
	}
	if groupCount != 0 {
		t.Errorf("5m window should drop all (seed is older), got %d groups", groupCount)
	}
}

func TestHTTP_Graph_InvalidAnchorID(t *testing.T) {
	srv, _ := newGraphTestServer(t)
	resp, _ := http.Get(srv.URL + "/api/v1/source/abc/graph")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("non-numeric id should 400, got %d", resp.StatusCode)
	}
}

func TestHTTP_Graph_PostNotAllowed(t *testing.T) {
	srv, _ := newGraphTestServer(t)
	resp, _ := http.Post(srv.URL+"/api/v1/source/42/graph", "application/json", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST should be 405, got %d", resp.StatusCode)
	}
}

func TestHTTP_Group_PaginatedLeaves(t *testing.T) {
	srv, _ := newGraphTestServer(t)
	// PID 200 has 2 file_read events.
	resp, _ := http.Get(srv.URL + "/api/v1/source/42/group/g-200-file_read?limit=10")
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	msgs := readNDJSON(t, resp)
	events := 0
	for _, m := range msgs {
		if m["type"] == "event" {
			events++
		}
	}
	if events != 2 {
		t.Errorf("PID 200 file_read events = %d, want 2", events)
	}

	// Paginate with offset=1.
	resp2, _ := http.Get(srv.URL + "/api/v1/source/42/group/g-200-file_read?limit=10&offset=1")
	msgs2 := readNDJSON(t, resp2)
	events2 := 0
	var paths []string
	for _, m := range msgs2 {
		if m["type"] == "event" {
			events2++
			paths = append(paths, m["target_path"].(string))
		}
	}
	if events2 != 1 {
		t.Errorf("offset=1 should return 1 event, got %d", events2)
	}
	if len(paths) == 1 && paths[0] != "/etc/passwd" {
		t.Errorf("paginated event path = %q, want /etc/passwd", paths[0])
	}
}

func TestHTTP_Group_BadGroupID(t *testing.T) {
	srv, _ := newGraphTestServer(t)
	resp, _ := http.Get(srv.URL + "/api/v1/source/42/group/wrong-format")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad group id should 400, got %d", resp.StatusCode)
	}
}

func TestHTTP_EventCount(t *testing.T) {
	srv, _ := newGraphTestServer(t)
	resp, _ := http.Get(srv.URL + "/api/v1/source/42/events/count")
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["count"].(float64) != 10 {
		t.Errorf("count=%v, want 10", body["count"])
	}
}

func TestHTTP_UnknownSubRoute(t *testing.T) {
	srv, _ := newGraphTestServer(t)
	resp, _ := http.Get(srv.URL + "/api/v1/source/42/banana")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown sub-route should 404, got %d", resp.StatusCode)
	}
}

func TestParseWindow_RelativeForms(t *testing.T) {
	cases := []struct {
		in        string
		wantBound bool
	}{
		{"", false},
		{"all", false},
		{"5m", true},
		{"15m", true},
		{"1h", true},
		{"24h", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			w, err := parseWindow(c.in, "", "")
			if err != nil {
				t.Fatalf("parseWindow(%q): %v", c.in, err)
			}
			hasBound := !w.Start.IsZero() || !w.End.IsZero()
			if hasBound != c.wantBound {
				t.Errorf("parseWindow(%q) bounded=%v, want %v", c.in, hasBound, c.wantBound)
			}
		})
	}
}

func TestParseWindow_BadDuration(t *testing.T) {
	if _, err := parseWindow("notADuration", "", ""); err == nil {
		t.Error("expected error for bad duration")
	}
}

func TestParseGroupID_Cases(t *testing.T) {
	cases := []struct {
		in        string
		wantPID   uint32
		wantKind  EventKind
		wantError bool
	}{
		{"g-200-file_read", 200, KindFileRead, false},
		{"g-1-spawn", 1, KindSpawn, false},
		{"missing-prefix", 0, "", true},
		{"g-abc-file_read", 0, "", true},
		{"g-200-", 0, "", true},
	}
	for _, c := range cases {
		pid, kind, err := parseGroupID(c.in)
		if c.wantError {
			if err == nil {
				t.Errorf("%q: expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if pid != c.wantPID || kind != c.wantKind {
			t.Errorf("%q: pid=%d kind=%q, want %d %q", c.in, pid, kind, c.wantPID, c.wantKind)
		}
	}
}

func TestAllEventKinds_Sorted(t *testing.T) {
	ks := AllEventKinds()
	if len(ks) == 0 {
		t.Fatal("AllEventKinds empty")
	}
	for i := 1; i < len(ks); i++ {
		if ks[i-1] > ks[i] {
			t.Errorf("not sorted: %q > %q", ks[i-1], ks[i])
		}
	}
}

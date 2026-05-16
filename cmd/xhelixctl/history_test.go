package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/store/history"
)

// seed creates a temp history.db with one session, two processes,
// three activities. Returns the path.
func seedHistory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dbp := filepath.Join(dir, "history.db")
	store, err := history.Open(dbp)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	t0 := time.Now().Add(-2 * time.Hour)
	sessID, err := store.InsertSession(ctx, history.Session{
		Kind: "login", Subject: "alice", CGroupClass: "user", StartedAt: t0,
	})
	if err != nil {
		t.Fatal(err)
	}

	pid1, _ := store.InsertProcess(ctx, history.Process{
		SessionID: sessID, PID: 100, Comm: "firefox", Exe: "/usr/bin/firefox",
		CGroupClass: "user", StartedAt: t0,
	})
	pid2, _ := store.InsertProcess(ctx, history.Process{
		SessionID: sessID, PID: 200, Comm: "snapd", Exe: "/usr/bin/snapd",
		CGroupClass: "system", StartedAt: t0,
	})

	_, _ = store.InsertActivity(ctx, history.Activity{
		ProcessID: pid1, StartedAt: t0.Add(time.Minute), EndedAt: t0.Add(2 * time.Minute),
		PrimaryHost: "news.ycombinator.com", Countries: []string{"US"},
		FlowCount: 24, Verdict: "green", VerdictScore: 92, BytesIn: 100000,
	})
	_, _ = store.InsertActivity(ctx, history.Activity{
		ProcessID: pid1, StartedAt: t0.Add(3 * time.Minute), EndedAt: t0.Add(4 * time.Minute),
		PrimaryHost: "github.com", Countries: []string{"US"},
		FlowCount: 10, Verdict: "green", VerdictScore: 95, BytesIn: 50000,
	})
	_, _ = store.InsertActivity(ctx, history.Activity{
		ProcessID: pid2, StartedAt: t0.Add(30 * time.Minute), EndedAt: t0.Add(31 * time.Minute),
		PrimaryHost: "snapcraft.io", Countries: []string{"NL"},
		FlowCount: 3, Verdict: "amber", VerdictScore: 40,
		Reasons: []string{"upload 14x baseline"}, BytesOut: 7000000,
	})
	return dbp
}

func TestHistoryDefaultViewListsSessions(t *testing.T) {
	dbp := seedHistory(t)
	var buf bytes.Buffer
	err := runHistory(historyOptions{DBPath: dbp, Since: "24h"}, &buf)
	if err != nil {
		t.Fatalf("runHistory: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"login session for alice", "3 activities clustered",
		"firefox", "snapd", "AMBER",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
}

func TestHistoryHourView(t *testing.T) {
	dbp := seedHistory(t)
	var buf bytes.Buffer
	err := runHistory(historyOptions{DBPath: dbp, HourView: true, Since: "24h"}, &buf)
	if err != nil {
		t.Fatalf("runHistory: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "activities") {
		t.Errorf("hour view missing activity count\n%s", out)
	}
	if !strings.Contains(out, "firefox") {
		t.Errorf("hour view missing firefox\n%s", out)
	}
}

func TestHistoryActivityDrillDown(t *testing.T) {
	dbp := seedHistory(t)
	// The seed gives us activity IDs 1, 2, 3.
	var buf bytes.Buffer
	err := runHistory(historyOptions{DBPath: dbp, ActivityID: 3}, &buf)
	if err != nil {
		t.Fatalf("runHistory: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"snapd talking to snapcraft.io", "AMBER", "score 40/100", "upload 14x baseline"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
}

func TestHistorySessionView(t *testing.T) {
	dbp := seedHistory(t)
	var buf bytes.Buffer
	err := runHistory(historyOptions{DBPath: dbp, SessionID: 1}, &buf)
	if err != nil {
		t.Fatalf("runHistory: %v", err)
	}
	if !strings.Contains(buf.String(), "login session for alice") {
		t.Errorf("missing session header:\n%s", buf.String())
	}
}

func TestHistoryFilterVerdict(t *testing.T) {
	dbp := seedHistory(t)
	var buf bytes.Buffer
	err := runHistory(historyOptions{
		DBPath: dbp, SessionID: 1, Filter: "verdict=amber",
	}, &buf)
	if err != nil {
		t.Fatalf("runHistory: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "1 activities clustered") {
		t.Errorf("expected 1 amber result, got:\n%s", out)
	}
	if strings.Contains(out, "news.ycombinator.com") || strings.Contains(out, "github.com") {
		t.Errorf("filter leaked green activities:\n%s", out)
	}
}

func TestHistoryFilterCountry(t *testing.T) {
	dbp := seedHistory(t)
	var buf bytes.Buffer
	err := runHistory(historyOptions{
		DBPath: dbp, SessionID: 1, Filter: "country=NL",
	}, &buf)
	if err != nil {
		t.Fatalf("runHistory: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "snapcraft.io") {
		t.Errorf("expected NL match:\n%s", out)
	}
	if strings.Contains(out, "news.ycombinator.com") {
		t.Errorf("filter leaked US activities:\n%s", out)
	}
}

func TestHistoryExportJSONL(t *testing.T) {
	dbp := seedHistory(t)
	var buf bytes.Buffer
	err := runHistoryExport(dbp, "24h", "jsonl", &buf)
	if err != nil {
		t.Fatalf("export jsonl: %v", err)
	}
	lines := strings.Count(strings.TrimSpace(buf.String()), "\n") + 1
	if lines != 3 {
		t.Errorf("expected 3 jsonl lines, got %d:\n%s", lines, buf.String())
	}
	if !strings.Contains(buf.String(), `"primary_host":"news.ycombinator.com"`) &&
		!strings.Contains(buf.String(), `"PrimaryHost":"news.ycombinator.com"`) {
		t.Errorf("jsonl missing expected host:\n%s", buf.String())
	}
}

func TestHistoryExportCSV(t *testing.T) {
	dbp := seedHistory(t)
	var buf bytes.Buffer
	err := runHistoryExport(dbp, "24h", "csv", &buf)
	if err != nil {
		t.Fatalf("export csv: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "primary_host") { // header row
		t.Errorf("csv missing header:\n%s", out)
	}
	if !strings.Contains(out, "snapcraft.io") {
		t.Errorf("csv missing data:\n%s", out)
	}
}

func TestParseSince(t *testing.T) {
	cases := []struct {
		in        string
		wantApprox time.Duration
	}{
		{"24h", 24 * time.Hour},
		{"1h", time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"2w", 14 * 24 * time.Hour},
		{"30m", 30 * time.Minute},
	}
	now := time.Now()
	for _, c := range cases {
		got, err := parseSince(c.in)
		if err != nil {
			t.Errorf("parseSince(%q): %v", c.in, err)
			continue
		}
		delta := now.Sub(got)
		off := delta - c.wantApprox
		if off < -time.Second || off > time.Second {
			t.Errorf("parseSince(%q) delta = %v, want ~%v", c.in, delta, c.wantApprox)
		}
	}
}

func TestParseSinceInvalid(t *testing.T) {
	if _, err := parseSince("garbage"); err == nil {
		t.Fatal("expected error on garbage")
	}
}

func TestFilterToSQL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"verdict=red", `verdict = "red"`},
		{"country=CN", `countries LIKE '%"CN"%'`},
		{"bytes_out>1000000", "bytes_out > 1000000"},
		{"verdict=amber AND country=NL", `verdict = "amber" AND countries LIKE '%"NL"%'`},
	}
	for _, c := range cases {
		got := filterToSQL(c.in)
		if got != c.want {
			t.Errorf("filterToSQL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResolveDBPathRespectsXDG(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/tmp/xdg")
	got, err := resolveDBPath("")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/xdg/xhelix/history.db" {
		t.Errorf("path = %s", got)
	}
}

func TestRunHistoryMissingDBErrors(t *testing.T) {
	err := runHistory(historyOptions{DBPath: "/nonexistent/path/x.db"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for missing db")
	}
}

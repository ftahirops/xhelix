package narrate

import (
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/store/history"
)

func tm(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		panic(err)
	}
	return t
}

func containsAll(t *testing.T, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("output missing %q\n---\n%s\n---", w, got)
		}
	}
}

func TestSessionSummaryEmpty(t *testing.T) {
	r := &Renderer{}
	s := history.Session{
		ID: 1, Kind: "login", Subject: "alice", StartedAt: tm("2026-05-12 08:14:00"),
	}
	out := r.SessionSummary(s, nil, nil)
	containsAll(t, out, "Tue 12 May 2026", "login session for alice", "(ongoing)", "No clustered activities yet.")
}

func TestSessionSummaryWithActivities(t *testing.T) {
	r := &Renderer{}
	s := history.Session{
		ID: 1, Kind: "login", Subject: "alice", StartedAt: tm("2026-05-12 08:14:00"),
		EndedAt: ptr(tm("2026-05-12 12:47:00")),
	}
	procs := map[int64]history.Process{
		100: {ID: 100, PID: 1, Comm: "firefox", Exe: "/usr/bin/firefox"},
		101: {ID: 101, PID: 2, Comm: "snapd", Exe: "/usr/bin/snapd"},
	}
	activities := []history.Activity{
		{ProcessID: 100, StartedAt: tm("2026-05-12 09:01:00"), EndedAt: tm("2026-05-12 09:01:30"),
			PrimaryHost: "news.ycombinator.com", Countries: []string{"US"}, FlowCount: 24, Verdict: "green",
			BytesIn: 4 << 20, BytesOut: 100 << 10, RelatedHosts: []string{"gstatic.com"}},
		{ProcessID: 100, StartedAt: tm("2026-05-12 09:05:00"), EndedAt: tm("2026-05-12 09:06:00"),
			PrimaryHost: "github.com", Countries: []string{"US"}, FlowCount: 10, Verdict: "green",
			BytesIn: 2 << 20, BytesOut: 30 << 10},
		{ProcessID: 101, StartedAt: tm("2026-05-12 09:32:00"), EndedAt: tm("2026-05-12 09:32:30"),
			PrimaryHost: "snapcraft.io", Countries: []string{"NL"}, FlowCount: 3, Verdict: "amber",
			BytesIn: 1 << 10, BytesOut: 6700000, Reasons: []string{"upload 14x baseline"}},
	}
	out := r.SessionSummary(s, activities, procs)
	containsAll(t, out,
		"login session for alice",
		"3 activities clustered",
		"firefox",
		"snapd",
		"AMBER",
		"upload 14x baseline",
	)
}

func TestHourSummaryEmpty(t *testing.T) {
	r := &Renderer{}
	out := r.HourSummary(tm("2026-05-12 09:00:00"), nil, nil)
	containsAll(t, out, "09:00", "No activity in this hour.")
}

func TestHourSummaryListsActivitiesByTime(t *testing.T) {
	r := &Renderer{}
	procs := map[int64]history.Process{
		1: {Comm: "firefox"},
		2: {Comm: "snapd"},
	}
	acts := []history.Activity{
		{ProcessID: 2, StartedAt: tm("2026-05-12 09:32:00"), PrimaryHost: "snapcraft.io", Verdict: "amber", FlowCount: 3, BytesOut: 6700000, Reasons: []string{"upload anomaly"}},
		{ProcessID: 1, StartedAt: tm("2026-05-12 09:01:14"), PrimaryHost: "news.ycombinator.com", Verdict: "green", FlowCount: 24, BytesIn: 100 << 10},
	}
	out := r.HourSummary(tm("2026-05-12 09:00:00"), acts, procs)
	// 09:01:14 must appear before 09:32:00 in the output
	pos1 := strings.Index(out, "09:01:14")
	pos2 := strings.Index(out, "09:32:00")
	if pos1 < 0 || pos2 < 0 || pos1 > pos2 {
		t.Fatalf("activities not chronologically ordered:\n%s", out)
	}
	containsAll(t, out, "2 activities", "2 distinct apps", "news.ycombinator.com", "snapcraft.io")
}

func TestActivityDrillDown(t *testing.T) {
	r := &Renderer{}
	p := history.Process{
		ID: 100, PID: 3214, Comm: "firefox", Exe: "/usr/lib/firefox/firefox",
		CGroupClass: "user", Unit: "firefox.service", UserID: "1000",
	}
	a := history.Activity{
		ProcessID:    100,
		StartedAt:    tm("2026-05-12 09:01:14"),
		EndedAt:      tm("2026-05-12 09:01:31"),
		PrimaryHost:  "news.ycombinator.com",
		FlowCount:    24,
		Verdict:      "green",
		VerdictScore: 92,
		Reasons:      []string{"all_intel_clean", "baseline_match"},
	}
	flows := []history.Flow{
		{DNSQName: "news.ycombinator.com", BytesIn: 142000},
		{DNSQName: "fonts.gstatic.com", BytesIn: 24000},
		{DNSQName: "news.ycombinator.com", BytesIn: 8000},
		{DNSQName: "fonts.gstatic.com", BytesIn: 16000},
	}
	dns := []history.DNSQuery{
		{AskedAt: tm("2026-05-12 09:01:14"), QName: "news.ycombinator.com", QType: "A", Answers: []string{"209.216.230.240"}},
		{AskedAt: tm("2026-05-12 09:01:15"), QName: "fonts.gstatic.com", QType: "A", Answers: []string{"142.250.83.97"}},
	}
	out := r.Activity(a, p, flows, dns)
	containsAll(t, out,
		"firefox talking to news.ycombinator.com",
		"pid 3214",
		"cgroup_class=user",
		"unit=firefox.service",
		"GREEN",
		"score 92/100",
		"all_intel_clean",
		"news.ycombinator.com",
		"fonts.gstatic.com",
		"DNS queries:",
		"209.216.230.240",
	)
	// News should appear before gstatic in the host list (more bytes_in).
	pos1 := strings.Index(out, "- news.ycombinator.com")
	pos2 := strings.Index(out, "- fonts.gstatic.com")
	if pos1 < 0 || pos2 < 0 || pos1 > pos2 {
		t.Fatalf("hosts not sorted by bytes_in:\n%s", out)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		n    uint64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1 << 20, "1.0 MB"},
		{int64ToUint(1<<30) + (1<<29), "1.50 GB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.n); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestHumanCountWithCommas(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{42, "42"},
		{999, "999"},
		{1000, "1,000"},
		{12345, "12,345"},
		{1234567, "1,234,567"},
	}
	for _, c := range cases {
		if got := humanCount(c.n); got != c.want {
			t.Errorf("humanCount(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Second, "5 seconds"},
		{45 * time.Second, "45 seconds"},
		{2 * time.Minute, "2 minutes"},
		{59 * time.Minute, "59 minutes"},
		{2*time.Hour + 30*time.Minute, "2h 30m"},
	}
	for _, c := range cases {
		if got := humanDuration(c.d); got != c.want {
			t.Errorf("humanDuration(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestTimeOfDayPhrase(t *testing.T) {
	cases := []struct {
		h    int
		want string
	}{
		{2, "overnight"},
		{6, "morning"},
		{12, "afternoon"},
		{19, "evening"},
		{23, "overnight"},
	}
	for _, c := range cases {
		got := timeOfDayPhrase(time.Date(2026, 5, 12, c.h, 0, 0, 0, time.UTC))
		if got != c.want {
			t.Errorf("hour=%d: got %q, want %q", c.h, got, c.want)
		}
	}
}

func TestGroupedActivityLinesGreenBucketsAndAmberHighlights(t *testing.T) {
	procs := map[int64]history.Process{
		1: {Comm: "firefox"},
		2: {Comm: "snapd"},
	}
	acts := []history.Activity{
		{ProcessID: 1, PrimaryHost: "github.com", Verdict: "green"},
		{ProcessID: 1, PrimaryHost: "news.ycombinator.com", Verdict: "green"},
		{ProcessID: 1, PrimaryHost: "google.com", Verdict: "green"},
		{ProcessID: 2, StartedAt: tm("2026-05-12 09:32:00"), PrimaryHost: "snapcraft.io",
			Verdict: "amber", Reasons: []string{"upload anomaly"}},
	}
	lines := groupedActivityLines(acts, procs)
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2 (one bucket + one highlight)", len(lines))
	}
	combined := strings.Join(lines, "\n")
	containsAll(t, combined,
		"3  firefox",
		"AMBER",
		"snapcraft.io",
		"upload anomaly",
	)
}

func TestActivityWithoutDNSStillRenders(t *testing.T) {
	r := &Renderer{}
	a := history.Activity{
		PrimaryIP: "1.2.3.4", FlowCount: 1, Verdict: "amber", VerdictScore: 40,
		StartedAt: tm("2026-05-12 10:00:00"), EndedAt: tm("2026-05-12 10:00:05"),
	}
	p := history.Process{PID: 99, Comm: "curl", Exe: "/usr/bin/curl"}
	out := r.Activity(a, p, []history.Flow{{DstIP: "1.2.3.4", BytesIn: 500}}, nil)
	containsAll(t, out, "curl talking to 1.2.3.4", "AMBER", "1.2.3.4")
}

// helpers

func ptr(t time.Time) *time.Time { return &t }

func int64ToUint(n int64) uint64 { return uint64(n) }

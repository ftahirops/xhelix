// Package narrate turns history rows into human-readable
// paragraphs for the narrative network journal.
//
// Three granularities exist (see docs/NETWORK_TELEMETRY_AND_
// HISTORY.md):
//
//   - Session  — one entry per user/system/container session
//   - Hour     — one entry per hour with the active apps
//   - Activity — one entry per clustered activity with drill-down
//
// The package is pure: each renderer takes already-fetched rows
// from pkg/store/history (the SQL join is the caller's job) and
// returns a string. No I/O, no shared state, trivially tested.
package narrate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/store/history"
)

// Renderer holds formatting options. Zero value works.
type Renderer struct {
	// Now is the clock function used to phrase "today", "this
	// morning", etc. nil → time.Now.
	Now func() time.Time
}

// now returns the renderer's clock value.
func (r *Renderer) now() time.Time {
	if r != nil && r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SessionSummary renders one session's header + roll-up paragraph
// + grouped activity tally. Activities should be filtered by the
// caller to those belonging to this session.
func (r *Renderer) SessionSummary(s history.Session, activities []history.Activity, processes map[int64]history.Process) string {
	var b strings.Builder
	r.writeSessionHeader(&b, s)

	stats := summarise(activities)
	subj := s.Subject
	if subj == "" {
		subj = "(unknown)"
	}
	period := timeOfDayPhrase(s.StartedAt)

	fmt.Fprintf(&b, "This %s, your machine made %s outbound connections to %d distinct destinations across %d countries.\nTotal: %s downloaded, %s uploaded.\n\n",
		period,
		humanCount(stats.totalFlows),
		stats.distinctHosts,
		stats.distinctCountries,
		humanBytes(stats.bytesIn),
		humanBytes(stats.bytesOut),
	)

	if len(activities) == 0 {
		b.WriteString("No clustered activities yet.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "%d activities clustered:\n", len(activities))
	for _, line := range groupedActivityLines(activities, processes) {
		fmt.Fprintf(&b, "  - %s\n", line)
	}
	return b.String()
}

// HourSummary renders one hour-bucket. `hour` should be a time at
// minute=0 second=0; activities are everything that started in
// [hour, hour+1h).
func (r *Renderer) HourSummary(hour time.Time, activities []history.Activity, processes map[int64]history.Process) string {
	var b strings.Builder
	fmt.Fprintf(&b, "--- Hour %s ---\n", hour.Format("15:04 — Mon 2 Jan 2006"))

	if len(activities) == 0 {
		b.WriteString("No activity in this hour.\n")
		return b.String()
	}

	stats := summarise(activities)
	fmt.Fprintf(&b, "%d activities, %s connections, %d distinct apps.\n\n",
		len(activities), humanCount(stats.totalFlows), stats.distinctProcesses)

	// Sort by start time
	sorted := make([]history.Activity, len(activities))
	copy(sorted, activities)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].StartedAt.Before(sorted[j].StartedAt) })

	for _, a := range sorted {
		p := processes[a.ProcessID]
		fmt.Fprintf(&b, "  %s  %-14s %s\n",
			a.StartedAt.Format("15:04:05"),
			truncate(processName(p), 14),
			activityOneLine(a),
		)
	}
	return b.String()
}

// Activity renders one activity in full drill-down form, including
// the cluster's flows and DNS queries.
func (r *Renderer) Activity(a history.Activity, p history.Process, flows []history.Flow, dns []history.DNSQuery) string {
	var b strings.Builder
	title := a.PrimaryHost
	if title == "" {
		title = a.PrimaryIP
	}
	if title == "" {
		title = "(direct connection)"
	}
	fmt.Fprintf(&b, "--- Activity: %s talking to %s ---\n",
		processName(p), title)

	dur := a.EndedAt.Sub(a.StartedAt)
	fmt.Fprintf(&b, "  Started %s, ended %s (%s).\n",
		a.StartedAt.Format("15:04:05"),
		a.EndedAt.Format("15:04:05"),
		humanDuration(dur),
	)
	fmt.Fprintf(&b, "  Process: %s  pid %d\n", p.Exe, p.PID)
	if p.UserID != "" || p.Unit != "" || p.CGroupClass != "" {
		fmt.Fprintf(&b, "  User: %s (cgroup_class=%s, unit=%s)\n",
			nonEmpty(p.UserID, "unknown"), p.CGroupClass, p.Unit)
	}

	fmt.Fprintf(&b, "\n  Verdict: %s  (score %.0f/100)\n",
		strings.ToUpper(string(a.Verdict)),
		a.VerdictScore,
	)
	if len(a.Reasons) > 0 {
		b.WriteString("  Reasons:\n")
		for _, reason := range a.Reasons {
			fmt.Fprintf(&b, "    - %s\n", reason)
		}
	}

	b.WriteString("\n")
	fmt.Fprintf(&b, "  %d flows in this activity:\n", a.FlowCount)
	hostBytes := map[string]uint64{}
	hostFlows := map[string]int{}
	for _, f := range flows {
		key := f.DNSQName
		if key == "" {
			key = f.DstIP
		}
		hostBytes[key] += f.BytesIn
		hostFlows[key]++
	}
	hosts := make([]string, 0, len(hostBytes))
	for h := range hostBytes {
		hosts = append(hosts, h)
	}
	sort.Slice(hosts, func(i, j int) bool { return hostBytes[hosts[i]] > hostBytes[hosts[j]] })
	for _, h := range hosts {
		fmt.Fprintf(&b, "    - %s (%d flows, %s in)\n",
			h, hostFlows[h], humanBytes(hostBytes[h]))
	}

	if len(dns) > 0 {
		b.WriteString("\n  DNS queries:\n")
		// Sort by AskedAt
		sorted := make([]history.DNSQuery, len(dns))
		copy(sorted, dns)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].AskedAt.Before(sorted[j].AskedAt) })
		for _, q := range sorted {
			ans := strings.Join(q.Answers, ", ")
			if ans == "" {
				ans = "NODATA"
			}
			fmt.Fprintf(&b, "    %s  %-5s  %-40s  ->  %s\n",
				q.AskedAt.Format("15:04:05"),
				strOrDash(q.QType),
				q.QName,
				ans,
			)
		}
	}

	return b.String()
}

// activityOneLine formats one activity for hour view.
func activityOneLine(a history.Activity) string {
	host := a.PrimaryHost
	if host == "" {
		host = a.PrimaryIP
	}
	if host == "" {
		host = "(direct conn)"
	}
	verdict := strings.ToUpper(string(a.Verdict))
	if verdict == "" {
		verdict = "GREEN"
	}
	bytes := humanBytes(a.BytesIn + a.BytesOut)
	return fmt.Sprintf("%s — %s (%d flows, %s).  %s.",
		host, verdict, a.FlowCount, bytes, oneLineReason(a))
}

// oneLineReason returns the first reason or a placeholder.
func oneLineReason(a history.Activity) string {
	if len(a.Reasons) > 0 {
		return a.Reasons[0]
	}
	return "no anomalies"
}

// groupedActivityLines collapses repeat-flavour activities into
// "12 Firefox browsing — green" style summary lines, with red/
// amber rows broken out individually.
func groupedActivityLines(activities []history.Activity, processes map[int64]history.Process) []string {
	type bucket struct {
		exe     string
		verdict string
		count   int
		hosts   map[string]struct{}
	}
	buckets := map[string]*bucket{}
	var highlights []history.Activity

	for _, a := range activities {
		switch a.Verdict {
		case "amber", "red":
			highlights = append(highlights, a)
			continue
		}
		exe := processName(processes[a.ProcessID])
		k := exe + "|" + a.Verdict
		bb := buckets[k]
		if bb == nil {
			bb = &bucket{exe: exe, verdict: a.Verdict, hosts: map[string]struct{}{}}
			buckets[k] = bb
		}
		bb.count++
		if a.PrimaryHost != "" {
			bb.hosts[a.PrimaryHost] = struct{}{}
		}
	}

	// Render greens first, then highlights (amber/red).
	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return buckets[keys[i]].count > buckets[keys[j]].count })

	out := make([]string, 0, len(buckets)+len(highlights))
	for _, k := range keys {
		bb := buckets[k]
		hosts := make([]string, 0, len(bb.hosts))
		for h := range bb.hosts {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		hostList := joinAtMost(hosts, 4)
		verdict := bb.verdict
		if verdict == "" {
			verdict = "green"
		}
		line := fmt.Sprintf("%2d  %s (%s) — %s",
			bb.count, bb.exe, hostList, strings.ToUpper(verdict))
		out = append(out, line)
	}
	for _, a := range highlights {
		exe := processName(processes[a.ProcessID])
		host := a.PrimaryHost
		if host == "" {
			host = a.PrimaryIP
		}
		verdict := strings.ToUpper(string(a.Verdict))
		reason := oneLineReason(a)
		out = append(out, fmt.Sprintf(" 1  %s  %s  %s %s (%s) — %s",
			verdictBadge(a.Verdict),
			a.StartedAt.Format("15:04"),
			exe, host, verdict, reason))
	}
	return out
}

// verdictBadge returns a short prefix string for non-green
// verdicts.
func verdictBadge(v string) string {
	switch v {
	case "amber":
		return "!"
	case "red":
		return "!!"
	}
	return " "
}

// ── helpers ────────────────────────────────────────────────────

type summary struct {
	totalFlows        int
	bytesIn           uint64
	bytesOut          uint64
	distinctHosts     int
	distinctCountries int
	distinctProcesses int
}

func summarise(activities []history.Activity) summary {
	var s summary
	hosts := map[string]struct{}{}
	countries := map[string]struct{}{}
	processes := map[int64]struct{}{}
	for _, a := range activities {
		s.totalFlows += a.FlowCount
		s.bytesIn += a.BytesIn
		s.bytesOut += a.BytesOut
		if a.PrimaryHost != "" {
			hosts[a.PrimaryHost] = struct{}{}
		}
		for _, h := range a.RelatedHosts {
			hosts[h] = struct{}{}
		}
		for _, c := range a.Countries {
			countries[c] = struct{}{}
		}
		processes[a.ProcessID] = struct{}{}
	}
	s.distinctHosts = len(hosts)
	s.distinctCountries = len(countries)
	s.distinctProcesses = len(processes)
	return s
}

func (r *Renderer) writeSessionHeader(b *strings.Builder, s history.Session) {
	subj := s.Subject
	if subj == "" {
		subj = "(unknown)"
	}
	when := s.StartedAt.Format("Mon 2 Jan 2006")
	dur := ""
	if s.EndedAt != nil {
		dur = fmt.Sprintf("  %s -> %s (%s)",
			s.StartedAt.Format("15:04"),
			s.EndedAt.Format("15:04"),
			humanDuration(s.EndedAt.Sub(s.StartedAt)),
		)
	} else {
		dur = fmt.Sprintf("  %s -> (ongoing)", s.StartedAt.Format("15:04"))
	}
	fmt.Fprintf(b, "--- %s — %s session for %s ---\n%s\n\n",
		when, s.Kind, subj, dur)
}

func processName(p history.Process) string {
	if p.Comm != "" {
		return p.Comm
	}
	if p.Exe != "" {
		return p.Exe
	}
	if p.PID != 0 {
		return fmt.Sprintf("pid-%d", p.PID)
	}
	return "(unknown process)"
}

func humanBytes(n uint64) string {
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%d B", n)
	case n < k*k:
		return fmt.Sprintf("%.1f KB", float64(n)/k)
	case n < k*k*k:
		return fmt.Sprintf("%.1f MB", float64(n)/(k*k))
	}
	return fmt.Sprintf("%.2f GB", float64(n)/(k*k*k))
}

func humanCount(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	// Manual thousand-separator
	s := fmt.Sprintf("%d", n)
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	return fmt.Sprintf("%dh %dm", h, m)
}

func timeOfDayPhrase(t time.Time) string {
	h := t.Hour()
	switch {
	case h < 5:
		return "overnight"
	case h < 12:
		return "morning"
	case h < 17:
		return "afternoon"
	case h < 22:
		return "evening"
	}
	return "overnight"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-1] + "."
}

func joinAtMost(s []string, n int) string {
	if len(s) <= n {
		return strings.Join(s, ", ")
	}
	return strings.Join(s[:n], ", ") + fmt.Sprintf(", +%d more", len(s)-n)
}

func strOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

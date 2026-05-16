package doctor

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"
)

// FormatJSON writes the report as a stable JSON document. Suitable
// for piping into jq, splunk, or storing as artefact.
func FormatJSON(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport(rep))
}

type jsonFinding struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Status         string `json:"status"`
	Evidence       string `json:"evidence,omitempty"`
	Detail         string `json:"detail,omitempty"`
	Description    string `json:"description,omitempty"`
	Impact         string `json:"impact,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
	FixCommand     string `json:"fix_command,omitempty"`
	Risky          bool   `json:"risky,omitempty"`
	HasApply       bool   `json:"has_apply,omitempty"`
	Error          string `json:"error,omitempty"`
}

type jsonReportT struct {
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	DurationMs int64         `json:"duration_ms"`
	Hostname   string        `json:"hostname,omitempty"`
	Score      Score         `json:"score"`
	Findings   []jsonFinding `json:"findings"`
}

func jsonReport(rep Report) jsonReportT {
	out := jsonReportT{
		StartedAt:  rep.StartedAt,
		FinishedAt: rep.FinishedAt,
		DurationMs: rep.FinishedAt.Sub(rep.StartedAt).Milliseconds(),
		Hostname:   rep.Hostname,
		Score:      rep.Score,
	}
	for _, f := range rep.Findings {
		jf := jsonFinding{
			ID:             f.Check.ID,
			Title:          f.Check.Title,
			Category:       f.Check.Category,
			Severity:       f.Check.Severity.String(),
			Status:         f.Result.Status.String(),
			Evidence:       f.Result.Evidence,
			Detail:         f.Result.Detail,
			Description:    f.Check.Description,
			Impact:         f.Check.Impact,
			Recommendation: f.Check.Recommendation,
			FixCommand:     f.Check.FixCommand,
			Risky:          f.Check.Risky,
			HasApply:       f.Check.Apply != nil,
		}
		if f.Result.Err != nil {
			jf.Error = f.Result.Err.Error()
		}
		out.Findings = append(out.Findings, jf)
	}
	return out
}

// ANSI colour helpers — disabled when caller passes useColor=false.
type colour struct {
	red, yellow, green, cyan, dim, bold, reset string
}

func ansi(useColor bool) colour {
	if !useColor {
		return colour{}
	}
	return colour{
		red:    "\x1b[31m",
		yellow: "\x1b[33m",
		green:  "\x1b[32m",
		cyan:   "\x1b[36m",
		dim:    "\x1b[2m",
		bold:   "\x1b[1m",
		reset:  "\x1b[0m",
	}
}

// FormatText writes a colour-coded terminal report.
func FormatText(w io.Writer, rep Report, useColor bool) {
	c := ansi(useColor)

	fmt.Fprintf(w, "%sxhelix doctor — security audit%s\n", c.bold, c.reset)
	fmt.Fprintf(w, "%s%s%s\n", c.dim, strings.Repeat("─", 60), c.reset)
	if rep.Hostname != "" {
		fmt.Fprintf(w, "host:       %s\n", rep.Hostname)
	}
	fmt.Fprintf(w, "started:    %s\n", rep.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "duration:   %s\n", rep.FinishedAt.Sub(rep.StartedAt).Round(time.Millisecond))
	fmt.Fprintf(w, "checks:     %d total | %s%d pass%s | %s%d warn%s | %s%d fail%s | %d skip | %d error\n",
		rep.Score.Total,
		c.green, rep.Score.Passed, c.reset,
		c.yellow, rep.Score.Warned, c.reset,
		c.red, rep.Score.Failed, c.reset,
		rep.Score.Skipped, rep.Score.Errored,
	)
	fmt.Fprintf(w, "score:      %s%d/100%s\n",
		scoreColor(c, rep.Score.Composite), rep.Score.Composite, c.reset)
	fmt.Fprintf(w, "by sev:     %sCRIT %d%s | %sHIGH %d%s | MED %d | LOW %d (failed)\n",
		c.red, rep.FailedCritical(), c.reset,
		c.red, rep.FailedHigh(), c.reset,
		rep.FailedMedium(), rep.FailedLow())
	fmt.Fprintln(w)

	failed := rep.FailedFindings()
	if len(failed) == 0 {
		fmt.Fprintf(w, "%s✓ all checks passed%s\n", c.green, c.reset)
		return
	}

	fmt.Fprintf(w, "%sFindings (%d) — sorted by severity:%s\n\n", c.bold, len(failed), c.reset)

	curCat := ""
	for _, f := range failed {
		if f.Check.Category != curCat {
			curCat = f.Check.Category
			fmt.Fprintf(w, "%s── %s ──%s\n", c.cyan, curCat, c.reset)
		}
		statusBadge := badge(c, f.Result.Status, f.Check.Severity)
		fmt.Fprintf(w, "%s %s%s%s  %s\n",
			statusBadge, c.bold, f.Check.ID, c.reset, f.Check.Title)
		if f.Result.Evidence != "" {
			fmt.Fprintf(w, "    found: %s\n", f.Result.Evidence)
		}
		if f.Check.Impact != "" {
			fmt.Fprintf(w, "    %simpact:%s %s\n", c.yellow, c.reset, wrap(f.Check.Impact, 76, "    "))
		}
		if f.Check.Recommendation != "" {
			fmt.Fprintf(w, "    %sfix:%s    %s\n", c.green, c.reset, wrap(f.Check.Recommendation, 76, "    "))
		}
		if f.Check.FixCommand != "" {
			fmt.Fprintf(w, "    %scmd:%s    %s\n", c.dim, c.reset, f.Check.FixCommand)
		}
		fmt.Fprintln(w)
	}
}

func scoreColor(c colour, score int) string {
	switch {
	case score >= 85:
		return c.green
	case score >= 60:
		return c.yellow
	default:
		return c.red
	}
}

func badge(c colour, st Status, sev Severity) string {
	tag := fmt.Sprintf("[%s/%s]", st.String(), strings.ToUpper(sev.String()[:3]))
	switch st {
	case Fail:
		return c.red + c.bold + tag + c.reset
	case Warn:
		return c.yellow + tag + c.reset
	case Pass:
		return c.green + tag + c.reset
	case Skip:
		return c.dim + tag + c.reset
	default:
		return tag
	}
}

func wrap(s string, width int, indent string) string {
	if len(s) <= width {
		return s
	}
	var b strings.Builder
	col := 0
	for _, w := range strings.Fields(s) {
		if col > 0 && col+1+len(w) > width {
			b.WriteByte('\n')
			b.WriteString(indent)
			col = 0
		}
		if col > 0 {
			b.WriteByte(' ')
			col++
		}
		b.WriteString(w)
		col += len(w)
	}
	return b.String()
}

const htmlTpl = `<!doctype html>
<html><head><meta charset="utf-8"><title>xhelix doctor — {{.Hostname}}</title>
<style>
  body { font-family: -apple-system, ui-sans-serif, sans-serif; max-width: 1100px;
         margin: 2em auto; padding: 0 1em; background: #1e1f29; color: #f8f8f2; }
  h1 { color: #ff79c6; }
  .meta { color: #6272a4; margin-bottom: 1em; }
  .score { display:inline-block; padding: 0.5em 1em; border-radius: 8px;
           font-weight: bold; font-size: 1.2em; }
  .score.good { background: #50fa7b; color: #1e1f29; }
  .score.ok   { background: #f1fa8c; color: #1e1f29; }
  .score.bad  { background: #ff5555; color: #f8f8f2; }
  .badge { display:inline-block; padding:0.1em 0.4em; border-radius:3px;
           font-family: ui-monospace, monospace; font-size: 0.8em;
           margin-right: 0.5em; }
  .badge.fail { background:#ff5555; color:#f8f8f2; }
  .badge.warn { background:#f1fa8c; color:#1e1f29; }
  .badge.pass { background:#50fa7b; color:#1e1f29; }
  .badge.skip { background:#6272a4; color:#f8f8f2; }
  details { background: #282a36; border-left: 3px solid #6272a4;
            padding: 0.8em 1em; margin-bottom: 0.5em; border-radius: 4px; }
  details.fail { border-left-color: #ff5555; }
  details.warn { border-left-color: #f1fa8c; }
  details.pass { border-left-color: #50fa7b; }
  summary { cursor: pointer; font-weight: 600; }
  .id { color: #8be9fd; font-family: ui-monospace, monospace; }
  .impact { color: #ffb86c; margin-top: 0.6em; }
  .fix    { color: #50fa7b; }
  pre { background: #1e1f29; padding: 0.6em; border-radius: 4px; overflow-x: auto; }
  table { border-collapse: collapse; }
  td { padding: 0.2em 1em 0.2em 0; }
</style>
</head>
<body>
<h1>xhelix doctor</h1>
<div class="meta">
  host: {{.Hostname}} · started: {{.StartedAt.Format "2006-01-02 15:04:05 MST"}} ·
  duration: {{.DurationMs}}ms
</div>
<div class="score {{.ScoreClass}}">score: {{.Score.Composite}}/100</div>
<table style="margin-top:1em">
  <tr><td>checks total</td><td>{{.Score.Total}}</td></tr>
  <tr><td>pass</td><td>{{.Score.Passed}}</td></tr>
  <tr><td>warn</td><td>{{.Score.Warned}}</td></tr>
  <tr><td>fail</td><td>{{.Score.Failed}}</td></tr>
  <tr><td>skip</td><td>{{.Score.Skipped}}</td></tr>
  <tr><td>error</td><td>{{.Score.Errored}}</td></tr>
</table>
<h2>Findings</h2>
{{range .Findings}}
<details class="{{.StatusClass}}">
  <summary>
    <span class="badge {{.StatusClass}}">{{.Status}}</span>
    <span class="badge">{{.Severity}}</span>
    <span class="id">{{.ID}}</span>
    {{.Title}}
  </summary>
  {{if .Evidence}}<p><b>found:</b> <code>{{.Evidence}}</code></p>{{end}}
  {{if .Description}}<p>{{.Description}}</p>{{end}}
  {{if .Impact}}<p class="impact"><b>impact:</b> {{.Impact}}</p>{{end}}
  {{if .Recommendation}}<p class="fix"><b>fix:</b> {{.Recommendation}}</p>{{end}}
  {{if .FixCommand}}<pre>{{.FixCommand}}</pre>{{end}}
</details>
{{end}}
</body></html>
`

type htmlFinding struct {
	ID, Title, Category, Severity, Status      string
	StatusClass                                string
	Evidence, Description, Impact, Recommendation, FixCommand string
}

type htmlData struct {
	Hostname   string
	StartedAt  time.Time
	DurationMs int64
	Score      Score
	ScoreClass string
	Findings   []htmlFinding
}

// FormatHTML renders a single-file dashboard report.
func FormatHTML(w io.Writer, rep Report) error {
	data := htmlData{
		Hostname:   rep.Hostname,
		StartedAt:  rep.StartedAt,
		DurationMs: rep.FinishedAt.Sub(rep.StartedAt).Milliseconds(),
		Score:      rep.Score,
	}
	switch {
	case rep.Score.Composite >= 85:
		data.ScoreClass = "good"
	case rep.Score.Composite >= 60:
		data.ScoreClass = "ok"
	default:
		data.ScoreClass = "bad"
	}
	for _, f := range rep.Findings {
		hf := htmlFinding{
			ID:             f.Check.ID,
			Title:          f.Check.Title,
			Category:       f.Check.Category,
			Severity:       strings.ToUpper(f.Check.Severity.String()),
			Status:         f.Result.Status.String(),
			Evidence:       f.Result.Evidence,
			Description:    f.Check.Description,
			Impact:         f.Check.Impact,
			Recommendation: f.Check.Recommendation,
			FixCommand:     f.Check.FixCommand,
		}
		switch f.Result.Status {
		case Fail:
			hf.StatusClass = "fail"
		case Warn:
			hf.StatusClass = "warn"
		case Pass:
			hf.StatusClass = "pass"
		default:
			hf.StatusClass = "skip"
		}
		data.Findings = append(data.Findings, hf)
	}
	t := template.Must(template.New("report").Parse(htmlTpl))
	return t.Execute(w, data)
}

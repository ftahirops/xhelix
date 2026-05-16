package web

// Embedded HTML templates and CSS for the enterprise dashboard.
//
// Designed for low overhead: total payload < 30 KB, no external
// fetches. Vanilla HTML and CSS — every page works without JS.
// SSE adds live updates as a progressive enhancement.

const stylesheet = `
:root{
  --bg:#0d1117;--card:#161b22;--card2:#1c2128;--border:#30363d;
  --fg:#e6edf3;--mut:#7d8590;--accent:#58a6ff;--accent-soft:#1f6feb33;
  --crit:#f85149;--high:#ff8c42;--warn:#d29922;--notice:#3fb950;--info:#79c0ff;
  --link:#58a6ff;--link-hover:#79c0ff;
  --table-row:rgba(255,255,255,0.02);
  --table-row-hover:rgba(88,166,255,0.05);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--fg);
  font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif;
  font-size:14px;line-height:1.4}
a{color:var(--link);text-decoration:none}
a:hover{color:var(--link-hover);text-decoration:underline}
header{background:var(--card2);border-bottom:1px solid var(--border);
  padding:0 24px;height:56px;display:flex;align-items:center;
  position:sticky;top:0;z-index:100}
header h1{margin:0;font-size:18px;font-weight:600;color:var(--fg);margin-right:32px}
header h1 span.tag{font-size:10px;background:var(--accent-soft);
  color:var(--accent);padding:2px 6px;border-radius:3px;margin-left:8px;
  font-weight:500;letter-spacing:.5px}
nav.tabs{display:flex;gap:4px;flex:1}
nav.tabs a{padding:8px 16px;border-radius:6px;color:var(--mut);
  font-weight:500;font-size:13px;text-decoration:none;
  transition:background .1s,color .1s}
nav.tabs a:hover{background:var(--card);color:var(--fg)}
nav.tabs a.active{background:var(--card);color:var(--fg)}
header .right{display:flex;align-items:center;gap:16px;color:var(--mut);
  font-size:12px}
header .right .live{display:inline-flex;align-items:center;gap:6px}
header .right .live::before{content:"";width:6px;height:6px;
  background:var(--notice);border-radius:50%;
  animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:.4}50%{opacity:1}}

main{padding:24px}
.tile-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
  gap:12px;margin-bottom:24px}
.tile{background:var(--card);border:1px solid var(--border);
  border-radius:8px;padding:14px 16px}
.tile .label{color:var(--mut);font-size:11px;text-transform:uppercase;
  letter-spacing:.5px;margin-bottom:6px}
.tile .value{font-size:24px;font-weight:600;color:var(--fg)}
.tile .delta{font-size:11px;color:var(--mut);margin-top:2px}
.tile.crit .value{color:var(--crit)}
.tile.high .value{color:var(--high)}
.tile.notice .value{color:var(--notice)}

.row{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--border);
  border-radius:8px;padding:16px;overflow:hidden}
.card h2{margin:0 0 12px 0;font-size:13px;font-weight:600;
  color:var(--mut);text-transform:uppercase;letter-spacing:.5px}
.card h2 .count{color:var(--fg);background:var(--card2);padding:2px 8px;
  border-radius:10px;margin-left:8px;font-size:11px}

table{width:100%;border-collapse:collapse;font-size:13px}
table th{text-align:left;padding:8px 10px;color:var(--mut);font-weight:500;
  text-transform:uppercase;font-size:10px;letter-spacing:.5px;
  border-bottom:1px solid var(--border)}
table td{padding:8px 10px;border-bottom:1px solid var(--border);
  vertical-align:top}
table tr:last-child td{border-bottom:none}
table tr:hover td{background:var(--table-row-hover)}
.code{font-family:SF Mono,Menlo,Monaco,Consolas,monospace;
  font-size:12px;background:var(--card2);padding:2px 6px;border-radius:3px;
  color:var(--info)}

.sev{display:inline-block;padding:2px 8px;border-radius:3px;
  font-size:10px;font-weight:600;text-transform:uppercase;
  letter-spacing:.5px;font-family:SF Mono,Menlo,monospace}
.sev-critical{background:#f8514922;color:var(--crit);border:1px solid #f8514944}
.sev-high{background:#ff8c4222;color:var(--high);border:1px solid #ff8c4244}
.sev-warn{background:#d2992222;color:var(--warn);border:1px solid #d2992244}
.sev-notice{background:#3fb95022;color:var(--notice);border:1px solid #3fb95044}
.sev-info{background:#79c0ff22;color:var(--info);border:1px solid #79c0ff44}

.layout{display:grid;grid-template-columns:240px 1fr;gap:16px}
.sidebar{background:var(--card);border:1px solid var(--border);
  border-radius:8px;padding:16px;height:fit-content;position:sticky;top:80px}
.sidebar h3{margin:0 0 8px 0;font-size:11px;color:var(--mut);
  text-transform:uppercase;letter-spacing:.5px}
.sidebar ul{list-style:none;padding:0;margin:0 0 16px 0}
.sidebar li{padding:4px 0;color:var(--fg);font-size:12px;
  display:flex;justify-content:space-between}
.sidebar li a{color:var(--fg)}
.sidebar li .num{color:var(--mut);font-family:SF Mono,monospace}

.btn{display:inline-block;padding:6px 12px;background:var(--card2);
  color:var(--fg);border:1px solid var(--border);border-radius:6px;
  font-size:12px;cursor:pointer;text-decoration:none}
.btn:hover{background:var(--accent-soft);border-color:var(--accent);
  text-decoration:none}
.btn.danger{background:#f8514922;border-color:#f8514944;color:var(--crit)}
.btn.danger:hover{background:#f8514944}
.btn.success{background:#3fb95022;border-color:#3fb95044;color:var(--notice)}

input[type=text],input[type=search],select{
  background:var(--card2);border:1px solid var(--border);border-radius:6px;
  padding:6px 10px;color:var(--fg);font-size:12px;font-family:inherit}
input[type=text]:focus,input[type=search]:focus,select:focus{
  outline:none;border-color:var(--accent)}

.tags{font-family:SF Mono,Menlo,monospace;font-size:11px;color:var(--mut);
  white-space:pre-wrap;word-break:break-all;max-width:600px;
  background:var(--card2);padding:6px 10px;border-radius:4px;margin-top:6px}

.muted{color:var(--mut)}
.success-text{color:var(--notice)}
.crit-text{color:var(--crit)}
.row-2col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.spacer{height:16px}
.kbd{font-family:SF Mono,monospace;font-size:11px;background:var(--card2);
  padding:1px 5px;border-radius:3px;border:1px solid var(--border)}
.timeline{position:relative;padding-left:20px;margin:0}
.timeline::before{content:"";position:absolute;left:5px;top:0;bottom:0;
  width:1px;background:var(--border)}
.timeline li{list-style:none;position:relative;margin-bottom:12px}
.timeline li::before{content:"";position:absolute;left:-19px;top:5px;
  width:8px;height:8px;border-radius:50%;background:var(--accent);
  box-shadow:0 0 0 3px var(--bg)}
.empty{text-align:center;color:var(--mut);padding:40px 20px;font-style:italic}
`

// pageHeader/Footer wrap each page so we don't have name collisions
// across "body" templates.
const pageHeader = `
{{define "header"}}<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8">
<title>{{.Title}} · xhelix</title>
<link rel="stylesheet" href="/ui/css">
<meta name="viewport" content="width=device-width, initial-scale=1">
</head><body>
<header>
  <h1>xhelix<span class="tag">v0.0.5</span></h1>
  <nav class="tabs">
    <a href="/ui" class="{{if eq .Active "dashboard"}}active{{end}}">Dashboard</a>
    <a href="/ui/alerts" class="{{if eq .Active "alerts"}}active{{end}}">Alerts</a>
    <a href="/ui/sessions" class="{{if eq .Active "sessions"}}active{{end}}">Sessions</a>
    <a href="/ui/bans" class="{{if eq .Active "bans"}}active{{end}}">Bans</a>
    <a href="/ui/rules" class="{{if eq .Active "rules"}}active{{end}}">Rules</a>
    <a href="/ui/doctor" class="{{if eq .Active "doctor"}}active{{end}}">Doctor</a>
  </nav>
  <div class="right">
    <span class="live">live</span>
  </div>
</header>
<main>{{end}}

{{define "footer"}}</main>
<script>
// Live updates via SSE — degrades gracefully when JS is off.
if (typeof EventSource !== "undefined") {
  const es = new EventSource("/ui/sse");
  es.addEventListener("alert", e => {
    // Refresh stats on every alert; debounce to once per 2s.
    if (window.__xhelix_refresh) return;
    window.__xhelix_refresh = setTimeout(() => {
      window.__xhelix_refresh = null;
      const t = document.querySelector(".live");
      if (t) { t.style.background = "#3fb95044"; setTimeout(()=>t.style.background="",300); }
    }, 250);
  });
}
</script>
</body></html>{{end}}
`

const dashboardHTML = `
{{define "dashboard"}}{{template "header" .}}
<div class="tile-grid">
  <div class="tile"><div class="label">Events</div><div class="value">{{.Stats.EventsTotal}}</div></div>
  <div class="tile"><div class="label">Alerts</div><div class="value">{{.Stats.AlertsTotal}}</div></div>
  <div class="tile crit"><div class="label">Critical</div><div class="value">{{.Stats.AlertsCritical}}</div></div>
  <div class="tile high"><div class="label">High</div><div class="value">{{.Stats.AlertsHigh}}</div></div>
  <div class="tile notice"><div class="label">Sessions</div><div class="value">{{.Stats.SessionsActive}}</div></div>
  <div class="tile"><div class="label">Bans</div><div class="value">{{.Stats.BansActive}}</div></div>
  <div class="tile"><div class="label">Remediated</div><div class="value">{{.Stats.RemediatedTotal}}</div></div>
  <div class="tile"><div class="label">Webhooks</div><div class="value">{{.Stats.WebhookDelivered}}</div></div>
</div>

<div class="row">
  <div class="card">
    <h2>Recent Alerts <span class="count">{{len .Alerts}}</span></h2>
    {{if .Alerts}}
    <table>
      <thead><tr><th>When</th><th>Severity</th><th>Rule</th><th>Comm</th><th>Tags</th></tr></thead>
      <tbody>
      {{range .Alerts}}
      <tr>
        <td class="muted">{{shortTime .Event.Time}}</td>
        <td><span class="sev {{sevClass .Event.Severity}}">{{.Event.Severity}}</span></td>
        <td><span class="code">{{.RuleID}}</span></td>
        <td>{{.Event.Comm}}</td>
        <td class="muted">{{truncate 60 .Reason}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<div class="empty">No alerts yet.</div>{{end}}
  </div>
  <div class="card">
    <h2>Active Sessions <span class="count">{{len .Sessions}}</span></h2>
    {{if .Sessions}}
    {{range .Sessions}}
    <div style="margin-bottom:10px;padding:8px;background:var(--card2);border-radius:4px">
      <strong>{{.User}}</strong>@{{.SrcIP}}<br>
      <span class="muted">{{.Method}} · {{shortTime .LoginAt}} · {{.Events}} events · {{.Alerts}} alerts</span>
    </div>
    {{end}}
    {{else}}<div class="empty">No active sessions.</div>{{end}}

    <h2 style="margin-top:24px">Active Bans <span class="count">{{len .Bans}}</span></h2>
    {{if .Bans}}
    {{range .Bans}}
    <div style="margin-bottom:6px;font-size:12px">
      <span class="code">{{.IP}}</span> <span class="muted">{{.Reason}}</span>
    </div>
    {{end}}
    {{else}}<div class="empty">No active bans.</div>{{end}}
  </div>
</div>
{{template "footer" .}}{{end}}
`

const alertsHTML = `
{{define "alerts"}}{{template "header" .}}
<div class="layout">
  <aside class="sidebar">
    <form method="get" action="/ui/alerts">
      <h3>Filter</h3>
      <input type="search" name="rule" placeholder="rule id" value="{{.Filter.ruleID}}" style="width:100%;margin-bottom:6px">
      <input type="search" name="comm" placeholder="comm" value="{{.Filter.comm}}" style="width:100%;margin-bottom:6px">
      <input type="search" name="src" placeholder="src ip" value="{{.Filter.srcIP}}" style="width:100%;margin-bottom:6px">
      <select name="severity" style="width:100%;margin-bottom:6px">
        <option value="">all severities</option>
        <option value="critical" {{if eq .Filter.severity "critical"}}selected{{end}}>critical</option>
        <option value="high" {{if eq .Filter.severity "high"}}selected{{end}}>high</option>
        <option value="warn" {{if eq .Filter.severity "warn"}}selected{{end}}>warn</option>
        <option value="notice" {{if eq .Filter.severity "notice"}}selected{{end}}>notice</option>
      </select>
      <button class="btn" type="submit">Apply</button>
      <a href="/ui/alerts" class="btn">Clear</a>
    </form>

    <h3 style="margin-top:24px">Top rules</h3>
    <ul>
    {{range .Rules}}
      <li><a href="/ui/alerts?rule={{.Name}}">{{.Name}}</a><span class="num">{{.Count}}</span></li>
    {{end}}
    </ul>

    <h3 style="margin-top:16px">By severity</h3>
    <ul>
    {{range $k, $v := .Sevs}}
      <li><a href="/ui/alerts?severity={{$k}}">{{$k}}</a><span class="num">{{$v}}</span></li>
    {{end}}
    </ul>
  </aside>

  <div>
    <div class="card">
      <h2>Alerts <span class="count">{{len .Alerts}}</span></h2>
      {{if .Alerts}}
      <table>
        <thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Sensor</th><th>Comm</th><th>PID</th><th>Reason</th></tr></thead>
        <tbody>
        {{range .Alerts}}
        <tr>
          <td class="muted">{{shortTime .Event.Time}}</td>
          <td><span class="sev {{sevClass .Event.Severity}}">{{.Event.Severity}}</span></td>
          <td><span class="code">{{.RuleID}}</span></td>
          <td class="muted">{{.Event.Sensor}}</td>
          <td>{{.Event.Comm}}</td>
          <td class="muted">{{.Event.PID}}</td>
          <td>{{truncate 80 .Reason}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      {{else}}<div class="empty">No alerts match.</div>{{end}}
    </div>
  </div>
</div>
{{template "footer" .}}{{end}}
`

const sessionsHTML = `
{{define "sessions"}}{{template "header" .}}
<div class="card">
  <h2>Sessions <span class="count">{{len .Sessions}}</span></h2>
  {{if .Sessions}}
    {{range .Sessions}}
    <div style="margin-bottom:24px;padding:16px;background:var(--card2);border-radius:6px;border:1px solid var(--border)">
      <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:12px">
        <div>
          <strong style="font-size:16px">{{.User}}</strong> <span class="muted">@</span> <span class="code">{{.SrcIP}}</span>
          {{if .Active}}<span class="sev sev-notice" style="margin-left:8px">active</span>
          {{else}}<span class="sev sev-info" style="margin-left:8px">closed</span>{{end}}
        </div>
        <div class="muted" style="font-size:12px">
          {{.Method}} · login {{shortTime .LoginAt}}
          {{if not .Active}} · logout {{shortTime .LogoutAt}}{{end}}
        </div>
      </div>
      <div style="display:flex;gap:24px;margin-bottom:12px;font-size:12px">
        <div><span class="muted">events:</span> <strong>{{.Events}}</strong></div>
        <div><span class="muted">commands:</span> <strong>{{len .Commands}}</strong></div>
        <div><span class="muted">alerts:</span> <strong>{{.Alerts}}</strong></div>
        <div><span class="muted">id:</span> <span class="code">{{.ID}}</span></div>
      </div>
      {{if .Commands}}
      <details>
        <summary style="cursor:pointer;color:var(--accent);font-size:12px">show command timeline ({{len .Commands}} entries)</summary>
        <ul class="timeline" style="margin-top:12px">
          {{range .Commands}}
          <li><span class="code">{{truncate 200 .}}</span></li>
          {{end}}
        </ul>
      </details>
      {{end}}
    </div>
    {{end}}
  {{else}}<div class="empty">No sessions yet.</div>{{end}}
</div>
{{template "footer" .}}{{end}}
`

const bansHTML = `
{{define "bans"}}{{template "header" .}}
<div class="card">
  <h2>Banned IPs <span class="count">{{len .Bans}}</span></h2>
  {{if .Bans}}
  <table>
    <thead><tr><th>IP</th><th>Reason</th><th>Banned at</th><th>Expires</th><th>Actions</th></tr></thead>
    <tbody>
    {{range .Bans}}
    <tr>
      <td><span class="code">{{.IP}}</span></td>
      <td>{{.Reason}}</td>
      <td class="muted">{{shortTime .AddedAt}}</td>
      <td class="muted">{{shortTime .Expires}}</td>
      <td>
        <button class="btn" data-ip="{{.IP}}" onclick="(function(b){fetch('/api/xdp/undrop',{method:'POST',body:JSON.stringify({ip:b.dataset.ip})}).then(()=>location.reload())})(this)">Unban</button>
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}<div class="empty">No active bans.</div>{{end}}
</div>
{{template "footer" .}}{{end}}
`

const rulesHTML = `
{{define "rules"}}{{template "header" .}}
<div class="card">
  <h2>Rules <span class="count">{{len .Rules}}</span></h2>
  <p class="muted" style="font-size:12px;margin-bottom:16px">
    Rules in <strong>detect</strong> mode log + alert. Promotion to <strong>quarantine</strong> requires
    30 days of zero false positives — auto-quarantine on a noisy rule causes outages, so the gate stays.
    Mark a fire as a false positive to reset the counter; promote when the badge shows <span class="success-text">promotable</span>.
  </p>
  <table>
    <thead><tr><th>ID</th><th>Severity</th><th>Mode</th><th>Fires</th><th>FPs</th><th>Clean days</th><th>Status</th></tr></thead>
    <tbody>
    {{range .Rules}}
    <tr>
      <td><span class="code">{{.ID}}</span></td>
      <td><span class="sev {{sevClass .Severity}}">{{.Severity}}</span></td>
      <td>{{.Mode}}</td>
      <td>{{.FireCount}}</td>
      <td>{{.FPCount}}</td>
      <td>{{.ConsecutiveCleanDays}}</td>
      <td>
        {{if .Promotable}}<span class="sev sev-notice">promotable</span>
        {{else if .Muted}}<span class="sev sev-warn">muted</span>
        {{else}}<span class="muted">soaking</span>{{end}}
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>

<div class="card" style="margin-top:16px">
  <h2>False Positive Strategy</h2>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;font-size:13px">
    <div>
      <h3 style="font-size:12px;color:var(--accent);margin:0 0 8px 0">Built-in zero-FP signals</h3>
      <ul>
        <li><strong>Decoys.</strong> Honey files / services / canary tokens have no legitimate access path.</li>
        <li><strong>Hash-pinned threat intel.</strong> Spamhaus DROP / Tor relay sets are curated.</li>
        <li><strong>LSM-denied actions.</strong> AppArmor/SELinux already blocked them.</li>
      </ul>
    </div>
    <div>
      <h3 style="font-size:12px;color:var(--accent);margin:0 0 8px 0">FP suppression mechanisms</h3>
      <ul>
        <li><strong>30-day soak gate</strong> before any rule auto-quarantines.</li>
        <li><strong>Per-rule mute</strong> for known-noisy environments.</li>
        <li><strong>Allow-lists</strong> for JIT processes (mprotect-RWX), legitimate scanners, etc.</li>
        <li><strong>Correlation rules</strong> require N events — single noisy event won't fire.</li>
      </ul>
    </div>
  </div>
</div>
{{template "footer" .}}{{end}}
`

const entTemplates = pageHeader + dashboardHTML + alertsHTML + sessionsHTML + bansHTML + rulesHTML + doctorHTML

const doctorHTML = `
{{define "doctor"}}{{template "header" .}}
<div class="card">
  <h2>Doctor — Security Audit
    <span class="count">score {{.Report.Score.Composite}}/100</span>
  </h2>
  <p class="muted" style="font-size:12px;margin-bottom:12px">
    Last scan: {{.AgeStr}} ago.
    <a href="/ui/doctor?refresh=1" class="btn">Re-scan</a>
    <a href="/ui/doctor?fmt=json" class="btn" style="margin-left:6px">JSON</a>
    <a href="/ui/doctor?fmt=html" class="btn" style="margin-left:6px">Download HTML</a>
  </p>
  <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:16px">
    <div class="tile"><div class="t-num success-text">{{.Report.Score.Passed}}</div><div class="t-lab">PASS</div></div>
    <div class="tile"><div class="t-num warn-text">{{.Report.Score.Warned}}</div><div class="t-lab">WARN</div></div>
    <div class="tile"><div class="t-num crit-text">{{.Report.Score.Failed}}</div><div class="t-lab">FAIL</div></div>
    <div class="tile"><div class="t-num">{{.Report.Score.Skipped}}</div><div class="t-lab">SKIP</div></div>
    <div class="tile"><div class="t-num">{{.Report.Score.Errored}}</div><div class="t-lab">ERROR</div></div>
  </div>
  <p class="muted" style="font-size:12px">
    Failed by severity:
    <span class="sev sev-crit">CRIT {{.Report.FailedCritical}}</span>
    <span class="sev sev-high">HIGH {{.Report.FailedHigh}}</span>
    <span class="sev sev-warn">MED {{.Report.FailedMedium}}</span>
    <span class="sev sev-notice">LOW {{.Report.FailedLow}}</span>
  </p>
</div>

{{if .Failed}}
<div class="card" style="margin-top:16px">
  <h2>Findings <span class="count">{{len .Failed}}</span></h2>
  <p class="muted" style="font-size:12px;margin-bottom:8px">
    Apply fixes via the CLI: <code>sudo xhelix doctor --apply</code> (interactive)
    or <code>sudo xhelix doctor --apply --yes</code> (auto-apply non-risky fixes).
  </p>
  <table>
    <thead><tr><th>Sev</th><th>ID</th><th>Title</th><th>Status</th><th>Found</th></tr></thead>
    <tbody>
    {{range .Failed}}
    <tr>
      <td><span class="sev sev-{{.Check.Severity}}">{{.Check.Severity}}</span></td>
      <td><span class="code">{{.Check.ID}}</span></td>
      <td>{{.Check.Title}}</td>
      <td>{{.Result.Status}}</td>
      <td><code style="font-size:11px">{{.Result.Evidence}}</code></td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{else}}
<div class="card" style="margin-top:16px">
  <h2 class="success-text">All checks passed</h2>
  <p class="muted">Nothing to do — re-scan periodically.</p>
</div>
{{end}}
{{template "footer" .}}{{end}}
`

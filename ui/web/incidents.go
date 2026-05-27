package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Phase D.2 — read-only incidents browser. Reads the on-disk
// incidentgraph.Store the daemon already maintains and serves it
// via JSON + a thin HTML view. No mutation — `xhelixctl incidents
// close` remains the operator path for state changes.

func (s *Server) handleIncidentsList(w http.ResponseWriter, r *http.Request) {
	if s.IncidentStore == nil {
		writeJSON(w, []any{})
		return
	}
	showAll := r.URL.Query().Get("all") == "1"
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var incs any
	var err error
	if showAll {
		incs, err = s.IncidentStore.LoadAll(limit)
	} else {
		incs, err = s.IncidentStore.LoadOpen()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, incs)
}

func (s *Server) handleIncidentDetail(w http.ResponseWriter, r *http.Request) {
	if s.IncidentStore == nil {
		http.Error(w, "no incident store", http.StatusServiceUnavailable)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/incidents/")
	if id == "" {
		http.Error(w, "missing incident id", http.StatusBadRequest)
		return
	}
	inc, ok, err := s.IncidentStore.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, inc)
}

func (s *Server) handleIncidentsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, incidentsHTML)
}

// incidentsHTML deliberately builds every cell with textContent /
// createElement — never innerHTML on attacker-influenced data —
// because incident fields contain external content (file paths,
// process args, IPs) and we won't trust them in the DOM.
const incidentsHTML = `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>xhelix — incidents</title>
<style>
  body{font-family:system-ui,sans-serif;margin:1.5em;background:#0f1116;color:#e6e6e6}
  h1{margin:0 0 .6em 0;font-size:1.3em}
  .controls{margin-bottom:1em;font-size:.9em}
  .controls a{color:#7eb6ff;margin-right:1em;cursor:pointer}
  table{border-collapse:collapse;width:100%;font-size:.85em}
  th,td{padding:.35em .6em;border-bottom:1px solid #2b2f3a;text-align:left;vertical-align:top}
  th{background:#1a1d27;color:#9aa3b2;font-weight:600}
  tr:hover{background:#1a1d27;cursor:pointer}
  .sev-critical{color:#ff6b6b;font-weight:600}
  .sev-high{color:#ff9d4d}
  .sev-medium{color:#ffd166}
  .sev-low{color:#7eb6ff}
  .closed{opacity:.55}
  .id{font-family:ui-monospace,monospace;font-size:.85em;color:#9aa3b2}
  .conf{font-variant-numeric:tabular-nums;text-align:right}
  .empty{padding:2em;text-align:center;color:#9aa3b2}
  details{margin-top:1em;background:#1a1d27;padding:.6em;border-radius:4px}
  summary{cursor:pointer;color:#9aa3b2;font-size:.85em}
  pre{margin:.5em 0;font-size:.8em;color:#cfd2da;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
</style>
</head><body>
<h1>incidents</h1>
<div class="controls">
  <a id="link-open">open</a><a id="link-all">all (last 200)</a>
  <span id="meta" style="color:#9aa3b2;float:right"></span>
</div>
<table id="t"><thead>
  <tr><th>id</th><th>severity</th><th>intent</th><th>conf</th>
      <th>evidence</th><th>summary</th><th>updated</th></tr>
</thead><tbody></tbody></table>
<div id="empty" class="empty" style="display:none">no incidents — quiet day</div>
<details id="detail" style="display:none">
  <summary>selected incident JSON</summary><pre id="detail-body"></pre>
</details>
<script>
let mode = 'open';

function td(text, cls) {
  const el = document.createElement('td');
  if (cls) el.className = cls;
  el.textContent = text == null ? '' : String(text);
  return el;
}

async function load() {
  const url = '/api/incidents' + (mode === 'all' ? '?all=1' : '');
  const r = await fetch(url);
  const incs = await r.json() || [];
  document.getElementById('meta').textContent = incs.length + ' ' + mode;
  const tb = document.querySelector('#t tbody');
  while (tb.firstChild) tb.removeChild(tb.firstChild);
  document.getElementById('empty').style.display = incs.length ? 'none' : 'block';
  for (const inc of incs) {
    const tr = document.createElement('tr');
    if (inc.ClosedAt || inc.Closed) tr.className = 'closed';
    const sev = (inc.Severity || '').toLowerCase();
    tr.appendChild(td(inc.ID || '', 'id'));
    tr.appendChild(td(inc.Severity || '', 'sev-' + sev));
    tr.appendChild(td(inc.Intent || ''));
    tr.appendChild(td((inc.Confidence ?? 0).toFixed(2), 'conf'));
    tr.appendChild(td(inc.Evidence ? inc.Evidence.length : 0));
    tr.appendChild(td(inc.Summary || ''));
    tr.appendChild(td(new Date(inc.UpdatedAt || inc.StartedAt).toLocaleString()));
    tr.addEventListener('click', () => showDetail(inc.ID));
    tb.appendChild(tr);
  }
}

async function showDetail(id) {
  const r = await fetch('/api/incidents/' + encodeURIComponent(id));
  if (!r.ok) return;
  const j = await r.json();
  document.getElementById('detail-body').textContent = JSON.stringify(j, null, 2);
  const d = document.getElementById('detail');
  d.style.display = 'block';
  d.open = true;
}

document.getElementById('link-open').addEventListener('click', () => { mode = 'open'; load(); });
document.getElementById('link-all').addEventListener('click',  () => { mode = 'all';  load(); });
load();
setInterval(load, 5000);
</script>
</body></html>`

package web

import (
	"fmt"
	"net/http"
)

// Phase T04.5 — read-only correlation-graph browser. The JSON data
// is already served by pkg/source's graphRouter at /api/v1/source/…;
// this page is the human-facing companion. No mutation; pure
// rendering on top of existing endpoints:
//
//   GET /api/v1/source/anchors          — list of recent anchors
//   GET /api/v1/source/{id}/graph       — NDJSON spine + groups
//   GET /api/v1/source/{id}/events/count — quick event count

func (s *Server) handleSourcesPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, sourcesHTML)
}

// sourcesHTML is DOM-only (textContent / createElement) — never
// innerHTML on attacker-influenced data. Anchor fields can hold
// process args, file paths, source IPs etc.; we won't trust them.
const sourcesHTML = `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>xhelix — sources</title>
<style>
  body{font-family:system-ui,sans-serif;margin:1.5em;background:#0f1116;color:#e6e6e6}
  h1{margin:0 0 .6em 0;font-size:1.3em}
  .controls{margin-bottom:1em;font-size:.9em;color:#9aa3b2}
  table{border-collapse:collapse;width:100%;font-size:.85em}
  th,td{padding:.35em .6em;border-bottom:1px solid #2b2f3a;text-align:left;vertical-align:top}
  th{background:#1a1d27;color:#9aa3b2;font-weight:600}
  tr:hover{background:#1a1d27;cursor:pointer}
  .id{font-family:ui-monospace,monospace;font-size:.85em;color:#9aa3b2}
  .empty{padding:2em;text-align:center;color:#9aa3b2}
  details{margin-top:1em;background:#1a1d27;padding:.6em;border-radius:4px}
  summary{cursor:pointer;color:#9aa3b2;font-size:.85em}
  pre{margin:.5em 0;font-size:.8em;color:#cfd2da;overflow-x:auto;white-space:pre-wrap;word-break:break-word;max-height:60vh}
  .kind{display:inline-block;padding:.05em .5em;border-radius:3px;font-size:.75em;background:#2b2f3a;color:#9aa3b2}
</style>
</head><body>
<h1>sources <span style="color:#9aa3b2;font-size:.75em">(correlation graph)</span></h1>
<div class="controls">
  most-recent <input id="limit" type="number" value="50" min="1" max="500" style="width:5em">
  anchors  <button id="reload">reload</button>
  <span id="meta" style="float:right"></span>
</div>
<table id="t"><thead>
  <tr><th>id</th><th>kind</th><th>created</th><th>image</th><th>summary</th></tr>
</thead><tbody></tbody></table>
<div id="empty" class="empty" style="display:none">no anchors yet</div>
<details id="detail" style="display:none">
  <summary>selected anchor graph (NDJSON)</summary>
  <pre id="detail-body"></pre>
</details>
<script>
function td(text, cls) {
  const el = document.createElement('td');
  if (cls) el.className = cls;
  el.textContent = text == null ? '' : String(text);
  return el;
}
function span(text, cls) {
  const el = document.createElement('span');
  if (cls) el.className = cls;
  el.textContent = text == null ? '' : String(text);
  return el;
}

async function load() {
  const lim = document.getElementById('limit').value || 50;
  const r = await fetch('/api/v1/source/anchors?limit=' + encodeURIComponent(lim));
  const anchors = r.ok ? await r.json() : [];
  document.getElementById('meta').textContent = (anchors?.length ?? 0) + ' anchors';
  const tb = document.querySelector('#t tbody');
  while (tb.firstChild) tb.removeChild(tb.firstChild);
  document.getElementById('empty').style.display = (anchors?.length ?? 0) ? 'none' : 'block';
  for (const a of anchors || []) {
    const tr = document.createElement('tr');
    tr.appendChild(td(a.ID ?? a.id ?? '', 'id'));
    const kindCell = document.createElement('td');
    kindCell.appendChild(span(a.Kind ?? a.kind ?? '', 'kind'));
    tr.appendChild(kindCell);
    const created = a.CreatedAt ?? a.created_at ?? a.CreatedNs ?? a.created_ns;
    tr.appendChild(td(created ? new Date(created).toLocaleString() : ''));
    tr.appendChild(td(a.Image ?? a.image ?? ''));
    tr.appendChild(td(a.Summary ?? a.summary ?? a.Origin ?? ''));
    tr.addEventListener('click', () => showGraph(a.ID ?? a.id));
    tb.appendChild(tr);
  }
}

async function showGraph(id) {
  const r = await fetch('/api/v1/source/' + encodeURIComponent(id) + '/graph?window=1h');
  const txt = r.ok ? await r.text() : ('error ' + r.status);
  document.getElementById('detail-body').textContent = txt;
  const d = document.getElementById('detail');
  d.style.display = 'block';
  d.open = true;
}

document.getElementById('reload').addEventListener('click', load);
load();
</script>
</body></html>`

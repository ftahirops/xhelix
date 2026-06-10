package web

// Maintenance chains UI — Phase 2 of the behavioral compiler.
//
// Operator flow:
//   GET  /maintenance          → HTML page
//   GET  /api/maintenance/list → []Grant JSON (all grants, newest first)
//   POST /api/maintenance/create → mint + store a new grant
//   POST /api/maintenance/revoke → revoke by ID
//
// The provider interface keeps the web package from importing
// pkg/maintenancechain directly — same pattern as safetynet/trustzone.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// MaintenanceGrant is the wire shape the UI uses. Mirrors
// pkg/maintenancechain.Grant but kept here so the web package stays
// independent.
type MaintenanceGrant struct {
	ID          string    `json:"id"`
	AppName     string    `json:"app"`
	CgroupMatch string    `json:"cgroup_match"`
	Scope       string    `json:"scope"`
	AllowExec   []string  `json:"allow_exec,omitempty"`
	AllowWrite  []string  `json:"allow_write,omitempty"`
	Reason      string    `json:"reason"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	SignedBy    string    `json:"signed_by"`
	Remaining   string    `json:"remaining"` // human-readable, e.g. "28m"
	Expired     bool      `json:"expired"`
}

// MaintenanceCreateReq is the POST body for /api/maintenance/create.
type MaintenanceCreateReq struct {
	AppName     string   `json:"app"`
	CgroupMatch string   `json:"cgroup_match"`
	Scope       string   `json:"scope"`
	AllowExec   []string `json:"allow_exec,omitempty"`
	AllowWrite  []string `json:"allow_write,omitempty"`
	Reason      string   `json:"reason"`
	CreatedBy   string   `json:"created_by"`
	TTLMinutes  int      `json:"ttl_minutes"`
}

// MaintenanceProvider is implemented by pkg/maintenancechain.Store.
// Defined here as an interface so tests can inject fakes.
type MaintenanceProvider interface {
	ListAll() ([]MaintenanceGrant, error)
	Create(req MaintenanceCreateReq) (*MaintenanceGrant, error)
	Revoke(id string) error
}

// SetMaintenance wires the maintenance chain store into the server.
func (s *Server) SetMaintenance(p MaintenanceProvider) {
	s.mu.Lock()
	s.maintenance = p
	s.mu.Unlock()
}

// RegisterMaintenanceRoutes mounts maintenance chain routes on mux.
func (s *Server) RegisterMaintenanceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/maintenance", s.handleMaintenancePage)
	mux.HandleFunc("/api/maintenance/list", s.handleMaintenanceList)
	mux.HandleFunc("/api/maintenance/create", s.handleMaintenanceCreate)
	mux.HandleFunc("/api/maintenance/revoke", s.handleMaintenanceRevoke)
}

func (s *Server) handleMaintenancePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, maintenanceHTML)
}

func (s *Server) handleMaintenanceList(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	p := s.maintenance
	s.mu.RUnlock()
	if p == nil {
		writeJSON(w, []any{})
		return
	}
	grants, err := p.ListAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if grants == nil {
		grants = []MaintenanceGrant{}
	}
	writeJSON(w, grants)
}

func (s *Server) handleMaintenanceCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	p := s.maintenance
	s.mu.RUnlock()
	if p == nil {
		http.Error(w, "maintenance chain store not available — check daemon logs", http.StatusServiceUnavailable)
		return
	}
	var req MaintenanceCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	g, err := p.Create(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "grant": g})
}

func (s *Server) handleMaintenanceRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	p := s.maintenance
	s.mu.RUnlock()
	if p == nil {
		http.Error(w, "maintenance chain store not available", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	if err := p.Revoke(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "revoked": req.ID})
}

// maintenanceHTML is the self-contained maintenance chains page.
// All user-controlled content is set via textContent, never innerHTML.
const maintenanceHTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Maintenance Chains · xhelix</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{
  --bg:#0d1117;--card:#161b22;--card2:#1c2128;--border:#30363d;
  --fg:#e6edf3;--mut:#7d8590;--accent:#58a6ff;--accent-soft:#1f6feb33;
  --crit:#f85149;--high:#ff8c42;--warn:#d29922;--notice:#3fb950;--info:#79c0ff;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--fg);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
  font-size:14px;line-height:1.5}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}

header{background:var(--card2);border-bottom:1px solid var(--border);
  padding:0 24px;height:56px;display:flex;align-items:center;
  position:sticky;top:0;z-index:100;gap:24px}
header h1{margin:0;font-size:17px;font-weight:600;white-space:nowrap}
header h1 .tag{font-size:10px;background:var(--accent-soft);color:var(--accent);
  padding:2px 6px;border-radius:3px;margin-left:8px;font-weight:500;letter-spacing:.5px}
nav{display:flex;gap:4px;flex:1}
nav a{padding:7px 14px;border-radius:6px;color:var(--mut);font-weight:500;
  font-size:13px;text-decoration:none;transition:background .1s,color .1s}
nav a:hover,nav a.active{background:var(--card);color:var(--fg)}
.live-dot{display:inline-flex;align-items:center;gap:6px;font-size:12px;
  color:var(--mut);margin-left:auto}
.live-dot::before{content:"";width:6px;height:6px;background:var(--notice);
  border-radius:50%;animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:.4}50%{opacity:1}}

main{padding:24px;max-width:1100px}
h2{margin:0 0 16px;font-size:15px;font-weight:600}
h3{margin:0 0 12px;font-size:13px;font-weight:600;color:var(--mut);
  text-transform:uppercase;letter-spacing:.4px}

.row2{display:grid;grid-template-columns:1fr 360px;gap:20px;align-items:start}
@media(max-width:800px){.row2{grid-template-columns:1fr}}

.card{background:var(--card);border:1px solid var(--border);
  border-radius:8px;padding:16px}

table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px 10px;color:var(--mut);font-weight:500;
  font-size:10px;text-transform:uppercase;letter-spacing:.5px;
  border-bottom:1px solid var(--border)}
td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(88,166,255,.04)}

.mono{font-family:"SF Mono",Menlo,Monaco,Consolas,monospace;font-size:12px}
.chip{display:inline-block;padding:2px 8px;border-radius:10px;
  font-size:11px;font-weight:600;font-family:"SF Mono",monospace;letter-spacing:.3px}
.chip-deploy{background:#1f6feb33;color:var(--accent)}
.chip-update{background:#d2992222;color:var(--warn)}
.chip-backup{background:#3fb95022;color:var(--notice)}
.chip-custom{background:#79c0ff22;color:var(--info)}
.chip-expired{background:#30363d;color:var(--mut)}
.chip-active{background:#3fb95033;color:var(--notice)}

.ttl-bar-wrap{display:flex;align-items:center;gap:8px;min-width:120px}
.ttl-bar{flex:1;height:4px;background:var(--border);border-radius:2px;overflow:hidden}
.ttl-fill{height:100%;background:var(--notice);border-radius:2px;transition:width .3s}
.ttl-fill.low{background:var(--warn)}
.ttl-fill.crit{background:var(--crit)}

.btn{display:inline-flex;align-items:center;gap:4px;padding:5px 12px;
  background:var(--card2);color:var(--fg);border:1px solid var(--border);
  border-radius:6px;font-size:12px;cursor:pointer;font-family:inherit;
  text-decoration:none;transition:background .1s,border-color .1s}
.btn:hover{background:var(--accent-soft);border-color:var(--accent)}
.btn.danger{background:#f8514922;border-color:#f8514944;color:var(--crit)}
.btn.danger:hover{background:#f8514944}
.btn:disabled{opacity:.45;cursor:not-allowed}

label{display:block;font-size:12px;color:var(--mut);margin-bottom:4px;margin-top:12px}
label:first-child{margin-top:0}
input,select,textarea{width:100%;background:var(--card2);border:1px solid var(--border);
  border-radius:6px;padding:6px 10px;color:var(--fg);font-size:13px;
  font-family:inherit;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--accent)}
textarea{resize:vertical;min-height:54px;font-size:12px;
  font-family:"SF Mono",Menlo,monospace}
select option{background:var(--card2)}

.form-row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.form-actions{margin-top:14px;display:flex;gap:8px;align-items:center}
.msg{font-size:12px;padding:4px 0}
.msg.ok{color:var(--notice)}
.msg.err{color:var(--crit)}

.empty{text-align:center;color:var(--mut);padding:32px;font-style:italic}
.scope-hint{font-size:11px;color:var(--mut);margin-top:4px}
</style>
</head>
<body>
<header>
  <h1>xhelix<span class="tag">EDR</span></h1>
  <nav>
    <a href="/ui">Dashboard</a>
    <a href="/ui/alerts">Alerts</a>
    <a href="/ui/sessions">Sessions</a>
    <a href="/egress">Egress</a>
    <a href="/maintenance" class="active">Maintenance</a>
  </nav>
  <span class="live-dot">live</span>
</header>

<main>
<h2>Maintenance Chains</h2>
<p style="color:var(--mut);font-size:13px;margin:0 0 20px">
  Signed, time-boxed grants that temporarily lift red-zone exec/write blocks
  for declared maintenance operations (deploy, update, backup).
  Each grant is Ed25519-signed and expires automatically.
</p>

<div class="row2">
  <!-- Grant table -->
  <div class="card">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <h3 style="margin:0">Active &amp; Recent Grants</h3>
      <span id="meta" style="font-size:11px;color:var(--mut)"></span>
    </div>
    <table id="grant-table">
      <thead>
        <tr>
          <th>App / Cgroup</th>
          <th>Scope</th>
          <th>Reason</th>
          <th>Signed by</th>
          <th>Expires</th>
          <th></th>
        </tr>
      </thead>
      <tbody id="grant-body"></tbody>
    </table>
    <div id="empty" class="empty" style="display:none">No grants — all red-zone behaviors are unconditionally blocked.</div>
  </div>

  <!-- Create form -->
  <div class="card">
    <h3>New Grant</h3>

    <label>App name</label>
    <input id="f-app" type="text" placeholder="billing-api" autocomplete="off">

    <label>Cgroup match <span style="font-size:10px;color:var(--mut)">(prefix, e.g. /system.slice/php-fpm.service)</span></label>
    <input id="f-cgroup" type="text" placeholder="/system.slice/php-fpm.service" autocomplete="off">

    <label>Scope</label>
    <select id="f-scope">
      <option value="deploy">deploy — shell + rsync + git</option>
      <option value="update">update — apt / pip / npm</option>
      <option value="backup">backup — tar + gpg + mysqldump</option>
      <option value="custom">custom — specify exec/write below</option>
    </select>
    <div id="scope-hint" class="scope-hint">Default exec: /bin/sh /bin/bash /usr/bin/rsync /usr/bin/git · Default write: /srv/ /opt/ /var/www/ /app/ /home/</div>

    <div id="custom-fields" style="display:none">
      <label>Allow exec paths <span style="font-size:10px;color:var(--mut)">(one per line)</span></label>
      <textarea id="f-exec" placeholder="/usr/local/bin/my-deploy&#10;/usr/bin/git"></textarea>

      <label>Allow write prefixes <span style="font-size:10px;color:var(--mut)">(one per line)</span></label>
      <textarea id="f-write" placeholder="/srv/myapp/&#10;/tmp/"></textarea>
    </div>

    <label>Reason</label>
    <input id="f-reason" type="text" placeholder="deploying v1.4.2" autocomplete="off">

    <div class="form-row">
      <div>
        <label>Duration</label>
        <select id="f-ttl">
          <option value="15">15 minutes</option>
          <option value="30" selected>30 minutes</option>
          <option value="60">1 hour</option>
          <option value="120">2 hours</option>
          <option value="240">4 hours</option>
          <option value="480">8 hours</option>
          <option value="1440">24 hours</option>
        </select>
      </div>
      <div>
        <label>Authorized by</label>
        <input id="f-by" type="text" placeholder="you@example.com" autocomplete="off">
      </div>
    </div>

    <div class="form-actions">
      <button class="btn" id="create-btn" onclick="createGrant()">Create grant</button>
      <span id="form-msg" class="msg"></span>
    </div>
  </div>
</div>
</main>

<script>
const SCOPE_HINTS = {
  deploy: 'Default exec: /bin/sh /bin/bash /usr/bin/rsync /usr/bin/git · Default write: /srv/ /opt/ /var/www/ /app/ /home/',
  update: 'Default exec: /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/bin/pip /usr/bin/npm /usr/bin/yarn · Default write: /var/lib/dpkg/ /var/cache/apt/ /tmp/',
  backup: 'Default exec: /usr/bin/tar /usr/bin/gzip /usr/bin/gpg /usr/bin/rsync /usr/bin/mysqldump /usr/bin/pg_dump · Default write: /var/backups/ /tmp/ /mnt/',
  custom: 'Enter allowed exec paths and write prefixes below.',
};

document.getElementById('f-scope').addEventListener('change', function() {
  document.getElementById('scope-hint').textContent = SCOPE_HINTS[this.value] || '';
  document.getElementById('custom-fields').style.display = this.value === 'custom' ? 'block' : 'none';
});

function chipClass(scope) {
  return 'chip chip-' + (['deploy','update','backup'].includes(scope) ? scope : 'custom');
}

function ttlBar(g) {
  if (g.expired) return '<span class="chip chip-expired">expired</span>';
  const now = Date.now();
  const total = new Date(g.expires_at) - new Date(g.created_at);
  const left  = new Date(g.expires_at) - now;
  if (total <= 0) return '';
  const pct = Math.max(0, Math.min(100, (left / total) * 100));
  const cls = pct < 15 ? 'crit' : pct < 30 ? 'low' : '';
  const rem = g.remaining || formatRemaining(left);
  return '<div class="ttl-bar-wrap">'
    + '<div class="ttl-bar"><div class="ttl-fill ' + cls + '" style="width:' + pct.toFixed(1) + '%"></div></div>'
    + '<span class="mono" style="font-size:11px;color:var(--mut);white-space:nowrap">' + esc(rem) + '</span>'
    + '</div>';
}

function formatRemaining(ms) {
  if (ms <= 0) return 'expired';
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm';
  return Math.floor(m / 60) + 'h ' + (m % 60) + 'm';
}

function esc(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function renderExecList(arr) {
  if (!arr || !arr.length) return '<span style="color:var(--mut);font-size:11px">scope defaults</span>';
  return arr.slice(0,3).map(p => '<span class="mono" style="font-size:11px">' + esc(p) + '</span>').join('<br>')
    + (arr.length > 3 ? '<br><span style="color:var(--mut);font-size:11px">+' + (arr.length-3) + ' more</span>' : '');
}

let grants = [];

async function load() {
  try {
    const r = await fetch('/api/maintenance/list');
    if (!r.ok) return;
    grants = await r.json() || [];
    render();
  } catch(e) { /* network error — silent */ }
}

function render() {
  const tbody = document.getElementById('grant-body');
  const empty = document.getElementById('empty');
  const meta  = document.getElementById('meta');

  const active = grants.filter(g => !g.expired).length;
  meta.textContent = active + ' active, ' + grants.length + ' total';

  if (!grants.length) {
    tbody.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  // Build rows without innerHTML on user data
  const frag = document.createDocumentFragment();
  for (const g of grants) {
    const tr = document.createElement('tr');
    if (g.expired) tr.style.opacity = '0.5';

    // App / Cgroup
    const tdApp = document.createElement('td');
    const appSpan = document.createElement('div');
    appSpan.style.fontWeight = '500';
    appSpan.textContent = g.app;
    const cgroupSpan = document.createElement('div');
    cgroupSpan.className = 'mono';
    cgroupSpan.style.fontSize = '11px';
    cgroupSpan.style.color = 'var(--mut)';
    cgroupSpan.textContent = g.cgroup_match;
    tdApp.appendChild(appSpan);
    tdApp.appendChild(cgroupSpan);
    tr.appendChild(tdApp);

    // Scope
    const tdScope = document.createElement('td');
    tdScope.innerHTML = '<span class="' + chipClass(g.scope) + '">' + esc(g.scope) + '</span>';
    tr.appendChild(tdScope);

    // Reason + allowed exec
    const tdReason = document.createElement('td');
    const rDiv = document.createElement('div');
    rDiv.textContent = g.reason;
    tdReason.appendChild(rDiv);
    const execDiv = document.createElement('div');
    execDiv.innerHTML = renderExecList(g.allow_exec);
    tdReason.appendChild(execDiv);
    tr.appendChild(tdReason);

    // Signed by
    const tdSig = document.createElement('td');
    tdSig.className = 'mono';
    tdSig.style.fontSize = '11px';
    tdSig.style.color = 'var(--mut)';
    tdSig.textContent = g.signed_by || '—';
    tr.appendChild(tdSig);

    // TTL bar
    const tdTTL = document.createElement('td');
    tdTTL.innerHTML = ttlBar(g);
    tr.appendChild(tdTTL);

    // Revoke button
    const tdAct = document.createElement('td');
    if (!g.expired) {
      const btn = document.createElement('button');
      btn.className = 'btn danger';
      btn.textContent = 'Revoke';
      btn.dataset.id = g.id;
      btn.addEventListener('click', () => revokeGrant(g.id, btn));
      tdAct.appendChild(btn);
    }
    tr.appendChild(tdAct);

    frag.appendChild(tr);
  }
  tbody.textContent = '';
  tbody.appendChild(frag);
}

async function revokeGrant(id, btn) {
  btn.disabled = true;
  btn.textContent = 'Revoking…';
  try {
    const r = await fetch('/api/maintenance/revoke', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({id}),
    });
    if (!r.ok) {
      const txt = await r.text();
      alert('Revoke failed: ' + txt);
      btn.disabled = false;
      btn.textContent = 'Revoke';
      return;
    }
    await load();
  } catch(e) {
    btn.disabled = false;
    btn.textContent = 'Revoke';
  }
}

async function createGrant() {
  const btn = document.getElementById('create-btn');
  const msg = document.getElementById('form-msg');
  msg.textContent = '';
  msg.className = 'msg';

  const app      = document.getElementById('f-app').value.trim();
  const cgroup   = document.getElementById('f-cgroup').value.trim();
  const scope    = document.getElementById('f-scope').value;
  const reason   = document.getElementById('f-reason').value.trim();
  const ttl      = parseInt(document.getElementById('f-ttl').value, 10);
  const by       = document.getElementById('f-by').value.trim();

  if (!app)    { showMsg('App name is required', true); return; }
  if (!cgroup) { showMsg('Cgroup match is required', true); return; }
  if (!reason) { showMsg('Reason is required', true); return; }
  if (!by)     { showMsg('Authorized by is required', true); return; }

  const body = {app, cgroup_match: cgroup, scope, reason, created_by: by, ttl_minutes: ttl};

  if (scope === 'custom') {
    const execLines  = document.getElementById('f-exec').value.trim();
    const writeLines = document.getElementById('f-write').value.trim();
    if (execLines)  body.allow_exec  = execLines.split('\n').map(s=>s.trim()).filter(Boolean);
    if (writeLines) body.allow_write = writeLines.split('\n').map(s=>s.trim()).filter(Boolean);
  }

  btn.disabled = true;
  btn.textContent = 'Creating…';
  try {
    const r = await fetch('/api/maintenance/create', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body),
    });
    const txt = await r.text();
    if (!r.ok) {
      showMsg(txt, true);
      return;
    }
    showMsg('Grant created', false);
    // Reset form
    document.getElementById('f-app').value    = '';
    document.getElementById('f-cgroup').value = '';
    document.getElementById('f-reason').value = '';
    document.getElementById('f-by').value     = '';
    document.getElementById('f-exec').value   = '';
    document.getElementById('f-write').value  = '';
    await load();
  } catch(e) {
    showMsg('Network error: ' + e, true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create grant';
  }
}

function showMsg(text, isErr) {
  const el = document.getElementById('form-msg');
  el.textContent = text;
  el.className = 'msg ' + (isErr ? 'err' : 'ok');
  if (!isErr) setTimeout(() => { if (el.textContent === text) el.textContent = ''; }, 4000);
}

// Auto-refresh every 15s so TTL bars stay current
load();
setInterval(load, 15000);
</script>
</body></html>`

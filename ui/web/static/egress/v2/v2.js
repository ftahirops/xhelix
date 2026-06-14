// xhelix /egress/v2 — Portmaster-style three-pane network monitor.
// Left rail = app list. Center = selected app's connection feed.
// Right = selected connection metadata.

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtBytes = (n) => {
  n = Number(n) || 0;
  const u = ['B','KB','MB','GB','TB'];
  let i = 0; while (n >= 1024 && i < u.length-1) { n /= 1024; i++; }
  return (n >= 100 || i === 0 ? n.toFixed(0) : n.toFixed(1)) + ' ' + u[i];
};
const fmtNum = (n) => Number(n||0).toLocaleString();
const fmtTime = (iso) => { try { return new Date(iso).toISOString().slice(11,19); } catch { return ''; } };

async function getJSON(p) {
  try { const r = await fetch(p, {credentials:'same-origin'}); if (!r.ok) return null; return await r.json(); }
  catch { return null; }
}

const CC_NAMES = {ZZ:'Private',US:'United States',GB:'United Kingdom',DE:'Germany',FR:'France',IT:'Italy',ES:'Spain',NL:'Netherlands',FI:'Finland',SE:'Sweden',NO:'Norway',DK:'Denmark',IE:'Ireland',BE:'Belgium',CH:'Switzerland',AT:'Austria',PT:'Portugal',PL:'Poland',CZ:'Czechia',RO:'Romania',RS:'Serbia',UA:'Ukraine',RU:'Russia',TR:'Turkey',IL:'Israel',AE:'UAE',SA:'Saudi Arabia',EG:'Egypt',ZA:'South Africa',CA:'Canada',MX:'Mexico',BR:'Brazil',AR:'Argentina',CL:'Chile',CN:'China',HK:'Hong Kong',TW:'Taiwan',JP:'Japan',KR:'South Korea',VN:'Vietnam',TH:'Thailand',SG:'Singapore',MY:'Malaysia',ID:'Indonesia',PH:'Philippines',IN:'India',PK:'Pakistan',AU:'Australia',NZ:'New Zealand',LB:'Lebanon'};
const ccName = (c) => { if (!c) return ''; const u=String(c).toUpperCase(); return CC_NAMES[u] || u; };

// Category → icon + colors. SVG glyphs sized to fit small (15px) and big (32px) tiles.
const CATEGORY = {
  'web-server': { from:'#3b82f6', to:'#1e40af', svg:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>` },
  'database':   { from:'#a78bfa', to:'#6d28d9', svg:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v6a9 3 0 0 0 18 0V5"/><path d="M3 11v6a9 3 0 0 0 18 0v-6"/></svg>` },
  'ssh':        { from:'#fbbf24', to:'#b45309', svg:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>` },
  'system':     { from:'#94a3b8', to:'#334155', svg:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v6M12 17v6M4.22 4.22l4.24 4.24M15.54 15.54l4.24 4.24M1 12h6M17 12h6M4.22 19.78l4.24-4.24M15.54 8.46l4.24-4.24"/></svg>` },
  'browser':    { from:'#34d399', to:'#047857', svg:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/></svg>` },
  'container':  { from:'#22d3ee', to:'#0e7490', svg:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="6" width="18" height="12" rx="2"/><line x1="7" y1="10" x2="7" y2="14"/><line x1="11" y1="10" x2="11" y2="14"/><line x1="15" y1="10" x2="15" y2="14"/></svg>` },
  'runtime':    { from:'#fb923c', to:'#9a3412', svg:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>` },
  'user-cli':   { from:'#86efac', to:'#15803d', svg:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>` },
  'unknown':    { from:'#9ca3af', to:'#374151', svg:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>` },
};
const catOf = (c) => CATEGORY[c] || CATEGORY.unknown;

// ── State ────────────────────────────────────────────
const state = {
  apps: [],
  selected: null,         // binary string
  selectedConn: null,     // { cidr, port, ... }
  overview: null,
  search: '',
};

// ── DOM refs ─────────────────────────────────────────
const $applist  = document.getElementById('v2-applist');
const $current  = document.getElementById('v2-c-current');
const $body     = document.getElementById('v2-center-body');
const $right    = document.getElementById('v2-right');
const $rTitle   = document.getElementById('v2-r-title');
const $rBody    = document.getElementById('v2-r-body');
const $search   = document.getElementById('v2-search');

$search.addEventListener('input', () => {
  state.search = $search.value.toLowerCase();
  renderAppList();
});
document.getElementById('v2-r-close').addEventListener('click', () => {
  state.selectedConn = null;
  $right.classList.add('hidden');
});

// ── Top-level data fetch + render ───────────────────
async function loadOverview() {
  const o = await getJSON('/api/egress/overview');
  if (!o) return;
  state.overview = o;
  state.apps = o.app_cards || [];
  renderAppList();
  renderSpark();
  if (state.selected) {
    // refresh detail if a binary is selected
    renderDetail();
  } else {
    renderDashboard();
  }
}

function renderAppList() {
  const q = state.search;
  const filtered = state.apps.filter(a => !q || (a.binary||'').toLowerCase().includes(q));
  if (!filtered.length) {
    $applist.innerHTML = '<div class="v2-loading">no apps yet</div>';
    return;
  }
  $applist.innerHTML = filtered.map(a => {
    const c = catOf(a.category);
    const selected = a.binary === state.selected ? 'selected' : '';
    const aliveDot = a.alive ? '<span class="v2-app-status-dot alive"></span>' : '';
    const blockedDot = a.blocked_conns > 0 ? '<span class="v2-app-blocked" title="blocked attempts"></span>' : '';
    return `<div class="v2-app-row ${selected}" data-binary="${esc(a.binary)}" title="${esc(a.binary)}">
      ${aliveDot}
      <div class="v2-app-icon" style="--ic-from:${c.from};--ic-to:${c.to}">${c.svg}</div>
      <div class="v2-app-info">
        <div class="v2-app-name">${esc(a.binary)}</div>
        <div class="v2-app-sub">${esc(a.category)} · ${esc(a.pids||0)} PID${a.pids===1?'':'s'}</div>
      </div>
      <div class="v2-app-badge">${fmtNum(a.conns || 0)}</div>
      ${blockedDot}
    </div>`;
  }).join('');
  $applist.querySelectorAll('.v2-app-row').forEach(row => {
    row.addEventListener('click', () => selectApp(row.dataset.binary));
  });
}

// Cheap sparkline drawn on canvas — hourly bytes out from overview.
function renderSpark() {
  const canvas = document.getElementById('v2-spn-spark');
  if (!canvas || !state.overview) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const buckets = state.overview.hourly_by_class || [];
  if (!buckets.length) {
    ctx.fillStyle = '#5b6478';
    ctx.font = '10px "JetBrains Mono"';
    ctx.fillText('no data', 6, 22);
    return;
  }
  const totals = buckets.map(b => {
    let s = 0; for (const k in (b.bytes||{})) s += b.bytes[k]||0; return s;
  });
  const max = Math.max(...totals, 1);
  // gradient fill
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, 'rgba(22,209,209,0.5)');
  grad.addColorStop(1, 'rgba(22,209,209,0.02)');
  ctx.fillStyle = grad;
  ctx.strokeStyle = '#16d1d1';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(0, h);
  totals.forEach((v, i) => {
    const x = (i / Math.max(totals.length-1, 1)) * w;
    const y = h - (v / max) * (h-4);
    if (i === 0) ctx.lineTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.lineTo(w, h);
  ctx.closePath();
  ctx.fill();
  // line on top
  ctx.beginPath();
  totals.forEach((v, i) => {
    const x = (i / Math.max(totals.length-1, 1)) * w;
    const y = h - (v / max) * (h-4);
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

// ── App selection + detail ──────────────────────────

function selectApp(binary) {
  state.selected = binary;
  state.selectedConn = null;
  $right.classList.add('hidden');
  $current.textContent = binary;
  renderAppList();      // restyle row highlights
  renderDetail();
}

async function renderDetail() {
  if (!state.selected) { renderDashboard(); return; }
  const bin = state.selected;
  const a = state.apps.find(x => x.binary === bin);
  if (!a) { $body.innerHTML = '<div class="v2-conn-empty">App went idle.</div>'; return; }
  const c = catOf(a.category);
  const status = a.alive ? '<span class="v2-tag alive">● Active</span>' : '<span class="v2-tag idle">○ Idle</span>';
  const dirTag = `<span class="v2-tag dir-${esc(a.direction||'unknown')}">${esc(a.direction||'unknown')}</span>`;
  const blockedTag = a.blocked_conns > 0 ? `<span class="v2-tag blocked">⛌ ${esc(a.blocked_conns)} blocked</span>` : '';

  $body.innerHTML = `
    <div class="v2-detail-head">
      <div class="v2-detail-icon" style="--ic-from:${c.from};--ic-to:${c.to}">${c.svg}</div>
      <div class="v2-detail-meta">
        <div class="v2-detail-name">${esc(a.binary)}</div>
        <div class="v2-detail-subtitle">${esc(a.category)} · ${esc(a.pids||0)} live PID${a.pids===1?'':'s'}${a.unit?' · '+esc(a.unit):''}</div>
        <div class="v2-detail-tags">${status} ${dirTag} ${blockedTag}</div>
      </div>
    </div>

    <div class="v2-detail-kpis">
      <div class="v2-dkpi"><div class="v2-dkpi-label">Sent (1h)</div><div class="v2-dkpi-value up">${fmtBytes(a.bytes_out)}</div></div>
      <div class="v2-dkpi"><div class="v2-dkpi-label">Received (1h)</div><div class="v2-dkpi-value down">${fmtBytes(a.bytes_in)}</div></div>
      <div class="v2-dkpi"><div class="v2-dkpi-label">Connections</div><div class="v2-dkpi-value">${fmtNum(a.conns)}</div></div>
      <div class="v2-dkpi"><div class="v2-dkpi-label">Countries</div><div class="v2-dkpi-value">${(a.countries||[]).length}</div></div>
      <div class="v2-dkpi"><div class="v2-dkpi-label">Blocked</div><div class="v2-dkpi-value">${fmtNum(a.blocked_conns||0)}</div></div>
    </div>

    <div class="v2-feed-head">
      <h3>Connection history</h3>
      <div class="meta" id="v2-feed-meta">loading…</div>
    </div>
    <div id="v2-conn-list" class="v2-conn-list"><div class="v2-conn-empty">Loading connection feed…</div></div>
  `;

  // Fetch live flow rows for this binary.
  const rows = await getJSON(`/api/egress/live?binary=${encodeURIComponent(bin)}`) || [];
  const meta = document.getElementById('v2-feed-meta');
  const list = document.getElementById('v2-conn-list');
  if (!rows.length) {
    list.innerHTML = '<div class="v2-conn-empty">No recent connections for this app.</div>';
    meta.textContent = '0 flows';
    return;
  }
  // sort: newest last_seen first
  rows.sort((a,b) => new Date(b.Metrics.LastSeen) - new Date(a.Metrics.LastSeen));
  meta.textContent = `${rows.length} flow${rows.length===1?'':'s'} · last hour`;
  // We need per-flow geoip — overview doesn't carry it for live rows, but
  // app_cards.countries was aggregated. For accurate per-row CC, ipinfo
  // endpoint would be needed. Cheap: look up via cached map from app_cards.
  list.innerHTML = rows.slice(0, 80).map(r => {
    const k = r.Key, m = r.Metrics;
    const cc = '';   // populated on row click via /api/egress/ipinfo
    const dirCls = (k.Role === 'server') ? 'in' : 'out';
    const dirArrow = (k.Role === 'server')
      ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="6 9 12 15 18 9"/></svg>'
      : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="18 15 12 9 6 15"/></svg>';
    const verdict = m.DenyEvents > 0 ? 'block' : '';
    const name = k.SNI || k.DNSName || '';
    return `<div class="v2-conn-row" data-cidr="${esc(k.DestCIDR)}" data-port="${esc(k.DestPort)}">
      <div class="v2-conn-dir ${dirCls}">${dirArrow}</div>
      <div class="v2-conn-when">${esc(fmtTime(m.LastSeen))}</div>
      <div class="v2-conn-dest" title="${esc(k.DestCIDR)}">
        ${name ? `<div class="v2-conn-name">${esc(name)}</div>` : `<div class="v2-conn-name v2-dim">${esc('(no SNI/DNS)')}</div>`}
        <div class="v2-conn-ip">${esc(k.DestCIDR)}</div>
      </div>
      <div class="v2-conn-port">:${esc(k.DestPort)}</div>
      <div class="v2-conn-cc" title="${esc(k.DestClass||'')}">${esc(k.DestClass||'?').slice(0,8)}</div>
      <div class="v2-conn-bytes">↑${fmtBytes(m.BytesOut)} ↓${fmtBytes(m.BytesIn)}</div>
      <div class="v2-conn-verdict ${verdict}"></div>
    </div>`;
  }).join('');
  list.querySelectorAll('.v2-conn-row').forEach(r => {
    r.addEventListener('click', () => selectConn(r.dataset.cidr, r.dataset.port, bin));
  });
}

// ── Connection detail (right pane) ──────────────────

async function selectConn(cidr, port, binary) {
  if (!cidr) return;
  state.selectedConn = { cidr, port, binary };
  $right.classList.remove('hidden');
  const ip = (cidr || '').split('/')[0];
  $rTitle.textContent = ip;
  $rBody.innerHTML = '<div class="v2-loading">loading IP intel…</div>';
  const info = await getJSON(`/api/egress/ipinfo?ip=${encodeURIComponent(ip)}`);
  if (!info) { $rBody.innerHTML = '<div class="v2-loading">no intel available</div>'; return; }
  const cc = info.country || '';
  const susp = info.suspicion ? info.suspicion.score : null;
  const verdict = info.suspicion ? info.suspicion.verdict : '';
  const verdictColor = { critical:'var(--err)', suspicious:'var(--orange)', watch:'var(--warn)', normal:'var(--ok)' }[verdict] || 'var(--txt-2)';

  // Suspicion contributions — full breakdown so user never needs to leave v2.
  const contribs = (info.suspicion && (info.suspicion.contributions || info.suspicion.contributors)) || [];
  const contribHTML = contribs.map(c => `<div style="display:flex;gap:10px;align-items:baseline;padding:4px 0;border-bottom:1px solid var(--border)">
    <span style="width:42px;text-align:right;font-family:var(--mono);font-weight:700;color:${c.delta>0?'var(--err)':'var(--ok)'}">${c.delta>0?'+':''}${esc(c.delta)}</span>
    <span style="min-width:140px;font-size:12px;color:var(--txt-2)">${esc(c.condition||c.label||'?')}</span>
    <span style="flex:1;font-size:11.5px;color:var(--txt-3)">${esc(c.detail||'')}</span>
  </div>`).join('');

  // Processes touching this dest (ipinfo returns top_binaries).
  const procs = info.top_binaries || info.processes || info.binaries || [];
  const procHTML = procs.slice(0,10).map(p => {
    const bin = p.binary || p.label || '?';
    return `<div style="display:flex;justify-content:space-between;padding:5px 8px;font-size:12px;cursor:pointer;border-radius:5px;align-items:center" data-bin="${esc(bin)}"
      onmouseover="this.style.background='var(--hover)'" onmouseout="this.style.background=''">
      <span class="v2-mono" style="color:var(--accent-2)">${esc(bin)}</span>
      <span class="v2-mono v2-dim">${fmtBytes(p.bytes_out || p.bytes || 0)}${p.connects?` · ${esc(p.connects)} conn`:''}</span>
    </div>`;
  }).join('');

  // Hourly sparkline (last 24h of bytes-out).
  const hourly = info.hourly_bytes_out || [];
  const tlPoints = hourly.slice(-24);
  const maxT = Math.max(...tlPoints, 1);
  const sparkHTML = tlPoints.length ? `<div style="display:flex;gap:1px;height:42px;align-items:flex-end;padding:4px 0">
    ${tlPoints.map(v => {
      const h = (v / maxT * 38).toFixed(0);
      return `<div style="flex:1;background:linear-gradient(180deg,var(--accent-2),var(--accent));min-width:2px;border-radius:2px;height:${Math.max(2,h)}px;opacity:${v>0?0.85:0.15}" title="${fmtBytes(v)}"></div>`;
    }).join('')}
  </div>
  <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--txt-3);margin-top:2px;font-family:var(--mono)">
    <span>24h ago</span><span>now</span>
  </div>` : '';

  // Stats summary.
  const statsHTML = `<dl class="v2-r-kv">
    <dt>Total out</dt><dd class="v2-mono">${fmtBytes(info.total_bytes_out||0)}</dd>
    <dt>Total in</dt><dd class="v2-mono">${fmtBytes(info.total_bytes_in||0)}</dd>
    <dt>Connects</dt><dd class="v2-mono">${fmtNum(info.total_connects||0)}</dd>
    <dt>Distinct apps</dt><dd class="v2-mono">${fmtNum(info.distinct_binaries||0)}</dd>
  </dl>`;

  $rBody.innerHTML = `
    <div class="v2-r-section">
      <h4>Destination</h4>
      <dl class="v2-r-kv">
        <dt>IP</dt><dd class="v2-mono">${esc(ip)}</dd>
        <dt>Port</dt><dd class="v2-mono">${esc(port)}</dd>
        <dt>Country</dt><dd>${cc?`<span class="v2-cc">${esc(cc)}</span> ${esc(ccName(cc))}`:'<span class="v2-dim">unknown</span>'}</dd>
        <dt>ASN</dt><dd>${esc(info.asn||'?')} ${esc(info.org||'')}</dd>
        <dt>rDNS</dt><dd class="v2-mono">${esc(info.reverse_dns||'—')}</dd>
        <dt>Class</dt><dd>${esc(info.class||'?')}</dd>
        ${info.first_seen?`<dt>First seen</dt><dd class="v2-mono">${esc(new Date(info.first_seen).toISOString().slice(0,19).replace('T',' '))}</dd>`:''}
        ${info.last_seen?`<dt>Last seen</dt><dd class="v2-mono">${esc(new Date(info.last_seen).toISOString().slice(0,19).replace('T',' '))}</dd>`:''}
      </dl>
    </div>

    ${susp !== null ? `<div class="v2-r-section">
      <h4>Suspicion score</h4>
      <div style="display:flex;align-items:center;gap:14px;padding:8px;background:var(--bg);border-radius:8px;border:1px solid var(--border)">
        <div style="font-size:36px;font-weight:800;color:${verdictColor};font-family:var(--mono);line-height:1">${esc(susp)}</div>
        <div>
          <div style="text-transform:uppercase;letter-spacing:0.8px;font-size:10px;color:var(--txt-3);font-weight:700">verdict</div>
          <div style="font-size:14px;color:${verdictColor};font-weight:700;text-transform:capitalize">${esc(verdict)}</div>
        </div>
      </div>
      ${contribHTML ? `<div style="margin-top:10px">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:1.2px;color:var(--txt-3);font-weight:700;margin-bottom:6px">contributors</div>
        ${contribHTML}
      </div>` : ''}
    </div>` : ''}

    <div class="v2-r-section">
      <h4>Volume (24h)</h4>
      ${statsHTML}
    </div>

    ${sparkHTML ? `<div class="v2-r-section">
      <h4>Bytes-out timeline (hourly)</h4>
      ${sparkHTML}
    </div>` : ''}

    ${procHTML ? `<div class="v2-r-section">
      <h4>Apps touching this IP</h4>
      <div id="v2-r-procs">${procHTML}</div>
    </div>` : ''}

    <div class="v2-r-section">
      <h4>From this view</h4>
      <dl class="v2-r-kv">
        <dt>Binary</dt><dd class="v2-mono">${esc(binary)}</dd>
      </dl>
    </div>

    <div class="v2-r-section">
      <h4>Actions</h4>
      <div class="v2-r-actions">
        <button id="v2-r-block">Block IP</button>
        <button id="v2-r-allow">Allow IP</button>
      </div>
      <div style="margin-top:8px;font-size:11px;color:var(--txt-3)">
        <a href="/egress/ip/${encodeURIComponent(ip)}" target="_blank">↗ Classic IP page (new tab)</a>
        ·
        <a href="/egress/flow/${encodeURIComponent(binary)}/${encodeURIComponent(cidr)}/${encodeURIComponent(port)}" target="_blank">↗ Flow timeline</a>
      </div>
    </div>
  `;
  // Process pivot — click a binary in "Processes touching this IP" to jump to its v2 detail.
  $rBody.querySelectorAll('#v2-r-procs > div[data-bin]').forEach(el => {
    el.addEventListener('click', () => { if (el.dataset.bin) selectApp(el.dataset.bin); });
  });
  const blk = document.getElementById('v2-r-block');
  const alw = document.getElementById('v2-r-allow');
  if (blk) blk.addEventListener('click', async () => {
    if (!confirm(`Add ${ip}/32 to safety-net block list?`)) return;
    const r = await fetch('/api/egress/safety/block', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({cidr: ip+'/32', reason: 'v2 monitor: '+binary})});
    alert(r.ok ? 'blocked' : 'failed: ' + await r.text());
  });
  if (alw) alw.addEventListener('click', async () => {
    if (!confirm(`Add ${ip}/32 to safety-net always-allow list?`)) return;
    const r = await fetch('/api/egress/safety/allow', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({cidr: ip+'/32', reason: 'v2 monitor'})});
    alert(r.ok ? 'allowed' : 'failed: ' + await r.text());
  });
}

// ── Dashboard view (no app selected) ─────────────────

function renderDashboard() {
  const o = state.overview;
  if (!o) { $body.innerHTML = '<div class="v2-loading">loading…</div>'; return; }
  const ctries = o.top_countries || [];
  const asns = o.top_asns || [];
  const blocks = o.recent_blocks || [];
  const alerts = o.active_alerts || [];
  const maxC = Math.max(...ctries.map(c => c.bytes||0), 1);
  const maxA = Math.max(...asns.map(a => a.bytes||0), 1);

  $body.innerHTML = `
    <div class="v2-dash">
      <div class="v2-dash-kpis">
        <div class="v2-dkpi-card"><div class="v2-dkpi-label">Active apps</div><div class="v2-dkpi-value">${fmtNum(o.active_app_count||0)}</div></div>
        <div class="v2-dkpi-card"><div class="v2-dkpi-label">Live conns</div><div class="v2-dkpi-value">${fmtNum(o.active_conns||0)}</div></div>
        <div class="v2-dkpi-card"><div class="v2-dkpi-label">Sent (1h)</div><div class="v2-dkpi-value">${fmtBytes(o.bytes_out_1h)}</div></div>
        <div class="v2-dkpi-card"><div class="v2-dkpi-label">Recv (1h)</div><div class="v2-dkpi-value">${fmtBytes(o.bytes_in_1h)}</div></div>
        <div class="v2-dkpi-card ${(o.blocked_count_24h||0)>0?'err':''}"><div class="v2-dkpi-label">Blocked 24h</div><div class="v2-dkpi-value">${fmtNum(o.blocked_count_24h||0)}</div></div>
        <div class="v2-dkpi-card ${(o.open_alerts_count||0)>0?'warn':''}"><div class="v2-dkpi-label">Open alerts</div><div class="v2-dkpi-value">${fmtNum(o.open_alerts_count||0)}</div></div>
      </div>

      <div class="v2-two-col">
        <div class="v2-card2">
          <div class="head"><h3>Top countries</h3><div class="meta">last hour</div></div>
          ${ctries.slice(0,8).map(c => {
            const pct = ((c.bytes||0)/maxC*100).toFixed(0);
            return `<div class="v2-bar-row">
              <span class="v2-cc">${esc(c.country||'??')}</span>
              <div><div class="label">${esc(ccName(c.country)||c.country)}</div>
                <div class="sub">${esc(c.top_binary||'')}</div>
                <div class="bar"><div style="width:${pct}%"></div></div></div>
              <div class="val">${fmtBytes(c.bytes)}</div>
            </div>`;
          }).join('') || '<div class="v2-conn-empty">No country data yet.</div>'}
        </div>
        <div class="v2-card2">
          <div class="head"><h3>Top ASNs</h3><div class="meta">last hour</div></div>
          ${asns.slice(0,8).map(a => {
            const pct = ((a.bytes||0)/maxA*100).toFixed(0);
            return `<div class="v2-bar-row">
              <span class="v2-cc" style="background:transparent;color:var(--accent-2)">${esc((a.sub||'').replace(/^AS/,''))}</span>
              <div><div class="label">${esc(a.label||'unknown')}</div>
                <div class="sub">${esc(a.sub||'')}</div>
                <div class="bar"><div style="width:${pct}%"></div></div></div>
              <div class="val">${fmtBytes(a.bytes)}</div>
            </div>`;
          }).join('') || '<div class="v2-conn-empty">No ASN data yet.</div>'}
        </div>
      </div>

      <div class="v2-two-col">
        <div class="v2-card2">
          <div class="head"><h3>Recently blocked</h3><div class="meta">${blocks.length} events</div></div>
          ${blocks.slice(0,8).map(b => `<div class="v2-bar-row">
            <span class="v2-cc">${esc(b.country||'??')}</span>
            <div>
              <div class="label">${esc(b.dst_ip||'?')}${b.dst_port?':'+esc(b.dst_port):''}</div>
              <div class="sub">${esc(b.binary||'system')} · ${esc(b.reason||'')}</div>
            </div>
            <div class="val" style="color:var(--err)">${esc(b.source||'')}</div>
          </div>`).join('') || '<div class="v2-conn-empty">Nothing blocked.</div>'}
        </div>
        <div class="v2-card2">
          <div class="head"><h3>Active alerts (24h)</h3><div class="meta">${alerts.length} hits</div></div>
          ${alerts.slice(0,8).map(a => `<div class="v2-bar-row">
            <span class="v2-cc" style="background:rgba(248,113,113,0.15);color:var(--err)">cls${a.class||'?'}</span>
            <div>
              <div class="label">${esc(a.rule_id||'?')}</div>
              <div class="sub">${esc(a.binary||'')}${a.dst_ip?' → '+esc(a.dst_ip):''}</div>
            </div>
            <div class="val">${esc(fmtTime(a.time))}</div>
          </div>`).join('') || '<div class="v2-conn-empty">No active alerts.</div>'}
        </div>
      </div>
    </div>`;
}

// ── Boot ────────────────────────────────────────────
loadOverview();
setInterval(loadOverview, 15000);

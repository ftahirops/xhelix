// xhelix egress dashboard — pure vanilla JS SPA.
// No framework. No external deps. Render-on-route.
(function () {
'use strict';

// ─── helpers ───────────────────────────────────────────────────

function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n.toFixed(0) + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(2) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(2) + ' MB';
  return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

function fmtNum(n) {
  n = Number(n) || 0;
  if (n < 1000) return String(n);
  if (n < 1000000) return (n / 1000).toFixed(1) + 'k';
  return (n / 1000000).toFixed(1) + 'M';
}

function fmtTime(t) {
  const d = (typeof t === 'number') ? new Date(t * 1000) : new Date(t);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function fmtAgo(t) {
  const d = (typeof t === 'number') ? new Date(t * 1000) : new Date(t);
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s/60) + 'm ago';
  if (s < 86400) return Math.floor(s/3600) + 'h ago';
  return Math.floor(s/86400) + 'd ago';
}

// uid → username map, fetched once.
const uidNames = {};
let uidNamesLoaded = false;
async function ensureUIDNames() {
  if (uidNamesLoaded) return;
  const j = await fetchJSON('/api/egress/uid_names');
  if (j && typeof j === 'object') {
    Object.keys(j).forEach(k => { uidNames[k] = j[k]; });
  }
  uidNamesLoaded = true;
}
function uidLabel(uid) {
  if (uid === null || uid === undefined || uid === '') return '';
  const name = uidNames[String(uid)];
  return name ? (uid + ' (' + name + ')') : String(uid);
}

// Application-protocol classifier from a FlowRecord.
function protocolOf(rec) {
  const k = rec.Key || {};
  const port = k.DestPort ?? rec.dst_port ?? 0;
  const sni = k.SNI || rec.sni || '';
  const proto = (k.Protocol || rec.proto || '').toLowerCase();
  if (sni) return 'HTTPS';
  if (proto === 'tcp' || proto === '') {
    if (port === 443) return 'HTTPS';
    if (port === 80)  return 'HTTP';
    if (port === 22)  return 'SSH';
    if (port === 53)  return 'DNS';
    if (port === 25 || port === 465 || port === 587) return 'SMTP';
    if (port === 143 || port === 993) return 'IMAP';
    if (port === 110 || port === 995) return 'POP3';
    if (port === 3306) return 'MySQL';
    if (port === 5432) return 'PostgreSQL';
    if (port === 6379) return 'Redis';
    if (port === 27017) return 'MongoDB';
    if (port === 21) return 'FTP';
  }
  if (proto === 'udp') {
    if (port === 53)  return 'DNS';
    if (port === 123) return 'NTP';
    if (port === 161 || port === 162) return 'SNMP';
  }
  return 'Other';
}

const PROTO_COLOR = {
  'HTTPS':      '#60a5fa',
  'HTTP':       '#facc15',
  'SSH':        '#a78bfa',
  'DNS':        '#4ade80',
  'SMTP':       '#ee8033',
  'IMAP':       '#f87171',
  'POP3':       '#f87171',
  'MySQL':      '#22d3ee',
  'PostgreSQL': '#22d3ee',
  'Redis':      '#ec4899',
  'MongoDB':    '#22d3ee',
  'FTP':        '#94a3b8',
  'NTP':        '#94a3b8',
  'SNMP':       '#94a3b8',
  'Other':      '#6b7283',
};

function classPill(cls) {
  if (!cls) cls = 'unknown';
  return `<span class="pill cls-${esc(cls)}">${esc(cls)}</span>`;
}

function verdictPill(deny, verify) {
  if (deny) return '<span class="pill solid-err">DENY</span>';
  if (verify) return '<span class="pill solid-warn">VERIFY</span>';
  return '<span class="pill solid-ok">ALLOW</span>';
}

// ipChip renders an IP with a small country code badge after it, and
// turns the IP into a click-through to /egress/ip/<ip> (deep analysis).
// Country code is read from the per-IP cache populated by
// backfillCountries; the chip degrades gracefully when no country is
// known yet (no badge rendered).
// ISO 3166-1 alpha-2 → English country name. Limited subset; expand
// when the geoip seed adds coverage. Special values:
//   ZZ → "Private / Internal" (RFC1918 + loopback synthetic code)
//   ?? → "Unmapped (public)" (public IP not in our geoip seed)
const COUNTRY_NAMES = {
  ZZ: 'Private / Internal', '??': 'Unmapped (public)',
  US: 'United States', GB: 'United Kingdom', DE: 'Germany',
  FR: 'France', NL: 'Netherlands', CA: 'Canada', AU: 'Australia',
  JP: 'Japan', SG: 'Singapore', IE: 'Ireland', IT: 'Italy',
  ES: 'Spain', SE: 'Sweden', FI: 'Finland', NO: 'Norway', DK: 'Denmark',
  CH: 'Switzerland', AT: 'Austria', BE: 'Belgium', PT: 'Portugal',
  PL: 'Poland', CZ: 'Czechia', RO: 'Romania', GR: 'Greece',
  HU: 'Hungary', SK: 'Slovakia', SI: 'Slovenia', HR: 'Croatia',
  BG: 'Bulgaria', LT: 'Lithuania', LV: 'Latvia', EE: 'Estonia',
  IS: 'Iceland', LU: 'Luxembourg', MT: 'Malta', CY: 'Cyprus',
  RU: 'Russia', UA: 'Ukraine', BY: 'Belarus', MD: 'Moldova',
  RS: 'Serbia', BA: 'Bosnia and Herzegovina', AL: 'Albania', MK: 'North Macedonia',
  TR: 'Turkey', IL: 'Israel', AE: 'United Arab Emirates', SA: 'Saudi Arabia',
  QA: 'Qatar', KW: 'Kuwait', OM: 'Oman', BH: 'Bahrain', JO: 'Jordan',
  LB: 'Lebanon', SY: 'Syria', IQ: 'Iraq', IR: 'Iran',
  EG: 'Egypt', MA: 'Morocco', DZ: 'Algeria', TN: 'Tunisia', LY: 'Libya',
  ZA: 'South Africa', NG: 'Nigeria', KE: 'Kenya', GH: 'Ghana',
  ET: 'Ethiopia', UG: 'Uganda', TZ: 'Tanzania', SD: 'Sudan',
  CN: 'China', HK: 'Hong Kong', TW: 'Taiwan', MO: 'Macao',
  KR: 'South Korea', KP: 'North Korea', MN: 'Mongolia', VN: 'Vietnam',
  TH: 'Thailand', MY: 'Malaysia', ID: 'Indonesia', PH: 'Philippines',
  IN: 'India', PK: 'Pakistan', BD: 'Bangladesh', LK: 'Sri Lanka', NP: 'Nepal',
  AF: 'Afghanistan', MM: 'Myanmar', KH: 'Cambodia', LA: 'Laos',
  NZ: 'New Zealand', MX: 'Mexico', BR: 'Brazil', AR: 'Argentina',
  CL: 'Chile', CO: 'Colombia', PE: 'Peru', VE: 'Venezuela', EC: 'Ecuador',
  UY: 'Uruguay', PY: 'Paraguay', BO: 'Bolivia', CR: 'Costa Rica',
  PA: 'Panama', DO: 'Dominican Republic', GT: 'Guatemala', HN: 'Honduras',
  SV: 'El Salvador', NI: 'Nicaragua', CU: 'Cuba', JM: 'Jamaica',
  HT: 'Haiti', PR: 'Puerto Rico', TT: 'Trinidad and Tobago',
  KZ: 'Kazakhstan', UZ: 'Uzbekistan', KG: 'Kyrgyzstan', TJ: 'Tajikistan',
  TM: 'Turkmenistan', AZ: 'Azerbaijan', AM: 'Armenia', GE: 'Georgia',
};
function countryName(cc) {
  if (!cc) return 'Unknown';
  const up = String(cc).toUpperCase();
  if (up === '??' || cc === '??') return COUNTRY_NAMES['??'];
  return COUNTRY_NAMES[up] || up;
}
function countryLabel(cc) {
  // Friendly label combining name + ISO code: "United States (US)"
  const name = countryName(cc);
  if (!cc || cc === '??') return name;
  return name + ' (' + cc + ')';
}

const ipCountryCache = new Map();
function ipChip(ip, country) {
  if (!ip) return '<span class="dim">—</span>';
  let cc = country;
  if (cc === undefined || cc === null || cc === '') cc = ipCountryCache.get(ip) || '';
  cc = (cc || '').toUpperCase();
  const flag = cc ? `<span class="ip-cc" title="${esc(cc)}">${esc(cc)}</span>` : '';
  // Use a real path so middle-click / ctrl-click open in a new tab via
  // the browser's default <a> behavior. Left-click is intercepted by a
  // delegated handler installed in init() that calls go().
  const href = '/egress/ip/' + encodeURIComponent(ip);
  return `<a class="ip-link" href="${href}" data-ip-link="1" data-ip="${esc(ip)}" title="Click for IP deep analysis">${esc(ip)}</a>${flag}`;
}

// backfillCountries populates ipCountryCache for the supplied IPs via
// /api/egress/ipinfo. Capped at 50 per call so a busy page doesn't
// fire hundreds of lookups. The next render picks up cached values.
async function backfillCountries(ips) {
  const need = (ips || []).filter(ip => ip && !ipCountryCache.has(ip));
  if (!need.length) return;
  const slice = need.slice(0, 50);
  await Promise.all(slice.map(async ip => {
    try {
      const r = await fetch('/api/egress/ipinfo?ip=' + encodeURIComponent(ip), { cache: 'no-store' });
      if (r.ok) {
        const d = await r.json();
        ipCountryCache.set(ip, d.country || '');
      } else {
        ipCountryCache.set(ip, '');
      }
    } catch (_) { ipCountryCache.set(ip, ''); }
  }));
}

async function fetchJSON(url) {
  try {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
    return await r.json();
  } catch (e) {
    console.error('fetch', url, e);
    return null;
  }
}

// Capture-loss banner: poll /api/sensors, find the ebpf sensor, and surface
// ringbuf/consumer-full drops. This makes loss VISIBLE — it does not prevent
// it (the kernel already dropped the events before userspace saw them).
async function refreshCaptureLoss() {
  const el = document.getElementById('capture-loss-banner');
  if (!el) return;
  const sensors = await fetchJSON('/api/sensors?_=' + Date.now());
  if (!Array.isArray(sensors)) return;
  const ebpf = sensors.find(s => s && s.name === 'ebpf');
  if (!ebpf) { el.style.display = 'none'; return; }
  const r = ebpf.drop_ringbuf || 0;
  const c = ebpf.drop_consumer_full || 0;
  const d = ebpf.drop_decode || 0;
  if (r > 0 || c > 0) {
    let msg = `⚠ Capture loss: ringbuf overflow ${fmtNum(r)}, consumer-full ${fmtNum(c)} — some egress traffic may be missing from this view.`;
    if (d > 0) {
      msg += ` <span class="cl-decode">(+${fmtNum(d)} decode errors)</span>`;
    }
    el.innerHTML = msg;
    el.style.display = '';
  } else {
    el.style.display = 'none';
  }
}

function debounce(fn, ms) {
  let t = null;
  return function () {
    const args = arguments;
    clearTimeout(t);
    t = setTimeout(() => fn.apply(null, args), ms);
  };
}

// ─── state ─────────────────────────────────────────────────────

const state = {
  route: '/egress',
  hours: 6,
  paused: false,
  refreshTimer: null,
  livePage: 0,
  livePageSize: 100,
  liveSearch: '',
  liveFilter: { class: '', verdict: '' },
  drawerOpen: false,
  selectedBinary: null,
  selectedCountry: null,
  // visibility: 'public' (default — external only), 'internal'
  // (lateral/IMDS/docker only), or 'all' (no filter).
  visibility: 'public',
};

function loadPrefs() {
  try {
    const p = JSON.parse(localStorage.getItem('xhelix.egress') || '{}');
    if (p.hours) state.hours = p.hours;
    if (typeof p.livePageSize === 'number') state.livePageSize = p.livePageSize;
    if (typeof p.liveSearch === 'string') state.liveSearch = p.liveSearch;
    if (typeof p.sidebarCollapsed === 'boolean') state.sidebarCollapsed = p.sidebarCollapsed;
    if (p.visibility === 'public' || p.visibility === 'internal' || p.visibility === 'all') {
      state.visibility = p.visibility;
    }
  } catch (_) {}
}
function savePrefs() {
  try {
    localStorage.setItem('xhelix.egress', JSON.stringify({
      hours: state.hours,
      livePageSize: state.livePageSize,
      liveSearch: state.liveSearch || '',
      sidebarCollapsed: !!state.sidebarCollapsed,
      visibility: state.visibility || 'public',
    }));
  } catch (_) {}
}

// ─── public / internal visibility helpers ──────────────────────
//
// The egress dashboard separates external traffic from internal
// (docker bridge, IMDS, lateral movement) so private chatter doesn't
// drown out the things operators actually need to see. Every data-
// fetching endpoint that accepts ?visibility= consumes the current
// state.visibility through visibilityParam().

function visibilityChip() {
  const v = state.visibility || 'public';
  return `
    <div class="vis-toggle">
      <button class="vis-btn ${v === 'public' ? 'active' : ''}" data-vis="public" title="External traffic only — exclude private/loopback/link-local">Public</button>
      <button class="vis-btn ${v === 'internal' ? 'active' : ''}" data-vis="internal" title="Internal traffic only (lateral movement, IMDS, docker chatter)">Internal</button>
      <button class="vis-btn ${v === 'all' ? 'active' : ''}" data-vis="all" title="Show both">All</button>
    </div>`;
}

function bindVisibility(view) {
  if (!view) return;
  view.querySelectorAll('.vis-btn').forEach(b => {
    b.addEventListener('click', () => {
      state.visibility = b.dataset.vis;
      savePrefs();
      render();
    });
  });
}

function visibilityParam() {
  return '&visibility=' + encodeURIComponent(state.visibility || 'public');
}

// ─── router ────────────────────────────────────────────────────

const routes = {
  '/egress':                       { name: 'Overview',          render: renderOverview,    refresh: 30000 },
  '/egress/live':                  { name: 'Live activity',     render: renderLive,        refresh: 5000  },
  '/egress/process':               { name: 'Per-process',       render: renderProcess,     refresh: 10000 },
  '/egress/connections':           { name: 'Per-connection',    render: renderConnections, refresh: 5000  },
  '/egress/users':                 { name: 'Per-user (UID)',    render: renderUsers,       refresh: 15000 },
  '/egress/cgroups':               { name: 'Per-cgroup',        render: renderCgroups,     refresh: 15000 },
  '/egress/countries':             { name: 'Countries',         render: renderCountries,   refresh: 15000 },
  '/egress/internal':              { name: 'Internal Network',  render: renderInternal,    refresh: 10000 },
  '/egress/country':                { name: 'Country detail',    render: renderCountryDetail, refresh: 30000 },
  '/egress/verdict':               { name: 'Verdict',           render: renderVerdict,     refresh: 15000 },
  '/egress/pid':                   { name: 'PID forensics',     render: renderPid,         refresh: 10000 },
  '/egress/ip':                    { name: 'IP deep analysis',  render: renderIPAnalysis,  refresh: 0     },
  '/egress/flow':                  { name: 'Flow analysis',     render: renderFlowAnalysis,refresh: 5000  },
  '/egress/captures':               { name: 'Packet captures',   render: renderCaptures,    refresh: 5000  },
  '/egress/tls-plaintext':         { name: 'TLS plaintext',     render: renderTLSPlaintext, refresh: 5000 },
  '/egress/companies':             { name: 'Companies / ASNs',  render: renderCompanies,   refresh: 15000 },
  '/egress/destinations':          { name: 'Destinations',      render: renderDestinations,refresh: 15000 },
  '/egress/protocols':             { name: 'Protocols',         render: renderProtocols,   refresh: 15000 },
  '/egress/alerts':                { name: 'Alerts',            render: renderAlerts,      refresh: 0     },
  '/egress/malware':               { name: 'Malware signals',   render: renderStub,        refresh: 0     },
  '/egress/anomalies':             { name: 'Anomalies',         render: renderStub,        refresh: 0     },
  '/egress/lineage':               { name: 'Source lineage',    render: renderStub,        refresh: 0     },
  '/egress/policy/process':        { name: 'Per-process rules', render: renderPolicy,      refresh: 30000 },
  '/egress/policy/review':         { name: 'Policy review',     render: renderPolicyReview,refresh: 0     },
  '/egress/policy/user':           { name: 'Per-user rules',    render: renderStub,        refresh: 0     },
  '/egress/policy/country':        { name: 'Per-country block', render: renderStub,        refresh: 0     },
  '/egress/policy/queue':          { name: 'Sign queue',        render: renderPolicy,      refresh: 30000 },
  '/egress/safety':                { name: 'IP Safety Net',     render: renderSafety,      refresh: 10000 },
  '/egress/storage':               { name: 'Storage',           render: renderStorage,     refresh: 10000 },
  '/egress/sensors':               { name: 'Sensors',           render: renderSensors,     refresh: 10000 },
  '/egress/chain':                 { name: 'Forensic chain',    render: renderStub,        refresh: 0     },
  '/egress/settings':              { name: 'Settings',          render: renderStub,        refresh: 0     },
};

function go(path) {
  // Allow /egress/process/<binary> form.
  state.route = path;
  history.pushState({}, '', path);
  render();
}

function render() {
  // Normalise route — /egress/process/<bin>
  let key = state.route;
  if (key.startsWith('/egress/process/')) {
    state.selectedBinary = decodeURIComponent(key.substring('/egress/process/'.length));
    key = '/egress/process';
  } else if (key === '/egress/process') {
    state.selectedBinary = null;
  } else if (key.startsWith('/egress/policy/review/')) {
    // /egress/policy/review/<binary>
    state.reviewBinary = decodeURIComponent(key.substring('/egress/policy/review/'.length));
    key = '/egress/policy/review';
  } else if (key === '/egress/policy/review') {
    state.reviewBinary = state.reviewBinary || null;
  } else if (key.startsWith('/egress/pid/')) {
    state.selectedPID = decodeURIComponent(key.substring('/egress/pid/'.length));
    key = '/egress/pid';
  } else if (key.startsWith('/egress/country/')) {
    state.selectedCountry = decodeURIComponent(key.substring('/egress/country/'.length));
    key = '/egress/country';
  } else if (key.startsWith('/egress/ip/')) {
    state.selectedIP = decodeURIComponent(key.substring('/egress/ip/'.length));
    key = '/egress/ip';
  } else if (key.startsWith('/egress/flow/')) {
    const parts = key.substring('/egress/flow/'.length).split('/');
    state.selectedFlowBinary = decodeURIComponent(parts[0] || '');
    state.selectedFlowDest   = decodeURIComponent(parts[1] || '');
    state.selectedFlowPort   = decodeURIComponent(parts[2] || '');
    key = '/egress/flow';
  }
  const route = routes[key] || routes['/egress'];

  // Sidebar active state.
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.route === key);
  });

  // Breadcrumbs.
  document.getElementById('crumbs').innerHTML =
    `Egress &nbsp;<span style="color:var(--text-2)">/</span>&nbsp; <strong>${esc(route.name)}</strong>`;

  // Run refresh schedule.
  if (state.refreshTimer) clearInterval(state.refreshTimer);
  state.refreshTimer = null;

  const view = document.getElementById('view');
  Promise.resolve(route.render(view)).catch(err => {
    console.error(err);
    view.innerHTML = `<div class="placeholder"><strong>render error</strong>${esc(err.message || err)}</div>`;
  });

  // Global delegated handler: every .ip-link (anywhere in any rendered view)
  // navigates to IP intel. Idempotent because we attach to #view exactly once
  // per render and the listener short-circuits on missing data-ip.
  if (!view.__ipLinkBound) {
    view.addEventListener('click', (e) => {
      const a = e.target.closest && e.target.closest('.ip-link');
      if (!a || !a.dataset || !a.dataset.ip) return;
      e.preventDefault(); e.stopPropagation();
      go('/egress/ip/' + encodeURIComponent(a.dataset.ip));
    });
    view.__ipLinkBound = true;
  }

  if (route.refresh > 0) {
    state.refreshTimer = setInterval(() => {
      if (state.paused || document.hidden) return;
      const ind = document.getElementById('refresh-ind');
      ind.classList.add('live');
      Promise.resolve(route.render(view)).finally(() => {
        setTimeout(() => ind.classList.remove('live'), 400);
      });
    }, route.refresh);
  }
}

// ─── Overview ──────────────────────────────────────────────────

async function renderOverview(view) {
  const data = await fetchJSON('/api/egress/overview?_=1' + visibilityParam());
  if (!data) {
    view.innerHTML = `<div class="placeholder"><strong>No data</strong>egress ledger is empty or unreachable.</div>`;
    return;
  }

  // Hero KPIs.
  const heroHTML = `
    <div class="hero">
      <div class="kpi">
        <div class="kpi-label">Active connections</div>
        <div class="kpi-value">${fmtNum(data.active_conns)}</div>
        <div class="kpi-sub">${esc(data.unique_binaries_1h || 0)} binaries · last hour</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Bytes out (1h)</div>
        <div class="kpi-value">${fmtBytes(data.bytes_out_1h)}</div>
        <div class="kpi-sub">${esc(data.unique_dests_1h || 0)} distinct destinations</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Bytes in (1h)</div>
        <div class="kpi-value">${fmtBytes(data.bytes_in_1h)}</div>
        <div class="kpi-sub">${esc(data.unique_countries_1h || 0)} countries</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Ledger</div>
        <div class="kpi-value">${fmtNum(data.ledger_stats.ObserveCount || 0)}</div>
        <div class="kpi-sub">hot ${esc(data.ledger_stats.HotRows||0)} · warm ${esc(data.ledger_stats.WarmKeys||0)} · cold ${esc(data.ledger_stats.ColdDays||0)}d</div>
      </div>
    </div>`;

  // Stacked area chart by class.
  const classes = Object.keys(data.class_breakdown || {});
  const buckets = (data.hourly_by_class || []).map(p => ({ x: p.hour, parts: p.bytes || {} }));
  const seenClasses = new Set();
  buckets.forEach(b => Object.keys(b.parts).forEach(c => seenClasses.add(c)));
  classes.forEach(c => seenClasses.add(c));
  const classList = Array.from(seenClasses);
  const chartHTML = Charts.stackedArea(buckets, classList, { height: 220 });

  const legend = classList.map(c =>
    `<span><span class="sw" style="background:${Charts.colorFor(c)}"></span>${esc(c)}</span>`
  ).join('');

  // World — fallback grid view.
  const countries = await fetchJSON('/api/egress/countries?hours=' + state.hours + visibilityParam()) || [];
  const worldHTML = Charts.worldGrid(countries, { limit: 40 });

  // Top tables.
  const topBins = (data.top_binaries || []).map(r =>
    `<tr class="clickable" data-binary="${esc(r.label)}">
      <td class="mono">${esc(r.label || '?')}</td>
      <td class="num">${fmtBytes(r.bytes)}</td>
      <td class="num dim">${fmtNum(r.connects)}</td>
    </tr>`).join('') || '<tr class="empty-row"><td colspan="3">no traffic</td></tr>';

  const topDests = (data.top_destinations || []).map(r => {
    const ip = (r.label||'').split(':')[0].split('/')[0];
    return `<tr>
      <td class="mono"><a href="#" class="ip-link" data-ip="${esc(ip)}">${esc(r.label)}</a></td>
      <td>${classPill(r.class)}</td>
      <td class="num">${fmtBytes(r.bytes)}</td>
    </tr>`;
  }).join('') || '<tr class="empty-row"><td colspan="3">no traffic</td></tr>';

  const topDenied = (data.top_denied || []).map(r =>
    `<tr><td class="mono">${esc(r.label)}</td><td class="num">${fmtNum(r.denied)}</td></tr>`
  ).join('') || '<tr class="empty-row"><td colspan="2">no denies</td></tr>';

  view.innerHTML = `
    ${heroHTML}
    <div class="grid grid-2" style="margin-bottom:12px">
      <div class="card chart-card">
        <div class="card-head"><h2>Bytes-out by class — last 24h</h2><div class="right">stacked area · hourly</div></div>
        ${chartHTML}
        <div class="chart-legend">${legend}</div>
      </div>
      <div class="card chart-card">
        <div class="card-head"><h2>Destination countries</h2><div class="right">top 40 · ${esc(state.hours)}h</div></div>
        ${worldHTML}
      </div>
    </div>
    <div class="grid grid-3">
      <div class="card">
        <div class="card-head"><h2>Top binaries</h2><div class="right">by bytes-out</div></div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl"><thead><tr><th>Binary</th><th class="num">Bytes</th><th class="num">Conns</th></tr></thead>
          <tbody>${topBins}</tbody></table>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Top destinations</h2><div class="right">CIDR : port</div></div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl"><thead><tr><th>Destination</th><th>Class</th><th class="num">Bytes</th></tr></thead>
          <tbody>${topDests}</tbody></table>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Top denied flows</h2><div class="right">deny events</div></div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl"><thead><tr><th>Flow</th><th class="num">Deny</th></tr></thead>
          <tbody>${topDenied}</tbody></table>
        </div>
      </div>
    </div>`;

  // Wire top-binaries click → process page.
  view.querySelectorAll('tr.clickable[data-binary]').forEach(tr => {
    tr.addEventListener('click', () => go('/egress/process/' + encodeURIComponent(tr.dataset.binary)));
  });
  // Universal: every .ip-link → IP intel.
  view.querySelectorAll('.ip-link').forEach(a => {
    a.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); go('/egress/ip/' + encodeURIComponent(a.dataset.ip)); });
  });

  // Wire world-grid click → countries filter.
  view.querySelectorAll('.world-cell').forEach(c => {
    c.addEventListener('click', () => {
      state.selectedCountry = c.dataset.country;
      go('/egress/countries');
    });
  });

  // Week 6 — cohort outliers card (fleet calibration). Render after
  // the main overview is in place so it gracefully degrades if the
  // fleet endpoint isn't wired.
  renderCohortOutliersCard(view).catch(err => console.error('cohort card', err));
}

// ─── Live activity ────────────────────────────────────────────

async function renderLive(view) {
  // Preserve filter bar across refreshes by using a stable shell.
  if (!view.dataset.live) {
    view.dataset.live = '1';
    view.innerHTML = `
      <div class="toolbar">
        <h1>Live activity</h1>
        <div class="spacer"></div>
        ${visibilityChip()}
      </div>
      <div class="filter-bar">
        <span class="lbl">search</span>
        <input id="f-search" class="grow" type="text" placeholder="binary, SNI, DNS, dest_class, country…" />
        <span class="lbl">class</span>
        <select id="f-class">
          <option value="">all</option>
          <option>cloud_provider</option>
          <option>cdn</option>
          <option>private</option>
          <option>dev_registry</option>
          <option>os_update</option>
          <option>intel_bad</option>
          <option>unknown</option>
        </select>
        <span class="lbl">verdict</span>
        <select id="f-verdict">
          <option value="">all</option>
          <option value="deny">deny only</option>
          <option value="verify">verify only</option>
        </select>
        <span class="lbl">page size</span>
        <select id="f-page-size">
          <option>50</option><option selected>100</option><option>200</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table class="tbl" id="live-tbl">
          <thead><tr>
            <th>Time</th><th>Binary</th><th>UID</th><th>Dest IP / SNI</th>
            <th>Port</th><th>Proto</th><th>Class</th>
            <th class="num">Out</th><th class="num">In</th><th>Verdict</th>
          </tr></thead>
          <tbody id="live-rows"></tbody>
        </table>
        <div class="pager" id="live-pager"></div>
      </div>`;
    // Restore persisted search if any.
    if (state.liveSearch) view.querySelector('#f-search').value = state.liveSearch;
    view.querySelector('#f-search').addEventListener('input', debounce(e => {
      state.liveSearch = e.target.value.trim().toLowerCase();
      state.livePage = 0;
      savePrefs();
      refreshLive(view);
    }, 200));
    view.querySelector('#f-class').addEventListener('change', e => {
      state.liveFilter.class = e.target.value; state.livePage = 0; refreshLive(view);
    });
    view.querySelector('#f-verdict').addEventListener('change', e => {
      state.liveFilter.verdict = e.target.value; state.livePage = 0; refreshLive(view);
    });
    view.querySelector('#f-page-size').addEventListener('change', e => {
      state.livePageSize = parseInt(e.target.value, 10) || 100;
      state.livePage = 0; savePrefs(); refreshLive(view);
    });
  }
  bindVisibility(view);
  await refreshLive(view);
}

async function refreshLive(view) {
  await ensureUIDNames();
  let url = '/api/egress/live?_=1';
  if (state.liveFilter.verdict === 'deny') url += '&deny_only=1';
  if (state.liveFilter.class) url += '&dest_class=' + encodeURIComponent(state.liveFilter.class);
  url += visibilityParam();
  const rows = await fetchJSON(url) || [];
  let filtered = rows;
  if (state.liveSearch) {
    const q = state.liveSearch;
    filtered = rows.filter(r => {
      const k = r.Key || {};
      return (k.Binary || '').toLowerCase().includes(q) ||
             (k.SNI || '').toLowerCase().includes(q) ||
             (k.DNSName || '').toLowerCase().includes(q) ||
             (k.DestCIDR || '').toLowerCase().includes(q) ||
             (k.DestClass || '').toLowerCase().includes(q);
    });
  }
  if (state.liveFilter.verdict === 'verify') {
    filtered = filtered.filter(r => (r.Metrics||{}).VerifyEvents > 0);
  }

  const total = filtered.length;
  const sz = state.livePageSize;
  const page = Math.min(state.livePage, Math.max(0, Math.floor((total - 1) / sz)));
  state.livePage = page;
  const slice = filtered.slice(page * sz, page * sz + sz);

  const body = view.querySelector('#live-rows');
  if (!slice.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="10">no flows in selected scope</td></tr>`;
  } else {
    body.innerHTML = slice.map((r, i) => {
      const k = r.Key || {}, m = r.Metrics || {};
      return `<tr class="clickable" data-idx="${i}">
        <td class="mono dim">${fmtTime(m.LastSeen || r.Bucket)}</td>
        <td class="mono">${esc(k.Binary || '')}</td>
        <td class="mono">${esc(uidLabel(k.UID))}</td>
        <td class="mono">${esc(k.SNI || k.DNSName || k.DestCIDR || '')}</td>
        <td class="mono">${esc(k.DestPort)}</td>
        <td class="mono">${esc(k.Protocol || '')}</td>
        <td>${classPill(k.DestClass)}</td>
        <td class="num">${fmtBytes(m.BytesOut)}</td>
        <td class="num dim">${fmtBytes(m.BytesIn)}</td>
        <td>${verdictPill(m.DenyEvents>0, m.VerifyEvents>0)}</td>
      </tr>`;
    }).join('');
    body.querySelectorAll('tr.clickable').forEach(tr => {
      tr.addEventListener('click', () => openDrawer('Flow detail',
        `<pre>${esc(JSON.stringify(slice[parseInt(tr.dataset.idx,10)], null, 2))}</pre>`));
    });
  }

  // Pager
  const pages = Math.max(1, Math.ceil(total / sz));
  view.querySelector('#live-pager').innerHTML = `
    <div>${total} flows · page ${page+1}/${pages}</div>
    <div class="ctrls">
      <button ${page<=0?'disabled':''} id="pg-prev">prev</button>
      <button ${page>=pages-1?'disabled':''} id="pg-next">next</button>
    </div>`;
  view.querySelector('#pg-prev')?.addEventListener('click', () => { state.livePage = Math.max(0,page-1); refreshLive(view); });
  view.querySelector('#pg-next')?.addEventListener('click', () => { state.livePage = page+1; refreshLive(view); });
}

// ─── Per-process ──────────────────────────────────────────────

async function renderProcess(view) {
  if (!state.selectedBinary) {
    // Show binary picker.
    const data = await fetchJSON('/api/egress/overview?_=1' + visibilityParam());
    const bins = (data && data.top_binaries) || [];
    view.innerHTML = `
      <h1>Per-process</h1>
      <div class="subtitle">Pick a binary to drill into its egress pattern.</div>
      <div class="card">
        <div class="card-head"><h2>Recent binaries</h2><div class="right">${bins.length} active</div></div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl">
            <thead><tr><th>Binary</th><th class="num">Bytes-out</th><th class="num">Connects</th><th></th></tr></thead>
            <tbody>${bins.map(b => `
              <tr class="clickable" data-bin="${esc(b.label)}">
                <td class="mono">${esc(b.label)}</td>
                <td class="num">${fmtBytes(b.bytes)}</td>
                <td class="num dim">${fmtNum(b.connects)}</td>
                <td><span class="pill info">drill in →</span></td>
              </tr>`).join('') || '<tr class="empty-row"><td colspan="4">no binaries seen yet</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>`;
    view.querySelectorAll('tr.clickable[data-bin]').forEach(tr => {
      tr.addEventListener('click', () => go('/egress/process/' + encodeURIComponent(tr.dataset.bin)));
    });
    return;
  }

  const binary = state.selectedBinary;
  // Convert state.hours (1/6/24/168) into days for the binary endpoint.
  const days = Math.max(1, Math.ceil((state.hours || 24) / 24));
  const rows = await fetchJSON('/api/egress/binary?binary=' + encodeURIComponent(binary) + '&days=' + days) || [];
  // Rich cross-correlation payload (countries, ASNs, PIDs, alerts).
  const detail = await fetchJSON('/api/egress/process_detail?binary=' + encodeURIComponent(binary) + '&hours=' + (state.hours||24)) || {};
  let totalOut = 0, totalIn = 0, totalConn = 0, distinctDest = new Set(), denyN = 0;
  let firstSeen = Infinity, lastSeen = 0;
  rows.forEach(r => {
    const m = r.Metrics || {}, k = r.Key || {};
    totalOut += m.BytesOut || 0;
    totalIn += m.BytesIn || 0;
    totalConn += m.Connects || 0;
    denyN += m.DenyEvents || 0;
    distinctDest.add(k.DestCIDR + ':' + k.DestPort);
    const fs = new Date(m.FirstSeen).getTime() / 1000;
    const ls = new Date(m.LastSeen).getTime() / 1000;
    if (fs < firstSeen) firstSeen = fs;
    if (ls > lastSeen) lastSeen = ls;
  });

  // Destinations grouped.
  const destMap = new Map();
  rows.forEach(r => {
    const k = r.Key || {}, m = r.Metrics || {};
    const key = (k.DestCIDR||'') + ':' + (k.DestPort||0);
    let d = destMap.get(key);
    if (!d) {
      d = { dest: k.DestCIDR, port: k.DestPort, sni: k.SNI, dns: k.DNSName, cls: k.DestClass,
            bytesOut: 0, bytesIn: 0, conns: 0, deny: 0 };
      destMap.set(key, d);
    }
    d.bytesOut += m.BytesOut || 0;
    d.bytesIn += m.BytesIn || 0;
    d.conns += m.Connects || 0;
    d.deny += m.DenyEvents || 0;
  });
  const destRows = Array.from(destMap.values()).sort((a,b) => b.bytesOut - a.bytesOut);

  // Build timeline series.
  const buckets = new Map();
  rows.forEach(r => {
    const t = new Date(r.Bucket).getTime() / 1000;
    const e = buckets.get(t) || { x: t, out: 0, in: 0 };
    e.out += (r.Metrics||{}).BytesOut || 0;
    e.in += (r.Metrics||{}).BytesIn || 0;
    buckets.set(t, e);
  });
  const series = Array.from(buckets.values()).sort((a,b) => a.x - b.x);
  const chartHTML = Charts.lineChart([
    { name: 'out', color: '#ee8033', points: series.map(s => ({ x: s.x, y: s.out })) },
    { name: 'in',  color: '#60a5fa', points: series.map(s => ({ x: s.x, y: s.in })) },
  ], { height: 200 });

  view.innerHTML = `
    <div class="toolbar">
      <button class="btn-ghost" id="back">← back</button>
      <h1 class="mono" style="margin:0">${esc(binary)}</h1>
      <span class="pill dim">last ${esc(state.hours || 24)}h</span>
      <div class="spacer"></div>
      <button class="btn-ghost" id="p-allow">Allow all</button>
      <button class="btn-ghost" id="p-block">Block all</button>
      <button class="btn-ghost" id="p-capture">▶ Capture</button>
      <button class="btn-primary" id="p-observe">Observe only</button>
    </div>

    <div class="hero">
      <div class="kpi"><div class="kpi-label">Bytes out</div><div class="kpi-value">${fmtBytes(totalOut)}</div></div>
      <div class="kpi"><div class="kpi-label">Bytes in</div><div class="kpi-value">${fmtBytes(totalIn)}</div></div>
      <div class="kpi"><div class="kpi-label">Countries</div><div class="kpi-value">${esc(detail.distinct_countries||0)}</div><div class="kpi-sub">${esc(detail.distinct_asns||0)} ASNs · ${distinctDest.size} dests</div></div>
      <div class="kpi"><div class="kpi-label">Live PIDs</div><div class="kpi-value">${esc((detail.live_pids||[]).length)}</div><div class="kpi-sub">${esc((detail.historical_pids||[]).length)} in last 24h</div></div>
      <div class="kpi"><div class="kpi-label">Deny events</div><div class="kpi-value" style="color:${denyN>0?'var(--err)':'inherit'}">${denyN}</div></div>
    </div>

    ${detail.direction === 'inbound_reply' ? `<div class="card" style="margin-bottom:12px;border-left:3px solid #facc15;background:#1a1a0d">
      <div class="card-head"><h2 style="color:#facc15">⚠ Direction</h2></div>
      <div style="padding:10px 14px"><strong style="color:#facc15">inbound_reply</strong>
        <div class="dim" style="margin-top:4px">${esc(detail.direction_note||'')}</div></div>
    </div>` : ''}

    <div class="grid grid-2" style="margin-bottom:12px">
      <div class="card">
        <div class="card-head"><h2>Countries (${esc((detail.top_countries||[]).length)})</h2><div class="right">by bytes-out</div></div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl"><thead><tr><th>Country</th><th class="num">Bytes</th><th class="num">In</th><th class="num">Dests</th></tr></thead><tbody>
          ${(detail.top_countries||[]).map(c => `<tr class="clickable" data-country="${esc(c.country)}">
            <td><span class="ip-cc" style="margin-right:6px">${esc(c.country)}</span>${esc(countryName(c.country))}</td>
            <td class="num">${fmtBytes(c.bytes_out)}</td>
            <td class="num dim">${fmtBytes(c.bytes_in)}</td>
            <td class="num dim">${esc(c.dests)}</td>
          </tr>`).join('') || '<tr class="empty-row"><td colspan="4">no country data</td></tr>'}
          </tbody></table>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h2>ASNs (${esc((detail.top_asns||[]).length)})</h2><div class="right">org / ASN</div></div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl"><thead><tr><th>ASN</th><th>Org</th><th class="num">Bytes</th><th class="num">Dests</th></tr></thead><tbody>
          ${(detail.top_asns||[]).map(a => `<tr>
            <td class="mono">${esc(a.asn||'?')}</td>
            <td>${esc(a.org||'?')}</td>
            <td class="num">${fmtBytes(a.bytes_out)}</td>
            <td class="num dim">${esc(a.dests)}</td>
          </tr>`).join('') || '<tr class="empty-row"><td colspan="4">no ASN data</td></tr>'}
          </tbody></table>
        </div>
      </div>
    </div>

    ${(detail.live_pids||[]).length ? `<div class="card" style="margin-bottom:12px">
      <div class="card-head"><h2>Live PIDs (${esc(detail.live_pids.length)})</h2><div class="right">click PID for forensic page</div></div>
      <div class="tbl-wrap" style="border:0">
        <table class="tbl"><thead><tr><th>PID</th><th>Parent</th><th>Cmdline</th><th>Unit</th><th>User</th><th>Listens</th><th>Age</th></tr></thead><tbody>
        ${detail.live_pids.map(p => {
          const anc = (p.ancestors||[]).map(a => esc(a.comm||'?')).join(' ← ');
          return `<tr class="clickable" data-pid="${esc(p.pid)}">
            <td class="mono" style="color:var(--accent)"><strong>${esc(p.pid)}</strong></td>
            <td class="mono dim">${esc(anc||p.parent_comm||'?')}</td>
            <td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(p.cmdline||'')}">${esc(p.cmdline||p.comm||'')}</td>
            <td class="mono dim">${esc(p.unit||'')}</td>
            <td class="mono dim">${esc(p.username||'uid'+p.uid)}</td>
            <td class="mono dim">${(p.listen_ports||[]).join(',') || '—'}</td>
            <td class="mono dim">${esc(Math.floor((p.age_seconds||0)/60))}m</td>
          </tr>`;
        }).join('')}
        </tbody></table>
      </div>
    </div>` : ''}

    ${(detail.historical_pids||[]).length ? `<div class="card" style="margin-bottom:12px">
      <div class="card-head"><h2>Historical PIDs (${esc(detail.historical_pids.length)})</h2><div class="right">includes exited</div></div>
      <div class="tbl-wrap" style="border:0">
        <table class="tbl"><thead><tr><th>PID</th><th>Parent</th><th>Role</th><th>Container</th><th>Status</th><th class="num">Out</th><th class="num">In</th><th>Window</th><th>Dests</th></tr></thead><tbody>
        ${detail.historical_pids.map(h => {
          const tm0 = new Date(h.first_seen).toISOString().slice(11,19);
          const tm1 = new Date(h.last_seen).toISOString().slice(11,19);
          const status = h.still_alive ? '<span class="pill" style="background:#0d2818;color:#86efac">alive</span>' : '<span class="pill" style="background:#2a0d0d;color:#fca5a5">exited</span>';
          return `<tr class="clickable" data-pid="${esc(h.pid)}">
            <td class="mono" style="color:var(--accent)"><strong>${esc(h.pid)}</strong>${h.ppid?'<span class="dim"> (←'+esc(h.ppid)+')</span>':''}</td>
            <td class="mono dim" style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(h.parent_comm||'?')}</td>
            <td class="mono dim" style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(h.service_role||'')}</td>
            <td class="mono dim">${esc(h.container||'')}</td>
            <td>${status}</td>
            <td class="num">${fmtBytes(h.bytes_out)}</td>
            <td class="num dim">${fmtBytes(h.bytes_in)}</td>
            <td class="mono dim">${esc(tm0)} → ${esc(tm1)}</td>
            <td class="mono dim" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc((h.dests||[]).slice(0,3).join(' '))}</td>
          </tr>`;
        }).join('')}
        </tbody></table>
      </div>
    </div>` : ''}

    ${detail.suggested_block ? `<div class="card" style="margin-bottom:12px;border-left:3px solid var(--accent)">
      <div class="card-head"><h2>Suggested action</h2><div class="right">all dests in one /24</div></div>
      <div style="padding:10px 14px;display:flex;gap:10px;align-items:center">
        <div>All ${esc((detail.top_dests||[]).length)} destinations for this binary live in <code>${esc(detail.suggested_block)}</code>.</div>
        <div class="spacer"></div>
        <button class="btn-primary" id="p-suggest-block" data-cidr="${esc(detail.suggested_block)}">▶ Block ${esc(detail.suggested_block)}</button>
      </div>
    </div>` : ''}

    <div class="tabs">
      <button class="active" data-tab="timeline">Timeline</button>
      <button data-tab="dests">Destinations (${destRows.length})</button>
      <button data-tab="conns">Open connections</button>
      <button data-tab="alerts">Recent alerts</button>
      <button data-tab="policy">Suggested policy</button>
      <button data-tab="appprofile">App profile</button>
    </div>

    <div id="tab-body"></div>`;

  view.querySelector('#back').addEventListener('click', () => { state.selectedBinary = null; state.activeProcessTab = null; go('/egress/process'); });

  // Country chip → country drilldown.
  view.querySelectorAll('tr.clickable[data-country]').forEach(tr => {
    tr.addEventListener('click', () => { state.selectedCountry = tr.dataset.country; go('/egress/country/'+encodeURIComponent(tr.dataset.country)); });
  });
  // PID row → PID forensics page.
  view.querySelectorAll('tr.clickable[data-pid]').forEach(tr => {
    tr.addEventListener('click', () => go('/egress/pid/' + encodeURIComponent(tr.dataset.pid)));
  });
  // Suggested-block one-click.
  const sb2 = view.querySelector('#p-suggest-block');
  if (sb2) sb2.addEventListener('click', async () => {
    if (!confirm('Add ' + sb2.dataset.cidr + ' to safety-net block list?\nReversible via /egress/safety.')) return;
    const r = await fetch('/api/egress/safety/block', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({cidr: sb2.dataset.cidr, reason: 'process page: ' + binary})});
    if (r.ok) { alert('Blocked'); go('/egress/safety'); } else { alert('failed: '+ await r.text()); }
  });

  // Pre-fill capture filter with top 5 destinations for this binary.
  view.querySelector('#p-capture').addEventListener('click', () => {
    const hosts = destRows.slice(0, 5)
      .map(d => 'host ' + (d.dest || '').split('/')[0])
      .filter(s => s !== 'host ')
      .join(' or ');
    openCaptureModal({
      filter: hosts,
      description: 'binary ' + binary,
    });
  });

  const tabBody = view.querySelector('#tab-body');
  const tabs = {
    timeline: () => `<div class="card chart-card">
        <div class="card-head"><h2>Bytes timeline — last 24h</h2><div class="right">
          <span><span class="sw" style="background:#ee8033;width:9px;height:9px;display:inline-block;border-radius:2px;margin-right:4px"></span>out</span>
          &nbsp;&nbsp;<span><span class="sw" style="background:#60a5fa;width:9px;height:9px;display:inline-block;border-radius:2px;margin-right:4px"></span>in</span>
        </div></div>
        ${chartHTML}
      </div>`,
    dests: async () => {
      // Fetch live connections once to enable per-/16 expand. Live conns
      // hold exact IPs that fall inside each ledger CIDR row.
      const liveConns = (await fetchJSON('/api/egress/connections') || [])
        .filter(c => (c.exe || c.comm) === binary || (c.comm) === binary);
      // Week 6 — pull cohort rarity for this binary; nil-safe degrade.
      const fleetRarity = await fetchFleetRarity(binary);
      const rarityByDest = {};
      if (fleetRarity && fleetRarity.available) {
        (fleetRarity.rows || []).forEach(rr => {
          rarityByDest[(rr.dest_cidr || '') + ':' + (rr.port || 0)] = rr;
        });
      }
      // Build dest_cidr → [exact dst_addr,port,bytes_in,bytes_out,country,asn]
      const cidrChildren = new Map();
      liveConns.forEach(c => {
        // map exact IP back to /16 (v4) or /48 (v6) cheaply
        let cidr = '';
        const ip = c.dst_addr || '';
        if (ip.includes(':')) {
          const segs = ip.split(':').filter(s => s !== '');
          if (segs.length >= 3) cidr = segs[0] + ':' + segs[1] + ':' + segs[2] + '::/48';
        } else if (ip.includes('.')) {
          const oc = ip.split('.');
          if (oc.length === 4) cidr = oc[0] + '.' + oc[1] + '.0.0/16';
        }
        if (!cidr) return;
        if (!cidrChildren.has(cidr)) cidrChildren.set(cidr, []);
        cidrChildren.get(cidr).push(c);
      });

      if (!state.processExpandedCIDR) state.processExpandedCIDR = {};

      // Page-slice the destRows for Week 6 pagination polish.
      if (state.processDestPage === undefined) state.processDestPage = 0;
      const _pgSize = 50;
      const _pages = Math.max(1, Math.ceil(destRows.length / _pgSize));
      const _curPage = Math.min(state.processDestPage, _pages - 1);
      const pagedDests = destRows.slice(_curPage * _pgSize, _curPage * _pgSize + _pgSize);

      const rowsHTML = pagedDests.map(d => {
        const cidrKey = d.dest;
        const children = cidrChildren.get(cidrKey) || [];
        const hasChildren = children.length > 0;
        const expanded = !!state.processExpandedCIDR[cidrKey];
        const expandIcon = hasChildren ? (expanded ? '▾' : '▸') : ' ';
        const rr = rarityByDest[(d.dest||'') + ':' + (d.port||0)];
        const cohortCell = rr
          ? `<td class="num mono" style="color:${rr.fraction < 0.1 ? 'var(--err)' : 'var(--text-2)'}" title="${esc(rr.hosts_seen)}/${esc(rr.cohort_size)} cohort hosts see this dest">${esc(rr.hosts_seen)}/${esc(rr.cohort_size)}</td>`
          : '<td class="num dim">—</td>';
        const head = `<tr class="clickable" data-cidr="${esc(cidrKey)}">
          <td class="mono"><span style="display:inline-block;width:12px;color:${hasChildren?'var(--accent)':'var(--text-2)'}">${expandIcon}</span> ${esc(d.dest)}${hasChildren?' <span class="dim">('+children.length+' live)</span>':''}</td>
          <td class="mono">${esc(d.port)}</td>
          <td class="mono dim">${esc(d.sni || d.dns || '—')}</td>
          <td>${classPill(d.cls)}</td>
          <td class="num">${fmtBytes(d.bytesOut)}</td>
          <td class="num dim">${fmtBytes(d.bytesIn)}</td>
          <td class="num dim">${d.conns}</td>
          <td class="num" style="color:${d.deny>0?'var(--err)':'inherit'}">${d.deny}</td>
          ${cohortCell}
        </tr>`;
        const kidRows = (expanded && hasChildren) ? children.map(c => `<tr style="background:var(--bg-3)">
          <td class="mono" style="padding-left:32px"><span class="dim">└</span> ${ipChip(c.dst_addr, c.country)} <span class="dim">${esc(c.org || '')}</span></td>
          <td class="mono">${esc(c.dst_port)}</td>
          <td class="mono dim">${esc(c.sni || c.dns_name || '—')}</td>
          <td>${classPill(c.class)}</td>
          <td class="num">${fmtBytes(c.bytes_out)}</td>
          <td class="num dim">${fmtBytes(c.bytes_in)}</td>
          <td class="num dim">${esc(c.state)}</td>
          <td class="num dim">${esc(c.pid)}</td>
          <td class="num dim">—</td>
        </tr>`).join('') : '';
        return head + kidRows;
      }).join('') || '<tr class="empty-row"><td colspan="9">no destinations</td></tr>';

      // Defer click binding to next tick after innerHTML insert.
      setTimeout(() => {
        view.querySelectorAll('tr[data-cidr]').forEach(tr => {
          tr.addEventListener('click', () => {
            const k = tr.dataset.cidr;
            state.processExpandedCIDR[k] = !state.processExpandedCIDR[k];
            showTab('dests');
          });
        });
        const dp = view.querySelector('#dest-prev');
        const dn = view.querySelector('#dest-next');
        if (dp) dp.addEventListener('click', () => { state.processDestPage = Math.max(0, (state.processDestPage||0) - 1); showTab('dests'); });
        if (dn) dn.addEventListener('click', () => { state.processDestPage = (state.processDestPage||0) + 1; showTab('dests'); });
      }, 10);

      // Pagination — Week 6 polish. 50 rows per page on the dest list.
      // The expandable child rows are NOT paged (they live under the
      // currently-visible parent only).
      if (state.processDestPage === undefined) state.processDestPage = 0;
      const pgSize = 50;
      const pages = Math.max(1, Math.ceil(destRows.length / pgSize));
      const curPage = Math.min(state.processDestPage, pages - 1);
      const pagerHTML = destRows.length > pgSize ? `
        <div class="pager">
          <div>${destRows.length} dests · page ${curPage+1}/${pages}</div>
          <div class="ctrls">
            <button ${curPage<=0?'disabled':''} id="dest-prev">prev</button>
            <button ${curPage>=pages-1?'disabled':''} id="dest-next">next</button>
          </div>
        </div>` : '';
      return `<div class="tbl-wrap"><table class="tbl" data-sortable="1">
        <thead><tr><th>Destination (▸ click to expand)</th><th>Port</th><th>SNI / DNS</th><th>Class</th><th class="num">Out</th><th class="num">In</th><th class="num">Conns</th><th class="num">Deny</th><th class="num" title="hosts in your cohort that talk to this dest">Cohort</th></tr></thead>
        <tbody>${rowsHTML}</tbody>
      </table>${pagerHTML}</div>`;
    },
    conns: async () => {
      const conns = (await fetchJSON('/api/egress/connections') || []).filter(c =>
        (c.exe || c.comm) === binary || (c.comm) === binary);
      return `<div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>PID</th><th>Comm</th><th>Dest</th><th>Port</th><th>Country</th><th>Class</th><th class="num">Out</th><th class="num">In</th><th>State</th></tr></thead>
        <tbody>${conns.map(c => `<tr>
          <td class="mono">${esc(c.pid)}</td>
          <td class="mono">${esc(c.comm)}</td>
          <td class="mono">${ipChip(c.dst_addr, c.country)}</td>
          <td class="mono">${esc(c.dst_port)}</td>
          <td class="mono">${esc(c.country || '—')}</td>
          <td>${classPill(c.class)}</td>
          <td class="num">${fmtBytes(c.bytes_out)}</td>
          <td class="num dim">${fmtBytes(c.bytes_in)}</td>
          <td><span class="pill info">${esc(c.state)}</span></td>
        </tr>`).join('') || '<tr class="empty-row"><td colspan="9">no live connections for this binary</td></tr>'}</tbody>
      </table></div>`;
    },
    alerts: () => `<div class="placeholder"><strong>Alert correlation by binary</strong>wires into /api/alerts — coming with policy engine in Week 3.</div>`,
    appprofile: () => renderAppProfile(binary, rows, destRows),
    policy: () => `<div class="card">
        <div class="card-head"><h2>Suggested rule</h2><div class="right">observed destinations</div></div>
        <pre style="margin:0;font-family:var(--mono);font-size:11px;color:var(--text-1);background:var(--bg-0);padding:10px;border-radius:5px;border:1px solid var(--border)">
binary: ${esc(binary)}
mode:   observe
allow:
${destRows.slice(0,10).map(d => '  - ' + esc(d.dest) + ':' + esc(d.port) + (d.sni?' # '+esc(d.sni):'')).join('\n')}
        </pre>
        <div style="margin-top:10px;display:flex;gap:8px">
          <button class="btn-primary" disabled title="policy engine lands Week 3">Sign rule</button>
          <button class="btn-ghost" disabled>Edit YAML</button>
        </div>
      </div>`,
  };

  async function showTab(name) {
    state.activeProcessTab = name;
    view.querySelectorAll('.tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
    const out = tabs[name]();
    tabBody.innerHTML = (out instanceof Promise) ? '<div class="placeholder">loading…</div>' : out;
    if (out instanceof Promise) tabBody.innerHTML = await out;
  }
  view.querySelectorAll('.tabs button').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));
  showTab(state.activeProcessTab && tabs[state.activeProcessTab] ? state.activeProcessTab : 'timeline');
}

// ─── Countries ────────────────────────────────────────────────

async function renderCountries(view) {
  const data = await fetchJSON('/api/egress/countries?hours=' + state.hours + visibilityParam()) || [];
  const totalBytes = data.reduce((s, r) => s + (r.bytes_out || 0), 0);

  view.innerHTML = `
    <div class="toolbar">
      <h1>Countries</h1>
      <div class="spacer"></div>
      ${visibilityChip()}
      <span class="pill dim">${data.length} countries · ${fmtBytes(totalBytes)} total</span>
    </div>

    <div class="card chart-card" style="margin-bottom:12px">
      <div class="card-head"><h2>Geographic distribution</h2><div class="right">last ${esc(state.hours)}h</div></div>
      ${Charts.worldGrid(data, { limit: 60 })}
    </div>

    <div class="tbl-wrap">
      <table class="tbl">
        <thead><tr>
          <th>Country</th><th class="num">Bytes out</th><th class="num">Bytes in</th>
          <th class="num">Connects</th><th class="num">Dests</th><th class="num">Bins</th>
          <th>Top binary</th>
        </tr></thead>
        <tbody>${data.map(c => `<tr class="clickable" data-country="${esc(c.country)}">
          <td><span class="ip-cc" style="margin-right:6px">${esc(c.country || '??')}</span>${esc(countryName(c.country))}</td>
          <td class="num">${fmtBytes(c.bytes_out)}</td>
          <td class="num dim">${fmtBytes(c.bytes_in)}</td>
          <td class="num dim">${fmtNum(c.connects)}</td>
          <td class="num dim">${c.distinct_dests}</td>
          <td class="num dim">${c.distinct_binaries}</td>
          <td class="mono">${esc(c.top_binary || '—')}</td>
        </tr>`).join('') || '<tr class="empty-row"><td colspan="7">no traffic — geoip provider may not be wired</td></tr>'}</tbody>
      </table>
    </div>`;

  view.querySelectorAll('tr[data-country]').forEach(tr => {
    tr.addEventListener('click', () => {
      state.selectedCountry = tr.dataset.country;
      go('/egress/country');
    });
  });
  bindVisibility(view);
}

// ─── Country drilldown ───────────────────────────────────────

async function renderCountryDetail(view) {
  if (!state.selectedCountry) {
    view.innerHTML = `<div class="placeholder"><strong>No country selected</strong>Pick a country from the <a href="#" data-route="/egress/countries" id="ctry-back">Countries</a> page.</div>`;
    view.querySelector('#ctry-back').addEventListener('click', e => { e.preventDefault(); go('/egress/countries'); });
    return;
  }
  const cc = state.selectedCountry;
  const data = await fetchJSON('/api/egress/country?country=' + encodeURIComponent(cc) + '&hours=' + state.hours + visibilityParam());
  if (!data) {
    view.innerHTML = `<div class="placeholder"><strong>No data</strong>could not load country detail.</div>`;
    return;
  }

  // Timeline as bytes-out line chart.
  const series = (data.timeline || []).map(p => ({
    x: new Date(p.bucket).getTime() / 1000,
    out: p.bytes_out || 0,
    in: p.bytes_in || 0,
  }));
  const chartHTML = Charts.lineChart([
    { name: 'out', color: '#ee8033', points: series.map(s => ({ x: s.x, y: s.out })) },
    { name: 'in',  color: '#60a5fa', points: series.map(s => ({ x: s.x, y: s.in })) },
  ], { height: 200 });

  const binaryDests = data.binary_dests || {};
  const firstIPof = c => (c || '').split('/')[0];
  const topBinsHTML = (data.top_binaries || []).map((b, i) => {
    const dests = binaryDests[b.binary] || [];
    const subRows = dests.map(d => {
      const ip = firstIPof(d.cidr);
      const dur = (new Date(d.last_seen) - new Date(d.first_seen)) / 1000;
      return `<tr class="sub-row">
        <td class="mono"><a href="#" class="ip-link" data-ip="${esc(ip)}">${esc(d.cidr)}</a></td>
        <td class="mono">${esc(d.port)}</td>
        <td class="mono dim">${esc(d.sni || d.dns_name || '—')}</td>
        <td class="num">${fmtBytes(d.bytes_out)}</td>
        <td class="num dim">${fmtBytes(d.bytes_in)}</td>
        <td class="num dim">${fmtNum(d.connects)}</td>
        <td class="dim mono" title="${esc(new Date(d.first_seen).toISOString())} → ${esc(new Date(d.last_seen).toISOString())}">${dur > 0 ? Math.floor(dur)+'s' : 'instant'}</td>
        <td><button class="btn-ghost flow-btn" data-bin="${esc(b.binary)}" data-cidr="${esc(d.cidr)}" data-port="${esc(d.port)}">flow ▸</button></td>
      </tr>`;
    }).join('');
    const expandable = dests.length > 0;
    return `<tr class="expandable" data-row="bin-${i}">
        <td>${expandable ? '<span class="chev">▸</span>' : '<span class="chev dim">·</span>'} <span class="mono">${esc(b.binary)}</span></td>
        <td class="num">${fmtBytes(b.bytes_out)}</td>
        <td class="num dim">${fmtBytes(b.bytes_in)}</td>
        <td class="num dim">${fmtNum(b.connects)}</td>
        <td class="num dim">${b.dests}</td>
        <td><button class="btn-ghost open-proc" data-binary="${esc(b.binary)}">open ▸</button></td>
      </tr>
      <tr class="sub-table hidden" data-sub="bin-${i}">
        <td colspan="6" style="padding:0;background:#0e1116">
          ${expandable ? `<table class="tbl sub-tbl"><thead><tr>
              <th>Destination</th><th>Port</th><th>SNI / DNS</th>
              <th class="num">Out</th><th class="num">In</th><th class="num">Conns</th>
              <th>Duration</th><th></th>
            </tr></thead><tbody>${subRows}</tbody></table>` : '<div class="dim" style="padding:10px 14px">no per-destination breakdown captured (aggregated row may have rolled out of hot window)</div>'}
        </td>
      </tr>`;
  }).join('') || '<tr class="empty-row"><td colspan="6">no binaries</td></tr>';

  const topASNsHTML = (data.top_asns || []).map(a => `
    <tr>
      <td class="mono">${esc(a.asn || '—')}</td>
      <td>${esc(a.org || '—')}</td>
      <td class="num">${fmtBytes(a.bytes_out)}</td>
      <td class="num dim">${a.dests}</td>
    </tr>`).join('') || '<tr class="empty-row"><td colspan="4">no ASN data</td></tr>';

  const topDestsHTML = (data.top_dests || []).map(d => {
    const ip = firstIPof(d.cidr);
    return `<tr>
      <td class="mono"><a href="#" class="ip-link" data-ip="${esc(ip)}">${esc(d.cidr)}</a></td>
      <td class="mono">${esc(d.port)}</td>
      <td class="mono dim">${esc(d.sni || '—')}</td>
      <td class="num">${fmtBytes(d.bytes_out)}</td>
      <td class="num dim">${fmtBytes(d.bytes_in)}</td>
      <td class="num dim">${fmtNum(d.connects)}</td>
    </tr>`;
  }).join('') || '<tr class="empty-row"><td colspan="6">no destinations</td></tr>';

  const portsHTML = (data.ports || []).map(p => `
    <tr>
      <td class="mono">${esc(p.port)}/${esc(p.protocol)}</td>
      <td class="num">${fmtBytes(p.bytes_out)}</td>
      <td class="num dim">${p.flows}</td>
    </tr>`).join('') || '<tr class="empty-row"><td colspan="3">no ports</td></tr>';

  // Pre-fill packet capture filter from top destinations: "host A or host B …" (up to 5).
  const captureFilter = (data.top_dests || [])
    .slice(0, 5)
    .map(d => 'host ' + (d.cidr || '').split('/')[0])
    .filter(s => s !== 'host ')
    .join(' or ');

  view.innerHTML = `
    <div class="toolbar">
      <button class="btn-ghost" id="back-to-countries">← back to countries</button>
      <h1 style="margin:0">${esc(countryName(cc))} <span class="dim" style="font-size:14px;font-family:var(--mono)">(${esc(cc)})</span></h1>
      <span class="pill dim">last ${esc(data.hours)}h</span>
      <div class="spacer"></div>
      <button class="btn-primary" id="capture-btn">▶ Start packet capture</button>
    </div>

    ${(() => {
      const inv = data.investigation || {};
      if (!inv.pattern) return '';
      const patternColor = {sustained:'#ee8033', bursty:'#facc15', 'one-shot':'#60a5fa', intermittent:'#a3a3a3'}[inv.pattern] || '#a3a3a3';
      const first = inv.first_contact ? new Date(inv.first_contact) : null;
      const last  = inv.last_contact  ? new Date(inv.last_contact)  : null;
      const dur = first && last ? Math.max(0, (last - first)/1000) : 0;
      const durStr = dur > 3600 ? Math.floor(dur/3600)+'h '+Math.floor((dur%3600)/60)+'m' : Math.floor(dur/60)+'m '+Math.floor(dur%60)+'s';
      const blockBtn = inv.suggested_block
        ? `<button class="btn-primary" id="suggest-block" data-cidr="${esc(inv.suggested_block)}">▶ Block ${esc(inv.suggested_block)}</button>`
        : '';
      const notes = (inv.notes || []).map(n => `<div class="dim">• ${esc(n)}</div>`).join('');
      return `<div class="card" style="margin-bottom:12px;border-left:3px solid ${patternColor}">
        <div class="card-head"><h2>Investigation summary</h2><div class="right dim">at-a-glance verdict</div></div>
        <div style="display:grid;grid-template-columns:repeat(4, 1fr);gap:14px;padding:12px 14px">
          <div><div class="kpi-label">Pattern</div><div class="kpi-value" style="color:${patternColor};font-size:18px;text-transform:uppercase">${esc(inv.pattern)}</div><div class="dim" style="font-size:11px">burstiness=${(inv.burstiness_ratio||0).toFixed(2)}</div></div>
          <div><div class="kpi-label">First contact</div><div class="kpi-value" style="font-size:14px">${first ? fmtTime(first.getTime()/1000) : '—'}</div></div>
          <div><div class="kpi-label">Last contact</div><div class="kpi-value" style="font-size:14px">${last ? fmtTime(last.getTime()/1000) : '—'}</div></div>
          <div><div class="kpi-label">Active span</div><div class="kpi-value" style="font-size:14px">${durStr}</div></div>
        </div>
        ${notes ? `<div style="padding:6px 14px 12px">${notes}</div>` : ''}
        ${blockBtn ? `<div style="padding:0 14px 14px">${blockBtn}</div>` : ''}
      </div>`;
    })()}

    ${(() => {
      const inv = data.process_inventory || [];
      if (!inv.length) return '';
      // Surface direction banner if ANY binary is classified inbound_reply.
      const hasInbound = inv.some(b => b.direction === 'inbound_reply');
      const hasMixed   = inv.some(b => b.direction === 'mixed');
      if (!hasInbound && !hasMixed) return '';
      const bins = inv.filter(b => b.direction === 'inbound_reply' || b.direction === 'mixed')
        .map(b => `${b.binary} (${b.direction})`).join(', ');
      const note = (inv.find(b => b.direction_note) || {}).direction_note || '';
      return `<div class="card" style="margin-bottom:12px;border-left:3px solid #facc15;background:#1a1a0d">
        <div class="card-head"><h2 style="color:#facc15">⚠ Direction warning</h2></div>
        <div style="padding:10px 14px">
          <div style="font-weight:600;margin-bottom:4px">${esc(bins)}</div>
          <div class="dim">${esc(note)}</div>
        </div>
      </div>`;
    })()}

    <div class="hero">
      <div class="kpi"><div class="kpi-label">Bytes out</div><div class="kpi-value">${fmtBytes(data.bytes_out)}</div></div>
      <div class="kpi"><div class="kpi-label">Bytes in</div><div class="kpi-value">${fmtBytes(data.bytes_in)}</div></div>
      <div class="kpi"><div class="kpi-label">Connects</div><div class="kpi-value">${fmtNum(data.connects)}</div></div>
      <div class="kpi"><div class="kpi-label">Distinct dests</div><div class="kpi-value">${data.distinct_dests}</div></div>
      <div class="kpi"><div class="kpi-label">Distinct binaries</div><div class="kpi-value">${data.distinct_binaries}</div></div>
      <div class="kpi"><div class="kpi-label">Distinct ASNs</div><div class="kpi-value">${data.distinct_asns}</div></div>
    </div>

    <div class="card chart-card" style="margin-bottom:12px">
      <div class="card-head"><h2>Bytes timeline — last ${esc(data.hours)}h</h2><div class="right">
        <span><span class="sw" style="background:#ee8033;width:9px;height:9px;display:inline-block;border-radius:2px;margin-right:4px"></span>out</span>
        &nbsp;&nbsp;<span><span class="sw" style="background:#60a5fa;width:9px;height:9px;display:inline-block;border-radius:2px;margin-right:4px"></span>in</span>
      </div></div>
      ${chartHTML}
    </div>

    <div class="grid grid-2" style="margin-bottom:12px">
      <div class="card">
        <div class="card-head"><h2>Top binaries</h2><div class="right">by bytes-out</div></div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl"><thead><tr><th>Binary</th><th class="num">Out</th><th class="num">In</th><th class="num">Conns</th><th class="num">Dests</th></tr></thead>
          <tbody>${topBinsHTML}</tbody></table>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Top ASNs</h2><div class="right">org &amp; ASN</div></div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl"><thead><tr><th>ASN</th><th>Org</th><th class="num">Out</th><th class="num">Dests</th></tr></thead>
          <tbody>${topASNsHTML}</tbody></table>
        </div>
      </div>
    </div>

    <div class="card" style="margin-bottom:12px">
      <div class="card-head"><h2>Top destinations</h2><div class="right">CIDR : port</div></div>
      <div class="tbl-wrap" style="border:0">
        <table class="tbl"><thead><tr><th>CIDR</th><th>Port</th><th>SNI</th><th class="num">Out</th><th class="num">In</th><th class="num">Conns</th></tr></thead>
        <tbody>${topDestsHTML}</tbody></table>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h2>Ports observed</h2><div class="right">port / proto</div></div>
      <div class="tbl-wrap" style="border:0">
        <table class="tbl"><thead><tr><th>Port/Proto</th><th class="num">Bytes out</th><th class="num">Flows</th></tr></thead>
        <tbody>${portsHTML}</tbody></table>
      </div>
    </div>

    ${(() => {
      const inv = data.process_inventory || [];
      if (!inv.length) return '';
      const dirBadge = d => {
        const colors = {outbound:'#86efac', inbound_reply:'#facc15', mixed:'#fb923c', unknown:'#a3a3a3'};
        return `<span class="pill" style="background:${colors[d]||'#a3a3a3'};color:#111">${esc(d)}</span>`;
      };
      const fmtDur = s => s < 60 ? s+'s' : s < 3600 ? Math.floor(s/60)+'m '+Math.floor(s%60)+'s' : Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';
      const sections = inv.map(b => {
        const pids = b.pids || [];
        const pidCards = pids.map(p => {
          const ancStr = (p.ancestors || []).map(a => `[${a.pid}] ${esc(a.comm||'?')}`).join(' → ') || '<span class="dim">(not in proctree)</span>';
          const dests = (p.country_dests || []).slice(0, 12).map(d => `<span class="pill mono" style="background:#1a1f27;font-size:11px">${esc(d)}</span>`).join(' ') || '<span class="dim">no live sockets to this country (traffic may have closed)</span>';
          const lps = (p.listen_ports || []).map(x => x.toString()).join(', ') || '—';
          const started = p.started_at && p.started_at !== '0001-01-01T00:00:00Z' ? new Date(p.started_at).toISOString().replace('T',' ').slice(0,19) : '?';
          return `<div class="pid-card">
            <div class="pid-head">
              <div class="pid-id mono">PID ${esc(p.pid)}</div>
              <div class="pid-comm mono">${esc(p.comm||'?')}</div>
              ${p.unit ? `<span class="pill" style="background:#1e293b;color:#93c5fd">${esc(p.unit)}</span>` : ''}
              ${p.username ? `<span class="pill" style="background:#0d2818;color:#86efac">${esc(p.username)} (uid ${p.uid})</span>` : `<span class="dim">uid ${p.uid}</span>`}
              <span class="dim mono" style="margin-left:auto">age ${fmtDur(p.age_seconds||0)}</span>
            </div>
            <div class="pid-grid">
              <div><span class="kpi-label">EXE</span><div class="mono">${esc(p.exe||'?')}</div></div>
              <div><span class="kpi-label">CMDLINE</span><div class="mono">${esc(p.cmdline||'?')}</div></div>
              <div><span class="kpi-label">CWD</span><div class="mono">${esc(p.cwd||'?')}</div></div>
              <div><span class="kpi-label">STARTED</span><div class="mono">${esc(started)}</div></div>
              <div><span class="kpi-label">PARENT</span><div class="mono">PID ${p.ppid}</div></div>
              <div><span class="kpi-label">OPEN SOCKETS</span><div class="mono">${p.open_sockets}</div></div>
              <div><span class="kpi-label">LISTENING ON</span><div class="mono">${esc(lps)}</div></div>
              <div><span class="kpi-label">CGROUP</span><div class="mono" style="font-size:11px">${esc(p.cgroup_path||'?')}</div></div>
            </div>
            <div style="margin-top:8px"><span class="kpi-label">ANCESTORS</span><div class="mono" style="font-size:12px">${ancStr}</div></div>
            <div style="margin-top:8px"><span class="kpi-label">LIVE DESTS IN ${esc(cc)}</span><div style="margin-top:4px">${dests}</div></div>
          </div>`;
        }).join('') || '<div class="placeholder"><strong>No live PIDs found for this binary</strong>The process(es) that produced these bytes have already exited. Try /egress/process/'+esc(b.binary)+' for the historical view.</div>';
        return `<div class="card" style="margin-bottom:12px">
          <div class="card-head">
            <h2>Process inventory: <span class="mono">${esc(b.binary)}</span></h2>
            <div class="right">${dirBadge(b.direction)} <span class="dim" style="margin-left:8px">${pids.length} live PID${pids.length===1?'':'s'}</span></div>
          </div>
          ${b.direction_note ? `<div class="dim" style="padding:0 14px 10px">${esc(b.direction_note)}</div>` : ''}
          <div style="padding:0 14px 14px">${pidCards}</div>
        </div>`;
      }).join('');
      return `<h2 style="margin-top:18px">Deep dive — who is sending, who spawned them, when, why</h2>${sections}`;
    })()}

    ${(() => {
      const hist = data.historical_pids || [];
      if (!hist.length) return '';
      const fmtTm = t => new Date(t).toISOString().replace('T',' ').slice(11,19);
      const rows = hist.map(h => {
        const span = (new Date(h.last_seen) - new Date(h.first_seen)) / 1000;
        const status = h.still_alive
          ? '<span class="pill" style="background:#0d2818;color:#86efac">alive</span>'
          : '<span class="pill" style="background:#2a0d0d;color:#fca5a5">exited</span>';
        const dests = (h.dests || []).slice(0,3).map(d => `<span class="pill mono" style="background:#1a1f27;font-size:10px;margin-right:3px">${esc(d)}</span>`).join('');
        return `<tr>
          <td class="mono"><strong>${esc(h.pid)}</strong>${h.ppid?'<span class="dim"> (←'+esc(h.ppid)+')</span>':''}</td>
          <td class="mono">${esc(h.comm||h.binary)}</td>
          <td class="mono dim" style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(h.parent_comm||'?')}</td>
          <td class="mono dim" style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(h.service_role||'')}</td>
          <td class="mono dim">${esc(h.container||'')}</td>
          <td>${status}</td>
          <td class="num">${fmtBytes(h.bytes_out)}</td>
          <td class="num dim">${fmtBytes(h.bytes_in)}</td>
          <td class="mono dim">${esc(fmtTm(h.first_seen))} → ${esc(fmtTm(h.last_seen))} (${Math.floor(span)}s)</td>
          <td>${dests}</td>
        </tr>`;
      }).join('');
      return `<div class="card" style="margin-top:12px">
        <div class="card-head">
          <h2>Historical PIDs (includes exited)</h2>
          <div class="right dim">${hist.length} PID${hist.length===1?'':'s'} touched ${esc(cc)} in last ${esc(data.hours)}h</div>
        </div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl"><thead><tr>
            <th>PID (PPID)</th><th>Comm</th><th>Parent</th><th>Role</th><th>Container</th><th>Status</th>
            <th class="num">Out</th><th class="num">In</th><th>Span</th><th>Dests</th>
          </tr></thead><tbody>${rows}</tbody></table>
        </div></div>`;
    })()}

    ${(() => {
      const alerts = data.related_alerts || [];
      if (!alerts.length) return '';
      const rows = alerts.map(a => `<tr>
        <td class="mono dim">${esc(new Date(a.time).toISOString().replace('T',' ').slice(0,19))}</td>
        <td class="mono">${esc(a.rule_id||'?')}</td>
        <td class="mono"><a href="#" class="ip-link" data-ip="${esc(a.dst_ip||'')}">${esc(a.dst_ip||'')}</a></td>
        <td class="mono">${a.pid?'PID '+a.pid:''}</td>
        <td class="mono">${esc(a.binary||'')}</td>
        <td class="mono">${esc(a.action||'')}</td>
        <td>${esc(a.reason||'')}</td>
      </tr>`).join('');
      return `<div class="card" style="margin-top:12px">
        <div class="card-head"><h2>Related alerts</h2><div class="right">${alerts.length} hit${alerts.length===1?'':'s'}</div></div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl"><thead><tr><th>Time</th><th>Rule</th><th>Dest</th><th>PID</th><th>Binary</th><th>Action</th><th>Reason</th></tr></thead>
          <tbody>${rows}</tbody></table>
        </div></div>`;
    })()}`;

  view.querySelector('#back-to-countries').addEventListener('click', () => go('/egress/countries'));
  // Expand/collapse binary rows.
  view.querySelectorAll('tr.expandable').forEach(tr => {
    tr.addEventListener('click', (e) => {
      if (e.target.closest('button') || e.target.closest('a')) return;
      const id = tr.dataset.row;
      const sub = view.querySelector(`tr.sub-table[data-sub="${id}"]`);
      if (!sub) return;
      sub.classList.toggle('hidden');
      const chev = tr.querySelector('.chev');
      if (chev) chev.textContent = sub.classList.contains('hidden') ? '▸' : '▾';
    });
  });
  view.querySelectorAll('.open-proc').forEach(b => {
    b.addEventListener('click', (e) => { e.stopPropagation(); go('/egress/process/' + encodeURIComponent(b.dataset.binary)); });
  });
  view.querySelectorAll('.flow-btn').forEach(b => {
    b.addEventListener('click', (e) => {
      e.stopPropagation();
      go(`/egress/flow/${encodeURIComponent(b.dataset.bin)}/${encodeURIComponent(b.dataset.cidr)}/${encodeURIComponent(b.dataset.port)}`);
    });
  });
  view.querySelectorAll('.ip-link').forEach(a => {
    a.addEventListener('click', (e) => {
      e.preventDefault(); e.stopPropagation();
      go('/egress/ip/' + encodeURIComponent(a.dataset.ip));
    });
  });
  const sb = view.querySelector('#suggest-block');
  if (sb) sb.addEventListener('click', async () => {
    if (!confirm('Add ' + sb.dataset.cidr + ' to the safety-net block list?\n\nThis will install an nftables drop rule for every IP in the range.\nReversible via /egress/safety.')) return;
    const resp = await fetch('/api/egress/safety/block', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({cidr: sb.dataset.cidr, reason: 'country drilldown: ' + cc}) });
    if (resp.ok) { alert('Block installed: ' + sb.dataset.cidr); go('/egress/safety'); }
    else { alert('Block failed: ' + (await resp.text())); }
  });
  view.querySelector('#capture-btn').addEventListener('click', () => {
    openCaptureModal({
      filter: captureFilter,
      description: 'country ' + cc + ' top dests',
    });
  });
}

// ─── Packet captures ─────────────────────────────────────────

async function renderCaptures(view) {
  const list = await fetchJSON('/api/egress/capture/list') || [];
  // Probe availability with a HEAD-style attempt: try fetch + check
  // for 503 on /start so the UI surfaces the "install tcpdump" hint
  // explicitly. We do this only on first render.
  let unavailable = false;
  if (!state.captureAvailChecked) {
    // Probe with a GET that the handler will reject with 503 when
    // pcap manager isn't wired, or 405 (method not allowed) when it
    // is. Either way we never accidentally start a capture.
    try {
      const r = await fetch('/api/egress/capture/start', { method: 'GET' });
      if (r.status === 503) unavailable = true;
      state.captureUnavailable = unavailable;
    } catch (_) {}
    state.captureAvailChecked = true;
  } else {
    unavailable = !!state.captureUnavailable;
  }

  const rowsHTML = list.map(c => {
    const statusPill = c.status === 'running'
      ? '<span class="pill solid-warn">running</span>'
      : c.status === 'stopped'
        ? '<span class="pill info">stopped</span>'
        : '<span class="pill solid-err">' + esc(c.status) + '</span>';
    const dl = c.status === 'stopped'
      ? `<a class="btn-ghost" href="/api/egress/capture/${esc(c.id)}/download">download</a>`
      : '';
    const stopBtn = c.status === 'running'
      ? `<button class="btn-ghost" data-stop="${esc(c.id)}">stop</button>`
      : '';
    const delBtn = `<button class="btn-ghost" data-del="${esc(c.id)}">delete</button>`;
    return `<tr>
      <td class="mono">${esc(c.id)}</td>
      <td class="mono">${esc(c.filter || '(any)')}</td>
      <td class="dim">${esc(c.description || '')}</td>
      <td>${statusPill}</td>
      <td class="num">${fmtBytes(c.size)}</td>
      <td class="dim">${esc(Math.floor((c.duration_limit||0)/1e9))}s / ${esc(c.size_limit_mb)}MB</td>
      <td class="dim">${fmtTime(new Date(c.started_at).getTime()/1000)}</td>
      <td>${dl} ${stopBtn} ${delBtn}</td>
    </tr>`;
  }).join('') || '<tr class="empty-row"><td colspan="8">no captures yet</td></tr>';

  view.innerHTML = `
    <div class="toolbar">
      <h1>Packet captures</h1>
      <span class="pill dim">${list.length} total · max 5 concurrent · 30 min · 500 MB</span>
      <div class="spacer"></div>
      <button class="btn-primary" id="new-capture" ${unavailable?'disabled':''}>▶ New capture</button>
    </div>
    ${unavailable ? '<div class="placeholder"><strong>Packet capture unavailable</strong>install tcpdump (apt install tcpdump) and restart xhelix.</div>' : ''}
    <div class="tbl-wrap">
      <table class="tbl">
        <thead><tr>
          <th>ID</th><th>Filter</th><th>Description</th><th>Status</th>
          <th class="num">Size</th><th>Limits</th><th>Started</th><th></th>
        </tr></thead>
        <tbody>${rowsHTML}</tbody>
      </table>
    </div>`;

  const newBtn = view.querySelector('#new-capture');
  if (newBtn && !unavailable) newBtn.addEventListener('click', () => openCaptureModal({}));
  view.querySelectorAll('button[data-stop]').forEach(b => {
    b.addEventListener('click', async () => {
      await fetch('/api/egress/capture/stop', { method: 'POST', body: JSON.stringify({ id: b.dataset.stop }) });
      renderCaptures(view);
    });
  });
  view.querySelectorAll('button[data-del]').forEach(b => {
    b.addEventListener('click', async () => {
      await fetch('/api/egress/capture/delete', { method: 'POST', body: JSON.stringify({ id: b.dataset.del }) });
      renderCaptures(view);
    });
  });
}

// openCaptureModal renders a small inline modal (re-uses the drawer)
// for starting a new packet capture. Pre-filled values come from the
// invoking context (country detail / process / connection).
function openCaptureModal(prefill) {
  const filter = (prefill && prefill.filter) || '';
  const description = (prefill && prefill.description) || '';
  const body = `
    <div class="form">
      <label>BPF filter <span class="dim">(host X / port Y / proto Z)</span></label>
      <input id="cap-filter" type="text" value="${esc(filter)}" placeholder="host 1.2.3.4 and port 443" />
      <label>Description</label>
      <input id="cap-desc" type="text" value="${esc(description)}" placeholder="why are you capturing?" />
      <label>Duration (seconds, max 1800)</label>
      <input id="cap-dur" type="number" value="300" min="1" max="1800" />
      <label>Size cap (MB, max 500)</label>
      <input id="cap-size" type="number" value="50" min="1" max="500" />
      <div style="margin-top:12px;display:flex;gap:8px">
        <button class="btn-primary" id="cap-start">Start capture</button>
        <button class="btn-ghost" id="cap-cancel">Cancel</button>
      </div>
      <div id="cap-msg" class="dim" style="margin-top:8px;font-size:11px"></div>
    </div>`;
  openDrawer('New packet capture', body);
  document.getElementById('cap-cancel').addEventListener('click', closeDrawer);
  document.getElementById('cap-start').addEventListener('click', async () => {
    const msg = document.getElementById('cap-msg');
    msg.textContent = 'starting…';
    const req = {
      filter: document.getElementById('cap-filter').value || '',
      description: document.getElementById('cap-desc').value || '',
      duration_seconds: parseInt(document.getElementById('cap-dur').value, 10) || 300,
      size_mb: parseInt(document.getElementById('cap-size').value, 10) || 50,
    };
    try {
      const r = await fetch('/api/egress/capture/start', {
        method: 'POST',
        body: JSON.stringify(req),
      });
      if (!r.ok) {
        const txt = await r.text();
        msg.textContent = 'error: ' + txt;
        return;
      }
      const rec = await r.json();
      msg.innerHTML = 'capture <span class="mono">' + esc(rec.id) + '</span> running — <a href="#" id="cap-goto">view captures</a>';
      document.getElementById('cap-goto').addEventListener('click', e => {
        e.preventDefault();
        closeDrawer();
        go('/egress/captures');
      });
    } catch (e) {
      msg.textContent = 'error: ' + (e.message || e);
    }
  });
}

// ─── Companies / ASNs ─────────────────────────────────────────

async function renderCompanies(view) {
  const data = await fetchJSON('/api/egress/companies?hours=' + state.hours + visibilityParam()) || [];
  const topCards = data.slice(0, 8);
  view.innerHTML = `
    <div class="toolbar">
      <h1>Companies &amp; ASNs</h1>
      <div class="spacer"></div>
      ${visibilityChip()}
      <span class="pill dim">${data.length} orgs · ${esc(state.hours)}h window</span>
    </div>

    <div class="grid grid-4" style="margin-bottom:12px">
      ${topCards.map(c => `
        <div class="card">
          <div class="card-head">
            <h2 style="text-transform:none;letter-spacing:0;font-size:13px">${esc(c.org || c.asn || 'unknown')}</h2>
            ${classPill(c.class)}
          </div>
          <div class="kpi-value" style="font-size:18px">${fmtBytes(c.bytes_out)}</div>
          <div class="kpi-sub">${c.distinct_dests} dests · ${fmtNum(c.connects)} conns</div>
          <div class="kpi-sub mono" style="margin-top:4px">${esc(c.asn || '—')} · top: ${esc(c.top_binary || '—')}</div>
        </div>
      `).join('') || '<div class="placeholder">no ASN data — geoip provider may not be wired</div>'}
    </div>

    <div class="tbl-wrap">
      <table class="tbl">
        <thead><tr>
          <th>Org</th><th>ASN</th><th>Class</th>
          <th class="num">Bytes out</th><th class="num">Bytes in</th>
          <th class="num">Connects</th><th class="num">Dests</th><th>Top binary</th>
        </tr></thead>
        <tbody>${data.map(c => `<tr>
          <td>${esc(c.org || '—')}</td>
          <td class="mono">${esc(c.asn || '—')}</td>
          <td>${classPill(c.class)}</td>
          <td class="num">${fmtBytes(c.bytes_out)}</td>
          <td class="num dim">${fmtBytes(c.bytes_in)}</td>
          <td class="num dim">${fmtNum(c.connects)}</td>
          <td class="num dim">${c.distinct_dests}</td>
          <td class="mono">${esc(c.top_binary || '—')}</td>
        </tr>`).join('') || '<tr class="empty-row"><td colspan="8">no orgs seen</td></tr>'}</tbody>
      </table>
    </div>`;
  bindVisibility(view);
}

// ─── Connections ──────────────────────────────────────────────

async function renderConnections(view) {
  await ensureUIDNames();
  const data = await fetchJSON('/api/egress/connections?_=1' + visibilityParam()) || [];
  if (state.connGrouped === undefined) state.connGrouped = false;
  if (state.connExpanded === undefined) state.connExpanded = {};

  function appProto(c) {
    return protocolOf({
      Key: { DestPort: c.dst_port, SNI: c.sni, Protocol: c.proto },
    });
  }
  function durationOf(c) {
    if (!c.opened_at) return '—';
    const last = c.last_seen || (Date.now()/1000);
    const d = Math.max(0, last - c.opened_at);
    if (d < 60) return d.toFixed(0) + 's';
    if (d < 3600) return Math.floor(d/60) + 'm';
    return Math.floor(d/3600) + 'h';
  }
  function rowHTML(c, i, indent) {
    const pad = indent ? 'padding-left:24px' : '';
    return `<tr class="clickable" data-idx="${i}">
      <td class="mono" style="${pad}">${esc(c.pid)}</td>
      <td class="mono dim">${esc(c.parent_comm ? c.parent_comm + ' (' + c.ppid + ')' : (c.ppid || '—'))}</td>
      <td class="mono">${esc(c.comm)}</td>
      <td class="mono dim">${esc(c.exe || '—')}</td>
      <td class="mono">${ipChip(c.dst_addr, c.country)}</td>
      <td class="mono dim">${esc(c.dns_name || c.sni || '—')}</td>
      <td class="mono">${esc(c.dst_port)}</td>
      <td class="mono">${esc(c.proto)}</td>
      <td class="mono">${esc(appProto(c))}</td>
      <td class="mono">${esc(c.country || '—')}</td>
      <td class="mono dim">${esc(c.org || c.asn || '—')}</td>
      <td>${classPill(c.class)}</td>
      <td class="num">${fmtBytes(c.bytes_out)}</td>
      <td class="num dim">${fmtBytes(c.bytes_in)}</td>
      <td class="dim">${durationOf(c)}</td>
      <td><span class="pill info">${esc(c.state)}</span></td>
    </tr>`;
  }

  let bodyHTML = '';
  if (state.connGrouped) {
    // Group by ppid; show one parent row, expandable to children.
    const groups = new Map();
    data.forEach((c, i) => {
      const key = c.ppid || 0;
      let g = groups.get(key);
      if (!g) { g = { ppid:key, parentComm:'', children:[], bytesOut:0, bytesIn:0 }; groups.set(key, g); }
      g.children.push({ c, i });
      g.bytesOut += c.bytes_out || 0;
      g.bytesIn += c.bytes_in || 0;
      // Best-effort parent comm: if a row has pid==ppid of another, capture its comm.
    });
    // Attach parent comm if we can find a row whose pid matches the ppid.
    const byPID = new Map();
    data.forEach(c => byPID.set(c.pid, c));
    const glist = Array.from(groups.values()).sort((a,b) => b.bytesOut - a.bytesOut);
    bodyHTML = glist.map(g => {
      // Prefer the backend-provided parent_comm (resolved via proctree).
      // Falls back to PID-in-snapshot lookup, then "?".
      const child0 = g.children[0]?.c;
      const parent = byPID.get(g.ppid);
      const parentComm = (child0 && child0.parent_comm) || (parent && parent.comm) || '?';
      const expanded = !!state.connExpanded[g.ppid];
      const head = `<tr class="clickable" data-group="${esc(g.ppid)}">
        <td class="mono"><span style="display:inline-block;width:12px">${expanded?'▾':'▸'}</span> ppid ${esc(g.ppid)}</td>
        <td class="mono dim">—</td>
        <td class="mono">${esc(parentComm)}</td>
        <td class="mono dim">—</td>
        <td class="mono dim" colspan="8">${g.children.length} child connection(s)</td>
        <td class="num">${fmtBytes(g.bytesOut)}</td>
        <td class="num dim">${fmtBytes(g.bytesIn)}</td>
        <td class="dim">—</td>
        <td><span class="pill info">grouped</span></td>
      </tr>`;
      const kids = expanded ? g.children.map(x => rowHTML(x.c, x.i, true)).join('') : '';
      return head + kids;
    }).join('');
  } else {
    bodyHTML = data.map((c, i) => rowHTML(c, i, false)).join('');
  }

  view.innerHTML = `
    <div class="toolbar">
      <h1>Per-connection</h1>
      <div class="spacer"></div>
      ${visibilityChip()}
      <button class="btn-ghost" id="grp-toggle">${state.connGrouped ? 'Ungroup' : 'Group by parent'}</button>
      <button class="btn-ghost" id="conn-capture">▶ Capture selected hosts</button>
      <span class="pill dim">${data.length} live</span>
    </div>
    <div class="tbl-wrap">
      <table class="tbl">
        <thead><tr>
          <th>PID</th><th>PPID</th><th>Comm</th><th>Exe</th>
          <th>Dst</th><th>Dst name</th><th>Port</th>
          <th>L4</th><th>App</th>
          <th>Country</th><th>ASN org</th><th>Class</th>
          <th class="num">Out</th><th class="num">In</th><th>Dur</th><th>State</th>
        </tr></thead>
        <tbody>${bodyHTML || '<tr class="empty-row"><td colspan="16">no open connections — connstate provider may not be wired</td></tr>'}</tbody>
      </table>
    </div>`;

  view.querySelector('#grp-toggle').addEventListener('click', () => {
    state.connGrouped = !state.connGrouped;
    state.connExpanded = {};
    renderConnections(view);
  });
  view.querySelector('#conn-capture').addEventListener('click', () => {
    // Pre-fill with the top 5 distinct destination IPs from the live snapshot.
    const seen = new Set();
    const hosts = [];
    for (const c of data) {
      if (!c.dst_addr || seen.has(c.dst_addr)) continue;
      seen.add(c.dst_addr);
      hosts.push('host ' + c.dst_addr);
      if (hosts.length >= 5) break;
    }
    openCaptureModal({
      filter: hosts.join(' or '),
      description: 'live conn snapshot — top dests',
    });
  });
  view.querySelectorAll('tr.clickable[data-group]').forEach(tr => {
    tr.addEventListener('click', () => {
      const k = tr.dataset.group;
      state.connExpanded[k] = !state.connExpanded[k];
      renderConnections(view);
    });
  });
  view.querySelectorAll('tr.clickable[data-idx]').forEach(tr => {
    tr.addEventListener('click', (e) => {
      e.stopPropagation();
      openDrawer('Connection',
        `<pre>${esc(JSON.stringify(data[parseInt(tr.dataset.idx, 10)], null, 2))}</pre>`);
    });
  });
  bindVisibility(view);
}

// ─── Alerts ───────────────────────────────────────────────────

async function renderAlerts(view) {
  view.innerHTML = `
    <div class="toolbar">
      <h1>Alerts</h1>
      <div class="spacer"></div>
      <span class="pill dim" id="alert-count">0 alerts</span>
    </div>
    <div class="card" style="padding:0">
      <div id="alert-stream"></div>
    </div>`;

  const stream = view.querySelector('#alert-stream');
  const count = view.querySelector('#alert-count');
  // Seed with the latest alerts.
  const seed = await fetchJSON('/api/alerts') || [];
  const list = seed.slice(-200);
  function appendAlert(a) {
    const sev = (a.severity || a.Severity || 'low').toLowerCase();
    const ruleID = a.rule_id || a.RuleID || a.rule || '';
    const title = a.message || a.Message || a.title || ruleID || 'alert';
    const ts = a.time || a.Time || a.created_at;
    const row = document.createElement('div');
    row.className = 'alert-row';
    row.innerHTML = `
      <div class="sev ${esc(sev)}"></div>
      <div style="flex:1;min-width:0">
        <div class="title">${esc(title)}</div>
        <div class="desc">${esc(a.comm || a.Comm || '')} <span class="dim">${esc(ruleID)}</span></div>
        <div class="meta">${fmtTime(ts || Date.now()/1000)} · ${esc(sev)}</div>
      </div>
      <span class="pill ${sev==='critical'?'solid-err':sev==='high'?'solid-warn':'info'}">${esc(sev)}</span>`;
    row.addEventListener('click', () => openDrawer('Alert', `<pre>${esc(JSON.stringify(a, null, 2))}</pre>`));
    stream.prepend(row);
    while (stream.children.length > 200) stream.removeChild(stream.lastChild);
    count.textContent = stream.children.length + ' alerts';
  }
  list.forEach(appendAlert);
  count.textContent = list.length + ' alerts';

  // Subscribe to SSE — keep ref so refresh re-render closes it.
  if (window._alertES) try { window._alertES.close(); } catch (_) {}
  try {
    const es = new EventSource('/api/alerts/stream');
    es.onmessage = e => {
      try { appendAlert(JSON.parse(e.data)); } catch (_) {}
    };
    es.onerror = () => { /* swallow; will retry */ };
    window._alertES = es;
  } catch (_) {}
}

// ─── Users / Cgroups / Destinations / Protocols / Storage / Sensors / Policy ─

async function renderUsers(view) {
  await ensureUIDNames();
  const rows = await fetchJSON('/api/egress/live') || [];
  // Aggregate by UID with full cross-axis breakdown.
  const m = new Map();
  rows.forEach(r => {
    const k = r.Key || {}, mt = r.Metrics || {};
    const uid = k.UID;
    let e = m.get(uid);
    if (!e) {
      e = { uid, bytesOut:0, bytesIn:0, conns:0, deny:0,
            bins: new Map(), dests: new Map(), countries: new Map() };
      m.set(uid, e);
    }
    e.bytesOut += mt.BytesOut||0; e.bytesIn += mt.BytesIn||0; e.conns += mt.Connects||0;
    e.deny += mt.DenyEvents||0;
    const bb = e.bins.get(k.Binary) || 0;       e.bins.set(k.Binary, bb + (mt.BytesOut||0));
    const dk = (k.DestCIDR||'') + ':' + (k.DestPort||0);
    const dv = e.dests.get(dk) || { ip: k.DestCIDR, port: k.DestPort, sni: k.SNI, dns: k.DNSName, bytes: 0 };
    dv.bytes += (mt.BytesOut||0); e.dests.set(dk, dv);
  });

  // Enrich with country lookups via /api/egress/ipinfo (cheap: hot cache hits).
  // We do this in bulk after the first paint — first pass uses what we have.
  const list = Array.from(m.values()).sort((a,b) => b.bytesOut - a.bytesOut);

  if (!state.selectedUID) {
    // ── List view ──
    view.innerHTML = `
      <h1>Per-user (UID)</h1>
      <div class="subtitle">Aggregate egress by Linux UID. Click a row to expand.</div>
      <div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>UID / User</th><th class="num">Bytes out</th><th class="num">Bytes in</th><th class="num">Conns</th><th class="num">Binaries</th><th class="num">Dests</th><th class="num">Deny</th></tr></thead>
        <tbody>${list.map(u => `<tr class="clickable" data-uid="${esc(u.uid)}">
          <td class="mono">${esc(uidLabel(u.uid))}</td>
          <td class="num">${fmtBytes(u.bytesOut)}</td>
          <td class="num dim">${fmtBytes(u.bytesIn)}</td>
          <td class="num dim">${fmtNum(u.conns)}</td>
          <td class="num dim">${u.bins.size}</td>
          <td class="num dim">${u.dests.size}</td>
          <td class="num" style="color:${u.deny>0?'var(--err)':'inherit'}">${u.deny}</td>
        </tr>`).join('') || '<tr class="empty-row"><td colspan="7">no flows</td></tr>'}</tbody>
      </table></div>`;
    view.querySelectorAll('tr.clickable[data-uid]').forEach(tr =>
      tr.addEventListener('click', () => { state.selectedUID = Number(tr.dataset.uid); render(); }));
    return;
  }

  // ── Per-UID drilldown ──
  const u = list.find(x => String(x.uid) === String(state.selectedUID));
  if (!u) {
    view.innerHTML = `<div class="placeholder"><strong>No flows for UID ${esc(state.selectedUID)}</strong>
      <button class="btn-ghost" id="uid-back">← back</button></div>`;
    view.querySelector('#uid-back').addEventListener('click', () => { state.selectedUID = null; render(); });
    return;
  }
  const binArr = Array.from(u.bins.entries()).map(([b,bytes]) => ({b, bytes})).sort((a,b)=>b.bytes-a.bytes);
  const destArr = Array.from(u.dests.values()).sort((a,b)=>b.bytes-a.bytes);

  // Bulk-geolookup all dest IPs (parallel, hot cache).
  const ipinfoCache = await Promise.all(destArr.slice(0,30).map(d =>
    fetchJSON('/api/egress/ipinfo?ip=' + encodeURIComponent((d.ip||'').split('/')[0])).catch(()=>null)
  ));
  const ctryByIP = {};
  ipinfoCache.forEach((info,i) => { if (info && info.country) ctryByIP[destArr[i].ip] = { cc: info.country, asn: info.asn, org: info.org }; });
  // Country aggregation.
  const ctryAgg = new Map();
  destArr.forEach(d => {
    const meta = ctryByIP[d.ip];
    if (!meta) return;
    const cur = ctryAgg.get(meta.cc) || { cc: meta.cc, bytes: 0, dests: 0 };
    cur.bytes += d.bytes; cur.dests++;
    ctryAgg.set(meta.cc, cur);
  });
  const ctryList = Array.from(ctryAgg.values()).sort((a,b)=>b.bytes-a.bytes);

  view.innerHTML = `
    <div class="toolbar">
      <button class="btn-ghost" id="uid-back">← back</button>
      <h1 style="margin:0">UID <span class="mono" style="color:var(--accent)">${esc(uidLabel(u.uid))}</span></h1>
      <span class="pill dim">last hour</span>
    </div>

    <div class="hero">
      <div class="kpi"><div class="kpi-label">Bytes out</div><div class="kpi-value">${fmtBytes(u.bytesOut)}</div></div>
      <div class="kpi"><div class="kpi-label">Bytes in</div><div class="kpi-value">${fmtBytes(u.bytesIn)}</div></div>
      <div class="kpi"><div class="kpi-label">Binaries</div><div class="kpi-value">${u.bins.size}</div></div>
      <div class="kpi"><div class="kpi-label">Dests · Countries</div><div class="kpi-value">${u.dests.size} · ${ctryList.length}</div></div>
      <div class="kpi"><div class="kpi-label">Deny events</div><div class="kpi-value" style="color:${u.deny>0?'var(--err)':'inherit'}">${u.deny}</div></div>
    </div>

    <div class="grid grid-2" style="margin-bottom:12px">
      <div class="card">
        <div class="card-head"><h2>Binaries this user runs (${binArr.length})</h2><div class="right">by bytes-out</div></div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl"><thead><tr><th>Binary</th><th class="num">Bytes</th></tr></thead><tbody>
          ${binArr.map(x => `<tr class="clickable" data-bin="${esc(x.b)}">
            <td class="mono">${esc(x.b)}</td><td class="num">${fmtBytes(x.bytes)}</td>
          </tr>`).join('') || '<tr class="empty-row"><td colspan="2">no binaries</td></tr>'}
          </tbody></table>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Countries (${ctryList.length})</h2><div class="right">geo-resolved</div></div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl"><thead><tr><th>Country</th><th class="num">Bytes</th><th class="num">Dests</th></tr></thead><tbody>
          ${ctryList.map(c => `<tr class="clickable" data-country="${esc(c.cc)}">
            <td><span class="ip-cc" style="margin-right:6px">${esc(c.cc)}</span>${esc(countryName(c.cc))}</td>
            <td class="num">${fmtBytes(c.bytes)}</td>
            <td class="num dim">${c.dests}</td>
          </tr>`).join('') || '<tr class="empty-row"><td colspan="3">no country data</td></tr>'}
          </tbody></table>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h2>Top destinations (${destArr.length})</h2><div class="right">click IP for intel</div></div>
      <div class="tbl-wrap" style="border:0">
        <table class="tbl"><thead><tr><th>IP : Port</th><th>SNI / DNS</th><th>Country / ASN</th><th class="num">Bytes</th></tr></thead><tbody>
        ${destArr.slice(0,80).map(d => {
          const ip = (d.ip||'').split('/')[0];
          const meta = ctryByIP[d.ip] || {};
          return `<tr>
            <td class="mono"><a href="#" class="ip-link" data-ip="${esc(ip)}">${esc(d.ip)}</a>:${esc(d.port)}</td>
            <td class="mono dim">${esc(d.sni || d.dns || '—')}</td>
            <td>${meta.cc ? `<span class="ip-cc" style="margin-right:6px">${esc(meta.cc)}</span>${esc(meta.org||'')}` : '<span class="dim">—</span>'}</td>
            <td class="num">${fmtBytes(d.bytes)}</td>
          </tr>`;
        }).join('') || '<tr class="empty-row"><td colspan="4">no destinations</td></tr>'}
        </tbody></table>
      </div>
    </div>
  `;
  view.querySelector('#uid-back').addEventListener('click', () => { state.selectedUID = null; render(); });
  view.querySelectorAll('tr.clickable[data-bin]').forEach(tr =>
    tr.addEventListener('click', () => go('/egress/process/' + encodeURIComponent(tr.dataset.bin))));
  view.querySelectorAll('tr.clickable[data-country]').forEach(tr =>
    tr.addEventListener('click', () => { state.selectedCountry = tr.dataset.country; go('/egress/country/'+encodeURIComponent(tr.dataset.country)); }));
}

async function renderCgroups(view) {
  const rows = await fetchJSON('/api/egress/live') || [];
  const m = new Map();
  rows.forEach(r => {
    const k = r.Key || {}, mt = r.Metrics || {};
    const cg = k.CGroupID;
    const e = m.get(cg) || { cg, bytesOut:0, bytesIn:0, conns:0, bins:new Set() };
    e.bytesOut += mt.BytesOut||0; e.bytesIn += mt.BytesIn||0; e.conns += mt.Connects||0;
    e.bins.add(k.Binary);
    m.set(cg, e);
  });
  const list = Array.from(m.values()).sort((a,b) => b.bytesOut - a.bytesOut);
  view.innerHTML = `
    <h1>Per-cgroup</h1>
    <div class="subtitle">Aggregate egress by cgroup id.</div>
    <div class="tbl-wrap"><table class="tbl">
      <thead><tr><th>CGroup</th><th class="num">Bytes out</th><th class="num">Bytes in</th><th class="num">Conns</th><th class="num">Binaries</th></tr></thead>
      <tbody>${list.map(u => `<tr>
        <td class="mono">${esc(u.cg)}</td>
        <td class="num">${fmtBytes(u.bytesOut)}</td>
        <td class="num dim">${fmtBytes(u.bytesIn)}</td>
        <td class="num dim">${fmtNum(u.conns)}</td>
        <td class="num dim">${u.bins.size}</td>
      </tr>`).join('') || '<tr class="empty-row"><td colspan="5">no flows</td></tr>'}</tbody>
    </table></div>`;
}

async function renderDestinations(view) {
  const rows = await fetchJSON('/api/egress/live') || [];
  const m = new Map();
  rows.forEach(r => {
    const k = r.Key || {}, mt = r.Metrics || {};
    const key = (k.DestCIDR||'') + ':' + (k.DestPort||0);
    const e = m.get(key) || { dest:k.DestCIDR, port:k.DestPort, sni:k.SNI, dns:k.DNSName, cls:k.DestClass,
                              bytesOut:0, bytesIn:0, conns:0, deny:0, bins:new Set() };
    e.bytesOut += mt.BytesOut||0; e.bytesIn += mt.BytesIn||0; e.conns += mt.Connects||0;
    e.deny += mt.DenyEvents||0; e.bins.add(k.Binary);
    m.set(key, e);
  });
  const list = Array.from(m.values()).sort((a,b) => b.bytesOut - a.bytesOut);
  view.innerHTML = `
    <h1>Destinations</h1>
    <div class="subtitle">Grouped by (CIDR, port). ${list.length} unique.</div>
    <div class="tbl-wrap"><table class="tbl">
      <thead><tr><th>Destination</th><th>Port</th><th>SNI / DNS</th><th>Class</th><th class="num">Bytes</th><th class="num">Bins</th><th class="num">Deny</th></tr></thead>
      <tbody>${list.map(d => `<tr>
        <td class="mono">${esc(d.dest)}</td>
        <td class="mono">${esc(d.port)}</td>
        <td class="mono dim">${esc(d.sni || d.dns || '—')}</td>
        <td>${classPill(d.cls)}</td>
        <td class="num">${fmtBytes(d.bytesOut)}</td>
        <td class="num dim">${d.bins.size}</td>
        <td class="num" style="color:${d.deny>0?'var(--err)':'inherit'}">${d.deny}</td>
      </tr>`).join('') || '<tr class="empty-row"><td colspan="7">no flows</td></tr>'}</tbody>
    </table></div>`;
}

async function renderProtocols(view) {
  const rows = await fetchJSON('/api/egress/live?_=1' + visibilityParam()) || [];
  const m = new Map();
  rows.forEach(r => {
    const k = r.Key || {}, mt = r.Metrics || {};
    const proto = protocolOf(r);
    let e = m.get(proto);
    if (!e) {
      e = { proto, bytesOut:0, bytesIn:0, conns:0,
            dests:new Set(), bins:new Map(), destBytes:new Map() };
      m.set(proto, e);
    }
    e.bytesOut += mt.BytesOut||0;
    e.bytesIn += mt.BytesIn||0;
    e.conns += mt.Connects||0;
    e.dests.add(k.DestCIDR);
    const dk = k.DestCIDR + ':' + (k.DestPort||0);
    e.destBytes.set(dk, (e.destBytes.get(dk)||0) + (mt.BytesOut||0));
    e.bins.set(k.Binary, (e.bins.get(k.Binary)||0) + (mt.BytesOut||0));
  });
  const list = Array.from(m.values()).sort((a,b) => b.bytesOut - a.bytesOut);
  const total = list.reduce((s,p) => s + p.bytesOut, 0) || 1;

  function topOf(mp) {
    let bestK = '', bestV = 0;
    mp.forEach((v,k) => { if (v > bestV) { bestV = v; bestK = k; } });
    return bestK || '—';
  }

  // Inline horizontal bar / proportion chart (pie alternative — no SVG dep).
  const barHTML = list.map(p => {
    const pct = (p.bytesOut / total) * 100;
    const color = PROTO_COLOR[p.proto] || PROTO_COLOR.Other;
    return `<div style="display:flex;align-items:center;gap:8px;margin:4px 0">
      <div style="width:90px;font-family:var(--mono);font-size:11px">${esc(p.proto)}</div>
      <div style="flex:1;background:var(--bg-0);border-radius:3px;overflow:hidden;height:14px;border:1px solid var(--border)">
        <div style="width:${pct.toFixed(1)}%;background:${color};height:100%"></div>
      </div>
      <div style="width:90px;text-align:right;font-family:var(--mono);font-size:11px">${fmtBytes(p.bytesOut)}</div>
      <div style="width:50px;text-align:right;font-family:var(--mono);font-size:11px;color:var(--text-2)">${pct.toFixed(1)}%</div>
    </div>`;
  }).join('');

  view.innerHTML = `
    <div class="toolbar">
      <h1>Protocols</h1>
      <div class="spacer"></div>
      ${visibilityChip()}
      <span class="pill dim">${list.length} protocols · ${fmtBytes(total)} total</span>
    </div>
    <div class="card chart-card" style="margin-bottom:12px">
      <div class="card-head"><h2>Bytes-out by application protocol</h2><div class="right">SNI + port heuristic · 1h</div></div>
      ${barHTML || '<div class="placeholder"><strong>No outbound TCP/UDP observed in the last hour.</strong>Generate some traffic with <code>curl https://example.com</code> or wait for an app to talk.</div>'}
    </div>
    <div class="tbl-wrap"><table class="tbl">
      <thead><tr>
        <th>Protocol</th>
        <th class="num">Bytes out</th><th class="num">Bytes in</th>
        <th class="num">Flows</th><th class="num">Dests</th><th class="num">Binaries</th>
        <th>Top binary</th><th>Top dest</th>
      </tr></thead>
      <tbody>${list.map(p => `<tr>
        <td><span class="pill" style="background:${PROTO_COLOR[p.proto]||PROTO_COLOR.Other};color:#0b1018">${esc(p.proto)}</span></td>
        <td class="num">${fmtBytes(p.bytesOut)}</td>
        <td class="num dim">${fmtBytes(p.bytesIn)}</td>
        <td class="num dim">${fmtNum(p.conns)}</td>
        <td class="num dim">${p.dests.size}</td>
        <td class="num dim">${p.bins.size}</td>
        <td class="mono">${esc(topOf(p.bins))}</td>
        <td class="mono dim">${esc(topOf(p.destBytes))}</td>
      </tr>`).join('') || '<tr class="empty-row"><td colspan="8">no flows</td></tr>'}</tbody>
    </table></div>`;
  bindVisibility(view);
}

async function renderStorage(view) {
  const s = await fetchJSON('/api/egress/stats') || {};
  view.innerHTML = `
    <h1>Storage tiers</h1>
    <div class="subtitle">Hot ledger in-memory · warm SQLite · cold compressed CSV.</div>
    <div class="grid grid-4" style="margin-bottom:12px">
      <div class="kpi"><div class="kpi-label">Hot rows</div><div class="kpi-value">${fmtNum(s.HotRows)}</div><div class="kpi-sub">in-memory · last hour</div></div>
      <div class="kpi"><div class="kpi-label">Warm keys</div><div class="kpi-value">${fmtNum(s.WarmKeys)}</div><div class="kpi-sub">SQLite · 48h</div></div>
      <div class="kpi"><div class="kpi-label">Cold days</div><div class="kpi-value">${fmtNum(s.ColdDays)}</div><div class="kpi-sub">${fmtBytes(s.ColdBytes)} on disk</div></div>
      <div class="kpi"><div class="kpi-label">Observe count</div><div class="kpi-value">${fmtNum(s.ObserveCount)}</div><div class="kpi-sub">${fmtNum(s.DropEmptyCount)} dropped (empty)</div></div>
    </div>
    <div class="card">
      <div class="card-head"><h2>Lifecycle</h2><div class="right">retention ${esc(s.RetentionDays || 0)}d</div></div>
      <table class="tbl">
        <tbody>
          <tr><td>Last tick</td><td class="mono dim">${esc(s.LastTickAt || '—')}</td></tr>
          <tr><td>Last compact</td><td class="mono dim">${esc(s.LastCompactAt || '—')}</td></tr>
        </tbody>
      </table>
    </div>`;
}

async function renderSensors(view) {
  const s = await fetchJSON('/api/sensors') || [];
  view.innerHTML = `
    <h1>Sensors</h1>
    <div class="subtitle">Per-sensor health from the running daemon.</div>
    <div class="tbl-wrap"><table class="tbl">
      <thead><tr><th>Sensor</th><th>Status</th><th class="num">Events</th><th>Last error</th></tr></thead>
      <tbody>${(Array.isArray(s)?s:[]).map(x => `<tr>
        <td class="mono">${esc(x.name || x.Name)}</td>
        <td>${(x.healthy||x.Healthy)?'<span class="pill solid-ok">healthy</span>':'<span class="pill solid-err">unhealthy</span>'}</td>
        <td class="num dim">${fmtNum(x.events || x.Events || 0)}</td>
        <td class="mono dim">${esc(x.last_error || x.LastError || '—')}</td>
      </tr>`).join('') || '<tr class="empty-row"><td colspan="4">no sensors reported</td></tr>'}</tbody>
    </table></div>`;
}

// Policy index — Week 4. Lists binaries with observed activity in
// the last 14 days alongside their current policy mode (or "observe
// (default)" if none signed). Click [Review] to open the per-binary
// review pane.
async function renderPolicy(view) {
  // /api/egress/live returns the hot-tier flow snapshot (last 60 min)
  // with no per-binary param. Aggregate by binary for the index. Older
  // history requires a per-binary call so we surface "Review" to drill
  // into each one with the full 14-day window via /api/egress/policy/propose.
  const [observed, installed] = await Promise.all([
    fetchJSON('/api/egress/live').catch(() => []),
    fetchJSON('/api/egress/policy/list').catch(() => []),
  ]);
  const installedMap = {};
  (Array.isArray(installed)?installed:[]).forEach(sp => {
    const p = sp.policy || sp.Policy || sp;
    if (p && p.binary) installedMap[p.binary] = p;
  });
  const obsAgg = {};
  if (Array.isArray(observed)) {
    observed.forEach(r => {
      const b = (r.Key && r.Key.Binary) || r.binary;
      if (!b) return;
      const m = r.Metrics || r.metrics || {};
      const o = obsAgg[b] = obsAgg[b] || { binary: b, connects: 0, dests: new Set() };
      o.connects += (m.Connects || m.connects || 0);
      const cidr = (r.Key && r.Key.DestCIDR) || r.dest_cidr || '';
      const port = (r.Key && r.Key.DestPort) || r.dest_port || 0;
      o.dests.add(cidr + ':' + port);
    });
  }
  // Union of observed + installed binaries.
  const allBins = new Set([...Object.keys(obsAgg), ...Object.keys(installedMap)]);
  const rows = [...allBins].sort().map(b => {
    const o = obsAgg[b] || { connects: 0, dests: new Set() };
    const ip = installedMap[b];
    return { binary: b, connects: o.connects, distinct: o.dests.size, mode: ip ? ip.mode : 'observe (default)' };
  });
  view.innerHTML = `
    <div class="toolbar">
      <h1>Policy — observe → sign → enforce</h1>
      <div class="spacer"></div>
      <span class="pill info">${rows.length} binar${rows.length===1?'y':'ies'}</span>
    </div>
    <div class="subtitle">Default mode is <strong>observe</strong> until the operator signs a stricter policy. Sign once observed traffic looks like intended traffic.</div>
    <div class="card" style="padding:0">
      <table class="data-table">
        <thead><tr>
          <th>Binary</th><th class="num">Connects (live)</th><th class="num">Distinct dests</th><th>Current mode</th><th></th>
        </tr></thead>
        <tbody>
          ${rows.map(r => `<tr>
            <td class="mono">${esc(r.binary)}</td>
            <td class="num">${fmtNum(r.connects)}</td>
            <td class="num">${r.distinct}</td>
            <td><span class="pill ${r.mode==='deny_default'?'solid-err':r.mode==='allow_any'?'solid-ok':'info'}">${esc(r.mode)}</span></td>
            <td><button class="btn-primary" onclick="go('/egress/policy/review/${encodeURIComponent(r.binary)}')">Review</button></td>
          </tr>`).join('') || '<tr class="empty-row"><td colspan="5">no observed flows in the last 14 days — start traffic to populate the ledger</td></tr>'}
        </tbody>
      </table>
    </div>`;
}

// Policy review pane — Week 4. Fetches the per-binary Proposal,
// renders it as editable YAML, shows the currently-installed policy
// (if any), and lets the operator sign + install.
async function renderPolicyReview(view) {
  const binary = state.reviewBinary;
  if (!binary) {
    view.innerHTML = `<div class="placeholder"><strong>No binary selected</strong>Pick one from the policy index.</div>`;
    return;
  }
  view.innerHTML = `
    <div class="toolbar">
      <h1>Policy review</h1>
      <span class="pill info mono">${esc(binary)}</span>
      <div class="spacer"></div>
      <button class="btn-secondary" onclick="go('/egress/policy/process')">← back</button>
    </div>
    <div id="pr-status" class="subtitle">Fetching proposal…</div>
    <div class="card" id="pr-card" style="display:none">
      <div class="row">
        <div class="col" style="flex:2">
          <label><strong>Proposal (editable YAML)</strong></label>
          <textarea id="pr-yaml" rows="24" style="width:100%;font-family:monospace;font-size:12px"></textarea>
        </div>
        <div class="col" style="flex:1">
          <label><strong>Currently installed</strong></label>
          <pre id="pr-current" style="background:var(--bg-2);padding:8px;border-radius:4px;font-size:11px;max-height:600px;overflow:auto">(none)</pre>
        </div>
      </div>
      <div class="row" style="margin-top:12px;align-items:center;gap:8px">
        <label>Signer:</label>
        <input id="pr-signer" type="text" placeholder="operator-id" style="width:200px">
        <label>Private key (hex or base64):</label>
        <input id="pr-key" type="password" placeholder="ed25519 private key" style="flex:1">
        <button class="btn-primary" onclick="prSign('deny_default')">Sign + Install (deny_default)</button>
        <button class="btn-secondary" onclick="prSign('observe')">Sign + Install (observe)</button>
        <button class="btn-secondary" onclick="prSign('allow_any')">Sign + Install (allow_any)</button>
        <button class="btn-danger" onclick="prRevert()" id="pr-revert" style="display:none">Revert (delete)</button>
      </div>
      <div id="pr-banner" class="subtitle" style="margin-top:8px"></div>
    </div>`;
  // Fetch proposal and installed in parallel.
  let prop, current;
  try {
    const propResp = await fetch('/api/egress/policy/propose', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({binary, days: 14}),
    });
    if (!propResp.ok) throw new Error(await propResp.text());
    prop = await propResp.json();
  } catch (e) {
    document.getElementById('pr-status').innerHTML = `<span class="pill solid-err">propose failed</span> ${esc(e.message||e)}`;
    return;
  }
  try {
    const r = await fetch('/api/egress/policy/show?binary=' + encodeURIComponent(binary));
    if (r.ok) current = await r.json();
  } catch (_) { /* not installed — fine */ }

  document.getElementById('pr-status').textContent = '';
  document.getElementById('pr-card').style.display = '';
  // Pretty-print the proposal as YAML-ish (we don't have a JS YAML lib;
  // use JSON for editing — the daemon accepts JSON SignedPolicy on
  // install via the workflow path).
  state.currentProposal = prop;
  document.getElementById('pr-yaml').value = JSON.stringify(prop, null, 2);
  if (current) {
    document.getElementById('pr-current').textContent = JSON.stringify(current, null, 2);
    document.getElementById('pr-revert').style.display = '';
  }
}

// prSign builds a Policy from the edited proposal, asks the operator
// to confirm, then signs CLIENT-SIDE using WebCrypto Ed25519. Falls
// back to a clear error if WebCrypto Ed25519 isn't available (older
// browsers); operator can still use xhelixctl egress policy sign.
async function prSign(mode) {
  const signer = document.getElementById('pr-signer').value.trim();
  const keyRaw = document.getElementById('pr-key').value.trim();
  const banner = document.getElementById('pr-banner');
  if (!signer) { banner.innerHTML = `<span class="pill solid-err">signer required</span>`; return; }
  if (!keyRaw) { banner.innerHTML = `<span class="pill solid-err">private key required</span>`; return; }
  let prop;
  try {
    prop = JSON.parse(document.getElementById('pr-yaml').value);
  } catch (e) {
    banner.innerHTML = `<span class="pill solid-err">bad JSON</span> ${esc(e.message||e)}`;
    return;
  }
  prop.suggested_mode = mode;
  // Browsers don't yet ship a stable Ed25519 in WebCrypto everywhere,
  // so we ship the proposal to a daemon-side sign endpoint is the
  // pragmatic answer. For Week 4 the daemon does not expose a sign
  // RPC (operator keys must never leave the operator's machine), so
  // direct in-browser signing is the only honest option. Defer to
  // xhelixctl when this fails.
  try {
    const sp = await signProposalInBrowser(prop, signer, keyRaw);
    const r = await fetch('/api/egress/policy/install', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(sp),
    });
    if (!r.ok) throw new Error(await r.text());
    const resp = await r.json();
    banner.innerHTML = `<span class="pill solid-ok">installed ${esc(resp.installed)} (loaded total: ${resp.loaded_total}) — daemon enforces within 30s</span>`;
  } catch (e) {
    banner.innerHTML = `<span class="pill solid-err">sign failed</span> ${esc(e.message||e)} — fallback: <code>xhelixctl egress policy sign &amp;&amp; install</code>`;
  }
}

// signProposalInBrowser — Ed25519 signing via WebCrypto. The key must
// be a 64-byte (PKCS#8-equivalent seed||pub) ed25519 private key.
// Browsers vary on Ed25519 support; throw a clear error if missing.
async function signProposalInBrowser(prop, signer, keyRaw) {
  if (!crypto.subtle || !crypto.subtle.sign) {
    throw new Error('WebCrypto unavailable — use xhelixctl egress policy sign');
  }
  // Build the Policy object the daemon expects.
  const allow = (prop.allow || []).map(r => {
    const out = {};
    if (r.dest_cidr) out.dest_cidr = r.dest_cidr;
    if (r.dest_class) out.dest_class = r.dest_class;
    if (r.sni) out.sni = r.sni;
    if (r.dns_name) out.dns_name = r.dns_name;
    if (r.dest_port) out.ports = [r.dest_port];
    if (r.protocol) out.protocols = [r.protocol];
    if (r.reason) out.comment = r.reason;
    return out;
  });
  const pol = {
    schema_version: 1,
    binary: prop.binary,
    mode: prop.suggested_mode || 'observe',
    signed_at: new Date().toISOString(),
    signer: signer,
    allow: allow,
  };
  // Canonical YAML signing is what the daemon's Verify() does. The
  // browser doesn't have a YAML lib; rely on the server-side sign
  // path via xhelixctl. For Week 4 we report a clear error so the
  // operator switches to CLI signing without confusion.
  throw new Error('browser-side YAML canonical signing not implemented — use xhelixctl egress policy sign');
}

async function prRevert() {
  const binary = state.reviewBinary;
  if (!binary) return;
  if (!confirm('Delete signed policy for ' + binary + '? Binary returns to default observe mode.')) return;
  try {
    const r = await fetch('/api/egress/policy/delete', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({binary}),
    });
    if (!r.ok) throw new Error(await r.text());
    const resp = await r.json();
    document.getElementById('pr-banner').innerHTML =
      `<span class="pill solid-ok">reverted ${esc(resp.deleted)} (loaded total: ${resp.loaded_total})</span>`;
  } catch (e) {
    document.getElementById('pr-banner').innerHTML =
      `<span class="pill solid-err">revert failed</span> ${esc(e.message||e)}`;
  }
}

function renderStub(view) {
  view.innerHTML = `
    <h1>Coming soon</h1>
    <div class="placeholder">
      <strong>This pane lands Week 5-6.</strong>
      Backend wiring is in place; UI pending.
    </div>`;
}

// ─── PID forensics — /egress/pid/<pid> ────────────────────────

async function renderPid(view) {
  if (!state.selectedPID) {
    view.innerHTML = `<div class="placeholder"><strong>No PID selected.</strong>Use the process detail page or Cmd-K search.</div>`;
    return;
  }
  const pid = state.selectedPID;
  const d = await fetchJSON('/api/egress/pid?pid=' + encodeURIComponent(pid));
  if (!d) {
    view.innerHTML = `<div class="placeholder"><strong>PID lookup failed.</strong></div>`;
    return;
  }
  if (!d.found) {
    view.innerHTML = `<div class="placeholder"><strong>PID ${esc(pid)} unknown.</strong>It may have exited before xhelix saw it.</div>`;
    return;
  }
  const status = d.live
    ? '<span class="pill" style="background:#0d2818;color:#86efac">alive</span>'
    : '<span class="pill" style="background:#2a0d0d;color:#fca5a5">exited</span>';
  const ancStr = (d.ancestors || []).map(a => `<span class="mono">[${esc(a.pid)}] ${esc(a.comm||'?')}</span>`).join(' ← ') || '<span class="dim">no ancestor chain</span>';
  const fmtTm = t => t ? new Date(t).toISOString().replace('T',' ').slice(0,19) : '?';
  const liveRows = (d.live_dests||[]).map(x => `<tr>
    <td class="mono"><a href="#" class="ip-link" data-ip="${esc(x.dst_addr)}">${esc(x.dst_addr)}</a>:${esc(x.dst_port)}</td>
    <td>${x.country?`<span class="ip-cc" style="margin-right:4px">${esc(x.country)}</span>${esc(countryName(x.country))}`:'<span class="dim">—</span>'}</td>
    <td class="mono dim">${esc(x.asn||'')}</td>
    <td class="mono dim">${esc(x.sni||'')}</td>
    <td class="mono dim">${esc(x.state||'')}</td>
    <td class="num">${fmtBytes(x.bytes_out)}</td>
    <td class="num dim">${fmtBytes(x.bytes_in)}</td>
  </tr>`).join('') || '<tr class="empty-row"><td colspan="7">no live sockets — process closed all connections</td></tr>';
  const histRows = (d.historical_dests||[]).map(x => `<tr>
    <td class="mono"><a href="#" class="ip-link" data-ip="${esc(x.dst_ip)}">${esc(x.dst_ip)}</a>:${esc(x.dst_port)}</td>
    <td>${x.country?`<span class="ip-cc">${esc(x.country)}</span>`:''}</td>
    <td class="num">${fmtBytes(x.bytes_out)}</td>
    <td class="num dim">${fmtBytes(x.bytes_in)}</td>
    <td class="mono dim">${esc(fmtTm(x.first_seen).slice(11,19))} → ${esc(fmtTm(x.last_seen).slice(11,19))}</td>
  </tr>`).join('') || '<tr class="empty-row"><td colspan="5">no historical observations in last 24h</td></tr>';
  const alertRows = (d.related_alerts||[]).map(a => `<tr>
    <td class="mono dim">${esc(fmtTm(a.time).slice(11,19))}</td>
    <td class="mono">${esc(a.rule_id||'?')}</td>
    <td class="mono">${a.dst_ip?`<a href="#" class="ip-link" data-ip="${esc(a.dst_ip)}">${esc(a.dst_ip)}</a>`:''}</td>
    <td class="dim">${esc(a.reason||'')}</td>
  </tr>`).join('') || '<tr class="empty-row"><td colspan="4">no alerts referencing this PID</td></tr>';

  view.innerHTML = `
    <div class="toolbar">
      <button class="btn-ghost" id="pid-back">← back</button>
      <h1 style="margin:0">PID <span class="mono" style="color:var(--accent)">${esc(d.pid)}</span> <span class="dim" style="font-size:14px">${esc(d.comm||'?')}</span></h1>
      ${status}
      <div class="spacer"></div>
      ${d.exe ? `<button class="btn-ghost" id="pid-open-bin">▸ Binary page</button>` : ''}
    </div>

    <div class="card" style="margin-bottom:12px">
      <div class="card-head"><h2>Process metadata</h2></div>
      <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px 24px;padding:10px 14px">
        <div><span class="kpi-label">EXE</span><div class="mono">${esc(d.exe||'?')}</div></div>
        <div><span class="kpi-label">CMDLINE</span><div class="mono">${esc(d.cmdline||'?')}</div></div>
        <div><span class="kpi-label">CWD</span><div class="mono">${esc(d.cwd||'?')}</div></div>
        <div><span class="kpi-label">USER</span><div class="mono">${esc(d.username||'uid '+d.uid)}</div></div>
        <div><span class="kpi-label">STARTED</span><div class="mono">${esc(fmtTm(d.started_at))}</div></div>
        <div><span class="kpi-label">AGE</span><div class="mono">${esc(Math.floor((d.age_seconds||0)/60))}m ${esc((d.age_seconds||0)%60)}s</div></div>
        <div><span class="kpi-label">UNIT</span><div class="mono">${esc(d.unit||'')}</div></div>
        <div><span class="kpi-label">PPID</span><div class="mono">${esc(d.ppid||0)} (${esc(d.parent_comm||'?')})</div></div>
        <div><span class="kpi-label">OPEN SOCKETS</span><div class="mono">${esc(d.open_sockets||0)}</div></div>
        <div><span class="kpi-label">LISTENS</span><div class="mono">${(d.listen_ports||[]).join(', ')||'—'}</div></div>
      </div>
      <div style="padding:10px 14px;border-top:1px solid var(--border)">
        <span class="kpi-label">ANCESTOR CHAIN</span>
        <div style="margin-top:6px;font-size:12px">${ancStr}</div>
      </div>
      ${d.cgroup_path ? `<div style="padding:10px 14px;border-top:1px solid var(--border)">
        <span class="kpi-label">CGROUP</span>
        <div class="mono" style="font-size:11px;margin-top:4px;color:var(--text-1)">${esc(d.cgroup_path)}</div>
      </div>` : ''}
    </div>

    <div class="card" style="margin-bottom:12px">
      <div class="card-head"><h2>Live sockets (${esc((d.live_dests||[]).length)})</h2><div class="right">from connstate</div></div>
      <div class="tbl-wrap" style="border:0">
        <table class="tbl"><thead><tr><th>Destination</th><th>Country</th><th>ASN</th><th>SNI</th><th>State</th><th class="num">Out</th><th class="num">In</th></tr></thead>
        <tbody>${liveRows}</tbody></table>
      </div>
    </div>

    <div class="card" style="margin-bottom:12px">
      <div class="card-head"><h2>Historical destinations (${esc((d.historical_dests||[]).length)})</h2><div class="right">last 24h via recent ring</div></div>
      <div class="tbl-wrap" style="border:0">
        <table class="tbl"><thead><tr><th>Destination</th><th>Country</th><th class="num">Out</th><th class="num">In</th><th>Window</th></tr></thead>
        <tbody>${histRows}</tbody></table>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h2>Related alerts (${esc((d.related_alerts||[]).length)})</h2></div>
      <div class="tbl-wrap" style="border:0">
        <table class="tbl"><thead><tr><th>Time</th><th>Rule</th><th>Dest</th><th>Reason</th></tr></thead>
        <tbody>${alertRows}</tbody></table>
      </div>
    </div>
  `;
  view.querySelector('#pid-back').addEventListener('click', () => history.back());
  const ob = view.querySelector('#pid-open-bin');
  if (ob && d.comm) ob.addEventListener('click', () => go('/egress/process/' + encodeURIComponent(d.comm)));
  view.querySelectorAll('.ip-link').forEach(a => {
    a.addEventListener('click', (e) => { e.preventDefault(); go('/egress/ip/' + encodeURIComponent(a.dataset.ip)); });
  });
}

// ─── Verdict — /egress/verdict ────────────────────────────────

async function renderVerdict(view) {
  const v = await fetchJSON('/api/egress/verdict');
  if (!v) { view.innerHTML = '<div class="placeholder"><strong>Verdict unavailable.</strong></div>'; return; }
  const verdictColor = { good:'#86efac', watch:'#facc15', concerning:'#fb923c', critical:'#fca5a5' }[v.verdict] || '#9ca3af';
  const verdictBg    = { good:'#0d2818', watch:'#1a1a0d', concerning:'#2a1f0d', critical:'#2a0d0d' }[v.verdict] || '#1a1f27';
  const dial = `<div style="position:relative;width:140px;height:140px;flex:none">
    <svg viewBox="0 0 100 100" style="width:100%;height:100%;transform:rotate(-90deg)">
      <circle cx="50" cy="50" r="42" fill="none" stroke="#1a1f27" stroke-width="8"/>
      <circle cx="50" cy="50" r="42" fill="none" stroke="${verdictColor}" stroke-width="8"
        stroke-dasharray="${(v.health_score/100*264).toFixed(1)} 264" stroke-linecap="round"/>
    </svg>
    <div style="position:absolute;inset:0;display:grid;place-items:center;flex-direction:column">
      <div style="font-size:34px;font-weight:800;color:${verdictColor};line-height:1">${esc(v.health_score)}</div>
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:1.2px;color:var(--text-2);margin-top:2px">${esc(v.verdict)}</div>
    </div>
  </div>`;
  const notes = (v.notes||[]).map(n => `<li style="margin:3px 0">${esc(n)}</li>`).join('');
  const ctryRows = (v.top_countries_pct||[]).map(c => `<tr class="clickable" data-country="${esc(c.country)}">
    <td><span class="ip-cc" style="margin-right:6px">${esc(c.country)}</span>${esc(countryName(c.country))}</td>
    <td class="num">${esc(c.pct.toFixed(1))}%</td>
    <td class="num dim">${fmtBytes(c.bytes)}</td>
  </tr>`).join('') || '<tr class="empty-row"><td colspan="3">no country data</td></tr>';
  const riskRows = (v.top_risk_apps||[]).map(a => `<tr class="clickable" data-bin="${esc(a.binary)}">
    <td class="mono">${esc(a.binary)}</td>
    <td class="dim">${esc(a.reason)}</td>
    <td class="num">${fmtBytes(a.bytes)}</td>
    <td class="num">${a.alerts>0?`<span style="color:var(--err)">${esc(a.alerts)}</span>`:'0'}</td>
    <td class="num">${a.blocked>0?`<span style="color:var(--err)">${esc(a.blocked)}</span>`:'0'}</td>
  </tr>`).join('') || '<tr class="empty-row"><td colspan="5">no high-risk apps</td></tr>';

  view.innerHTML = `
    <div class="toolbar">
      <h1 style="margin:0">Verdict</h1>
      <span class="pill dim">global posture — last 24h</span>
    </div>

    <div class="card" style="margin-bottom:14px;border-left:3px solid ${verdictColor};background:${verdictBg}">
      <div style="display:flex;align-items:center;gap:24px;padding:14px 20px">
        ${dial}
        <div style="flex:1">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:1.2px;color:var(--text-2)">Network posture</div>
          <div style="font-size:24px;font-weight:700;color:${verdictColor};text-transform:capitalize;margin-top:2px">${esc(v.verdict)}</div>
          ${notes ? `<ul style="margin:10px 0 0;padding-left:22px;color:var(--text-1);font-size:13px">${notes}</ul>` : ''}
        </div>
      </div>
    </div>

    <div class="hero">
      <div class="kpi"><div class="kpi-label">Active apps</div><div class="kpi-value">${fmtNum(v.active_apps)}</div><div class="kpi-sub">of ${esc(v.total_apps)} known</div></div>
      <div class="kpi"><div class="kpi-label">Sent 24h</div><div class="kpi-value">${fmtBytes(v.bytes_out_24h)}</div><div class="kpi-sub">${fmtBytes(v.bytes_out_1h)} in last hour</div></div>
      <div class="kpi"><div class="kpi-label">Recv 24h</div><div class="kpi-value">${fmtBytes(v.bytes_in_24h)}</div><div class="kpi-sub">${fmtBytes(v.bytes_in_1h)} in last hour</div></div>
      <div class="kpi"><div class="kpi-label">Blocked 24h</div><div class="kpi-value" style="color:${v.blocked_count_24h>0?'var(--err)':'inherit'}">${fmtNum(v.blocked_count_24h)}</div></div>
      <div class="kpi"><div class="kpi-label">Open alerts</div><div class="kpi-value" style="color:${v.open_alerts_count>0?'var(--warn)':'inherit'}">${fmtNum(v.open_alerts_count)}</div><div class="kpi-sub">cls1=${esc(v.alerts_by_class?.[1]||0)} cls2=${esc(v.alerts_by_class?.[2]||0)} cls3=${esc(v.alerts_by_class?.[3]||0)}</div></div>
      <div class="kpi"><div class="kpi-label">Countries</div><div class="kpi-value">${fmtNum(v.distinct_countries)}</div></div>
    </div>

    <div class="card" style="margin:14px 0">
      <div class="card-head"><h2>Direction breakdown</h2><div class="right">share of 1h bytes-out</div></div>
      <div style="padding:14px;display:grid;grid-template-columns:repeat(3,1fr);gap:14px">
        <div>
          <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--text-2)"><span>Outbound</span><span class="mono">${esc(v.outbound_pct.toFixed(1))}%</span></div>
          <div style="height:8px;background:#1a1f27;border-radius:4px;margin-top:6px;overflow:hidden"><div style="width:${esc(v.outbound_pct)}%;height:100%;background:#60a5fa;border-radius:4px"></div></div>
        </div>
        <div>
          <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--text-2)"><span>Inbound reply</span><span class="mono">${esc(v.inbound_reply_pct.toFixed(1))}%</span></div>
          <div style="height:8px;background:#1a1f27;border-radius:4px;margin-top:6px;overflow:hidden"><div style="width:${esc(v.inbound_reply_pct)}%;height:100%;background:#facc15;border-radius:4px"></div></div>
        </div>
        <div>
          <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--text-2)"><span>Unknown</span><span class="mono">${esc(v.unknown_dir_pct.toFixed(1))}%</span></div>
          <div style="height:8px;background:#1a1f27;border-radius:4px;margin-top:6px;overflow:hidden"><div style="width:${esc(v.unknown_dir_pct)}%;height:100%;background:#6b7280;border-radius:4px"></div></div>
        </div>
      </div>
    </div>

    <div class="grid grid-2" style="margin-bottom:12px">
      <div class="card">
        <div class="card-head"><h2>Top countries (24h)</h2><div class="right">share</div></div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl"><thead><tr><th>Country</th><th class="num">Share</th><th class="num">Bytes</th></tr></thead><tbody>${ctryRows}</tbody></table>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Top risk apps</h2><div class="right">by alerts + blocked + volume</div></div>
        <div class="tbl-wrap" style="border:0">
          <table class="tbl"><thead><tr><th>Binary</th><th>Reason</th><th class="num">Bytes</th><th class="num">Alerts</th><th class="num">Blocked</th></tr></thead><tbody>${riskRows}</tbody></table>
        </div>
      </div>
    </div>
  `;
  view.querySelectorAll('tr.clickable[data-country]').forEach(tr => tr.addEventListener('click', () => { state.selectedCountry = tr.dataset.country; go('/egress/country/'+encodeURIComponent(tr.dataset.country)); }));
  view.querySelectorAll('tr.clickable[data-bin]').forEach(tr => tr.addEventListener('click', () => go('/egress/process/' + encodeURIComponent(tr.dataset.bin))));
}

// ─── Universal search (Cmd-K / Ctrl-K) ───────────────────────

function setupUniversalSearch() {
  if (document.getElementById('cmdk-modal')) return;
  const modal = document.createElement('div');
  modal.id = 'cmdk-modal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:9999;display:none;align-items:flex-start;justify-content:center;padding-top:14vh;backdrop-filter:blur(4px)';
  modal.innerHTML = `
    <div style="background:var(--bg-1);border:1px solid var(--border);border-radius:10px;width:560px;max-width:92vw;box-shadow:0 30px 80px rgba(0,0,0,0.5);overflow:hidden">
      <div style="display:flex;align-items:center;padding:14px 16px;border-bottom:1px solid var(--border);gap:10px">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px;color:var(--text-2)"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input id="cmdk-input" placeholder="Binary · IP · PID · ASN · country code …" autofocus
          style="flex:1;background:transparent;border:0;outline:0;color:var(--text-0);font-size:15px;font-family:inherit" />
        <span style="font-size:11px;color:var(--text-2);font-family:var(--mono)">esc</span>
      </div>
      <div id="cmdk-results" style="max-height:320px;overflow-y:auto;padding:6px"></div>
      <div style="padding:8px 16px;border-top:1px solid var(--border);font-size:11px;color:var(--text-2);font-family:var(--mono)">
        try: <code>nginx</code> · <code>156.59.197.102</code> · <code>2871220</code> · <code>HK</code> · <code>AS21859</code>
      </div>
    </div>`;
  document.body.appendChild(modal);
  const $input = modal.querySelector('#cmdk-input');
  const $res = modal.querySelector('#cmdk-results');

  function open() { modal.style.display = 'flex'; setTimeout(()=>$input.focus(), 10); render(''); }
  function close(){ modal.style.display = 'none'; $input.value=''; }
  modal.addEventListener('click', (e) => { if (e.target === modal) close(); });

  function render(q) {
    q = (q||'').trim();
    if (!q) {
      $res.innerHTML = `<div style="padding:18px;color:var(--text-2);font-size:13px;text-align:center">type to search…</div>`;
      return;
    }
    const items = [];
    // PID (all digits)
    if (/^\d+$/.test(q)) {
      items.push({ kind:'PID', label:'PID '+q, sub:'open forensic page', route:'/egress/pid/'+encodeURIComponent(q) });
    }
    // IP (rough match)
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(q) || q.includes(':')) {
      items.push({ kind:'IP',  label:q, sub:'open IP intel', route:'/egress/ip/'+encodeURIComponent(q) });
    }
    // 2-letter uppercase country code
    if (/^[A-Za-z]{2}$/.test(q)) {
      const cc = q.toUpperCase();
      items.push({ kind:'CC', label:cc+' — '+(typeof countryName==='function'?countryName(cc):cc), sub:'country drilldown', route:'/egress/country/'+encodeURIComponent(cc) });
    }
    // ASN form
    if (/^AS\d+$/i.test(q)) {
      items.push({ kind:'ASN', label:q.toUpperCase(), sub:'ASN — filtered companies view', route:'/egress/companies' });
    }
    // Default: treat as binary name
    items.push({ kind:'BIN', label:q, sub:'open per-process page', route:'/egress/process/'+encodeURIComponent(q) });

    $res.innerHTML = items.map((it, i) => `<div class="cmdk-item${i===0?' active':''}" data-route="${esc(it.route)}"
      style="display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:6px;cursor:pointer">
      <span style="font-family:var(--mono);font-size:10px;color:#111;background:var(--accent);padding:2px 7px;border-radius:4px;font-weight:700">${esc(it.kind)}</span>
      <div style="flex:1;min-width:0">
        <div style="font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(it.label)}</div>
        <div style="font-size:11px;color:var(--text-2)">${esc(it.sub)}</div>
      </div>
      <span style="color:var(--text-2);font-size:11px">↵</span>
    </div>`).join('');
    $res.querySelectorAll('.cmdk-item').forEach(el => {
      el.addEventListener('mouseenter', () => { $res.querySelectorAll('.cmdk-item').forEach(x => x.classList.remove('active')); el.classList.add('active'); });
      el.addEventListener('click', () => { close(); go(el.dataset.route); });
    });
  }
  $input.addEventListener('input', () => render($input.value));
  $input.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { close(); return; }
    if (e.key === 'Enter') {
      const a = $res.querySelector('.cmdk-item.active') || $res.querySelector('.cmdk-item');
      if (a) { close(); go(a.dataset.route); }
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const items = Array.from($res.querySelectorAll('.cmdk-item'));
      if (!items.length) return;
      let idx = items.findIndex(x => x.classList.contains('active'));
      idx = e.key === 'ArrowDown' ? Math.min(items.length-1, idx+1) : Math.max(0, idx-1);
      items.forEach((x,i) => x.classList.toggle('active', i===idx));
    }
  });

  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); open(); }
    else if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
      e.preventDefault(); open();
    } else if (e.key === 'Escape' && modal.style.display === 'flex') {
      close();
    }
  });
  // Click handle for sidebar Search if present
  const navSearch = document.querySelector('[data-route="search"]');
  if (navSearch) navSearch.addEventListener('click', open);
}
setupUniversalSearch();

// ─── TLS plaintext (Phase TLS-L2, opt-in) ───────────────────────

async function renderTLSPlaintext(view) {
  const stats = await fetchJSON('/api/tls/plaintext/stats');
  const enabled = stats && stats.enabled;
  view.innerHTML = `
    <h1>TLS plaintext <span style="background:#a00;color:#fff;font-size:10px;padding:2px 6px;border-radius:3px;">BETA</span></h1>
    <div class="placeholder" style="border-left:3px solid #c33;background:#2a1010;color:#fcc;">
      <strong>Sensitive data — every view is audited.</strong>
      Records are written to <code>/var/log/xhelix/tls-plaintext-access.log</code>
      on the daemon. <code>Authorization</code> / <code>Cookie</code> / <code>Set-Cookie</code>
      / <code>X-Auth-*</code> / <code>X-Api-Key</code> / <code>X-Csrf-Token</code>
      / <code>X-Session-Id</code> headers are redacted. JSON fields named
      <code>password</code> / <code>token</code> / <code>api_key</code> / <code>secret</code>
      / <code>credentials</code> / <code>access_token</code> / <code>refresh_token</code>
      / <code>session_id</code> are redacted. Bodies are capped per record.
    </div>

    <div class="cards" style="display:flex;gap:12px;margin:12px 0;">
      <div class="card" style="flex:1;padding:12px;border:1px solid #333;">
        <div style="font-size:11px;color:#888;">STATUS</div>
        <div style="font-size:18px;color:${enabled?'#0f0':'#f80'};">${enabled?'ENABLED':'DISABLED'}</div>
      </div>
      <div class="card" style="flex:1;padding:12px;border:1px solid #333;">
        <div style="font-size:11px;color:#888;">STORED</div>
        <div style="font-size:18px;">${enabled?(stats.stats.stored||0):'—'}</div>
      </div>
      <div class="card" style="flex:1;padding:12px;border:1px solid #333;">
        <div style="font-size:11px;color:#888;">OBSERVED</div>
        <div style="font-size:18px;">${enabled?(stats.stats.observed_total||0):'—'}</div>
      </div>
      <div class="card" style="flex:1;padding:12px;border:1px solid #333;">
        <div style="font-size:11px;color:#888;">DROPPED (not allowed)</div>
        <div style="font-size:18px;">${enabled?(stats.stats.dropped_not_allowed||0):'—'}</div>
      </div>
    </div>

    <h2>Allow-list (per-binary opt-in)</h2>
    <div id="tls-allow-block">loading…</div>

    <h2 style="margin-top:24px;">Recent records</h2>
    <div id="tls-records-block">loading…</div>
  `;
  if (!enabled) {
    document.getElementById('tls-allow-block').innerHTML =
      '<div class="placeholder">Ledger disabled. Set <code>tls_plaintext.enabled: true</code> + <code>tls_plaintext.allowed_binaries</code> in <code>/etc/xhelix/xhelix.yaml</code>, then restart the daemon.</div>';
    document.getElementById('tls-records-block').innerHTML = '';
    return;
  }
  await renderTLSAllowList();
  await renderTLSRecords();
}

async function renderTLSAllowList() {
  const list = await fetchJSON('/api/tls/plaintext/allowlist') || [];
  const block = document.getElementById('tls-allow-block');
  if (!block) return;
  const rows = list.length === 0
    ? '<tr><td colspan="2" style="color:#888;">(no binaries opted in)</td></tr>'
    : list.map(b => `<tr>
        <td>${esc(b)}</td>
        <td><button data-tls-remove="${esc(b)}" class="btn-ghost">remove</button></td>
      </tr>`).join('');
  block.innerHTML = `
    <table>
      <thead><tr><th>BINARY</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <div style="margin-top:8px;">
      <input id="tls-allow-input" placeholder="/usr/bin/curl" style="padding:6px;width:300px;">
      <button id="tls-allow-add" class="btn-ghost">add opt-in</button>
    </div>
  `;
  document.getElementById('tls-allow-add').onclick = async () => {
    const v = document.getElementById('tls-allow-input').value.trim();
    if (!v) return;
    await tlsAllowAction(v, 'add');
    await renderTLSAllowList();
  };
  block.querySelectorAll('[data-tls-remove]').forEach(b => {
    b.onclick = async () => {
      await tlsAllowAction(b.getAttribute('data-tls-remove'), 'remove');
      await renderTLSAllowList();
    };
  });
}

async function tlsAllowAction(binary, action) {
  try {
    await fetch('/api/tls/plaintext/allow', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({binary, action}),
    });
  } catch (e) { console.error('tls allow', e); }
}

async function renderTLSRecords() {
  const recs = await fetchJSON('/api/tls/plaintext/list?n=50') || [];
  const block = document.getElementById('tls-records-block');
  if (!block) return;
  if (recs.length === 0) {
    block.innerHTML = '<div class="placeholder">No records yet. Make a TLS call from an opted-in binary, then refresh.</div>';
    return;
  }
  const rows = recs.map(r => {
    const mp = r.http_method ? `${esc(r.http_method)} ${esc((r.http_path||'').slice(0,40))}` : '—';
    const preview = (r.body_text||'').slice(0, 80).replace(/\n/g,' ');
    return `<tr>
      <td>${esc(new Date(r.time).toLocaleTimeString())}</td>
      <td>${esc(r.direction||'')}</td>
      <td>${esc(r.binary||'')}</td>
      <td>${esc((r.peer_sni||'')+(r.peer_port?':'+r.peer_port:''))}</td>
      <td>${mp}</td>
      <td>${r.http_status||''}</td>
      <td><code>${esc(preview)}${preview.length>=80?'…':''}</code></td>
      <td><button data-tls-view="${esc(r.id)}" class="btn-ghost">view full</button></td>
    </tr>`;
  }).join('');
  block.innerHTML = `
    <table>
      <thead><tr>
        <th>TIME</th><th>DIR</th><th>BINARY</th><th>SNI</th>
        <th>METHOD / PATH</th><th>STATUS</th><th>BODY (first 80)</th><th></th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
  block.querySelectorAll('[data-tls-view]').forEach(b => {
    b.onclick = () => tlsViewRecord(b.getAttribute('data-tls-view'));
  });
}

async function tlsViewRecord(id) {
  const r = await fetchJSON('/api/tls/plaintext/get?id=' + encodeURIComponent(id));
  if (!r) return;
  const headers = r.headers ? Object.entries(r.headers)
    .map(([k,v]) => `<tr><td><b>${esc(k)}</b></td><td>${esc(v)}</td></tr>`).join('') : '';
  openDrawer('TLS record ' + id, `
    <div style="margin-bottom:8px;color:#f88;font-size:11px;">
      This view was audited. Treat the contents as a credential dump.
    </div>
    <table>
      <tr><td><b>time</b></td><td>${esc(new Date(r.time).toISOString())}</td></tr>
      <tr><td><b>binary</b></td><td>${esc(r.binary)}</td></tr>
      <tr><td><b>pid</b></td><td>${r.pid}</td></tr>
      <tr><td><b>direction</b></td><td>${esc(r.direction)}</td></tr>
      <tr><td><b>peer</b></td><td>${esc(r.peer_sni||'')} (${esc(r.peer_ip||'')}:${r.peer_port||0})</td></tr>
      <tr><td><b>http</b></td><td>${esc(r.http_method||'')} ${esc(r.http_path||'')} → ${r.http_status||'-'}</td></tr>
      <tr><td><b>body_bytes</b></td><td>${r.body_bytes} ${r.truncated?'<span style="color:#f80;">(truncated)</span>':''}</td></tr>
    </table>
    <h3>Headers (sensitive redacted)</h3>
    <table>${headers}</table>
    <h3>Body</h3>
    <pre style="background:#111;padding:8px;white-space:pre-wrap;word-break:break-all;max-height:400px;overflow:auto;">${esc(r.body_text||'')}</pre>
  `);
}

// ─── Drawer ───────────────────────────────────────────────────

function openDrawer(title, html) {
  document.getElementById('drawer-title').textContent = title;
  document.getElementById('drawer-body').innerHTML = html;
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-scrim').classList.add('open');
}
function closeDrawer() {
  document.getElementById('drawer').classList.remove('open');
  document.getElementById('drawer-scrim').classList.remove('open');
}

// ─── Wiring ───────────────────────────────────────────────────

window.addEventListener('DOMContentLoaded', () => {
  loadPrefs();

  // Sidebar nav.
  document.querySelectorAll('.nav-item').forEach(el => {
    el.addEventListener('click', e => { e.preventDefault(); go(el.dataset.route); });
  });

  // Range picker.
  document.querySelectorAll('.range-picker .rng').forEach(b => {
    if (parseInt(b.dataset.hours, 10) === state.hours) {
      document.querySelectorAll('.range-picker .rng').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
    }
    b.addEventListener('click', () => {
      state.hours = parseInt(b.dataset.hours, 10);
      document.querySelectorAll('.range-picker .rng').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      savePrefs(); render();
    });
  });

  // Pause — also dim the refresh indicator while paused so the
  // operator can tell from peripheral vision that auto-refresh is off.
  document.getElementById('pause-btn').addEventListener('click', () => {
    state.paused = !state.paused;
    document.getElementById('pause-btn').textContent = state.paused ? '▶ Resume' : '⏸ Pause';
    const ind = document.getElementById('refresh-ind');
    if (ind) ind.style.opacity = state.paused ? '0.4' : '';
  });

  // Drawer.
  document.getElementById('drawer-close').addEventListener('click', closeDrawer);
  document.getElementById('drawer-scrim').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

  // History.
  window.addEventListener('popstate', () => {
    state.route = location.pathname || '/egress';
    render();
  });

  // Delegated click handler for in-app navigation links (IP chips,
  // flow rows). Honors browser modifiers: middle-click, ctrl-click,
  // cmd-click, shift-click all fall through to the browser so the
  // operator can open deep-analysis in a new tab (their explicit
  // ask). Only plain left-click is intercepted to call go().
  document.addEventListener('click', e => {
    if (e.button !== 0) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const a = e.target.closest && e.target.closest('a[data-ip-link], a[data-flow-link]');
    if (!a) return;
    const href = a.getAttribute('href');
    if (!href || !href.startsWith('/egress/')) return;
    e.preventDefault();
    go(href);
  });

  // Capture-loss banner: poll independently of the per-route refresh so it
  // stays current on every page. Honors pause + hidden-tab like the main
  // refresh loop.
  refreshCaptureLoss();
  setInterval(() => {
    if (state.paused || document.hidden) return;
    refreshCaptureLoss();
  }, 5000);

  // Host info best-effort.
  try {
    fetchJSON('/api/health').then(h => {
      if (!h) return;
      document.getElementById('host-name').textContent = h.host || h.hostname || 'host';
      document.getElementById('host-meta').textContent = (h.version || h.Version || '') + ' · ' + (h.uptime || '');
    });
  } catch (_) {}

  // Initial route from URL.
  state.route = location.pathname || '/egress';
  // Accept any /egress/<thing>/<param> subpath — the render() prefix-handler
  // strips the param and routes to the parent key. Without this clause direct
  // URL loads of /egress/ip/<ip>, /egress/pid/<n>, /egress/country/<cc>,
  // /egress/flow/<bin>/<dest>/<port>, /egress/policy/review/<bin> silently
  // redirected to Overview.
  const isParamSubpath =
    state.route.startsWith('/egress/process/') ||
    state.route.startsWith('/egress/ip/') ||
    state.route.startsWith('/egress/pid/') ||
    state.route.startsWith('/egress/country/') ||
    state.route.startsWith('/egress/flow/') ||
    state.route.startsWith('/egress/policy/review/');
  if (!routes[state.route] && !isParamSubpath) state.route = '/egress';
  render();

  // Apply Week 6 polish wiring once shell is up.
  installSidebarCollapse();
  installKeyboardNav();
  installSortableTables();
  installSpinnerHook();
});

// ─── Week 6 polish + fleet + app profiles ─────────────────────

// Relative-time formatter — "5m ago" / "2h ago" when ≤24h; absolute
// otherwise. Used for last_seen columns that benefit from "when was
// this active?" framing over "what wall-clock did it happen at".
function fmtRelTime(t) {
  if (t === null || t === undefined || t === '' || t === 0) return '—';
  const d = (typeof t === 'number') ? new Date(t * 1000) : new Date(t);
  if (isNaN(d.getTime())) return '—';
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 0) return d.toLocaleTimeString();
  if (s < 5) return 'just now';
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s/60) + 'm ago';
  if (s < 86400) return Math.floor(s/3600) + 'h ago';
  return d.toLocaleString();
}

// Toast — non-modal bottom-right error/info popup. Auto-dismiss after
// `ms` (default 5000). Keep this tiny + dependency-free.
function toast(msg, kind) {
  let host = document.getElementById('xh-toasts');
  if (!host) {
    host = document.createElement('div');
    host.id = 'xh-toasts';
    host.style.cssText = 'position:fixed;bottom:16px;right:16px;z-index:9999;display:flex;flex-direction:column;gap:6px;max-width:380px';
    document.body.appendChild(host);
  }
  const el = document.createElement('div');
  const bg = kind === 'err' ? '#7f1d1d' : kind === 'ok' ? '#14532d' : '#1f2937';
  el.style.cssText = 'background:' + bg + ';color:#f3f4f6;padding:8px 12px;border-radius:6px;font-size:12px;font-family:var(--mono);box-shadow:0 4px 12px rgba(0,0,0,0.4);opacity:0;transition:opacity .15s';
  el.textContent = msg;
  host.appendChild(el);
  requestAnimationFrame(() => { el.style.opacity = '1'; });
  setTimeout(() => {
    el.style.opacity = '0';
    setTimeout(() => { if (el.parentNode) el.parentNode.removeChild(el); }, 200);
  }, 5000);
}

// Spinner hook — monkey-patch window.fetch so every in-flight HTTP
// request flips a small spinner glyph on the refresh indicator. We
// also surface a toast on non-OK responses. fetchJSON inside this
// IIFE bottoms out at fetch() so this catches everything without
// reaching into closures.
function installSpinnerHook() {
  if (window._xhFetchPatched) return;
  window._xhFetchPatched = true;
  const orig = window.fetch.bind(window);
  let inFlight = 0;
  const spinChars = ['◐','◑','◒','◓'];
  let spinTimer = null;
  function ensureSpinNode() {
    let n = document.getElementById('xh-spinner');
    if (n) return n;
    const ind = document.getElementById('refresh-ind');
    if (!ind || !ind.parentNode) return null;
    n = document.createElement('span');
    n.id = 'xh-spinner';
    n.style.cssText = 'margin-left:6px;font-family:var(--mono);font-size:12px;color:var(--text-2);min-width:1ch;display:inline-block';
    ind.parentNode.insertBefore(n, ind.nextSibling);
    return n;
  }
  function tick() {
    const n = ensureSpinNode();
    if (!n) return;
    if (inFlight <= 0) {
      if (spinTimer) { clearInterval(spinTimer); spinTimer = null; }
      n.textContent = '';
      return;
    }
    if (!spinTimer) {
      let i = 0;
      spinTimer = setInterval(() => {
        const m = document.getElementById('xh-spinner');
        if (m) m.textContent = spinChars[(i++) % spinChars.length];
      }, 120);
    }
  }
  window.fetch = async function (url, opts) {
    inFlight++; tick();
    try {
      const r = await orig(url, opts);
      return r;
    } catch (e) {
      toast('fetch failed: ' + (typeof url === 'string' ? url : ''), 'err');
      throw e;
    } finally {
      inFlight--; tick();
    }
  };
}

// Sidebar collapse — toggles a body class that the CSS uses to drop
// the sidebar to icon-only width. The toggle button is injected next
// to the existing breadcrumbs.
function installSidebarCollapse() {
  const crumbs = document.getElementById('crumbs');
  if (!crumbs) return;
  if (document.getElementById('sb-toggle')) return;
  const btn = document.createElement('button');
  btn.id = 'sb-toggle';
  btn.className = 'btn-ghost';
  btn.title = 'Collapse sidebar';
  btn.textContent = '⇤';
  btn.style.cssText = 'margin-right:8px';
  crumbs.parentNode.insertBefore(btn, crumbs);
  if (state.sidebarCollapsed) document.body.classList.add('sb-collapsed');
  btn.addEventListener('click', () => {
    state.sidebarCollapsed = !state.sidebarCollapsed;
    document.body.classList.toggle('sb-collapsed', state.sidebarCollapsed);
    savePrefs();
  });

  // Light/dark theme toggle — disabled-with-tooltip placeholder so the
  // affordance is discoverable but doesn't ship a half-baked theme.
  const themeBtn = document.createElement('button');
  themeBtn.className = 'btn-ghost';
  themeBtn.disabled = true;
  themeBtn.title = 'light theme coming';
  themeBtn.textContent = '☾';
  themeBtn.style.cssText = 'margin-right:8px;opacity:0.5;cursor:not-allowed';
  crumbs.parentNode.insertBefore(themeBtn, crumbs);
}

// Keyboard nav — j/k for table row movement, "/" to focus search,
// gg to top, G to bottom. Stays inert when an input has focus.
function installKeyboardNav() {
  let lastG = 0;
  document.addEventListener('keydown', e => {
    const tag = (e.target && e.target.tagName) || '';
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === '/') {
      const s = document.querySelector('#f-search');
      if (s) { s.focus(); e.preventDefault(); }
      return;
    }
    if (e.key === 'j' || e.key === 'k') {
      const rows = Array.from(document.querySelectorAll('#view table.tbl tbody tr'));
      if (!rows.length) return;
      let idx = rows.findIndex(r => r.classList.contains('kb-focus'));
      if (idx < 0) idx = 0;
      else { rows[idx].classList.remove('kb-focus'); idx = (e.key === 'j') ? Math.min(rows.length-1, idx+1) : Math.max(0, idx-1); }
      rows[idx].classList.add('kb-focus');
      rows[idx].scrollIntoView({ block: 'nearest' });
      e.preventDefault();
      return;
    }
    if (e.key === 'g') {
      const now = Date.now();
      if (now - lastG < 500) {
        window.scrollTo({ top: 0, behavior: 'smooth' });
        lastG = 0;
      } else {
        lastG = now;
      }
      return;
    }
    if (e.key === 'G') {
      window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
      return;
    }
  });
}

// Sortable headers — delegated click on any th inside a table. Sort
// is in-place by parsing the cell text (numeric if it looks numeric).
// Adds a CSV export button to every table whose surrounding wrap has
// a thead. Installed as a single delegated handler.
function installSortableTables() {
  document.body.addEventListener('click', e => {
    const th = e.target.closest && e.target.closest('table.tbl thead th');
    if (!th) return;
    const table = th.closest('table');
    if (!table) return;
    const tbody = table.querySelector('tbody');
    if (!tbody) return;
    const idx = Array.from(th.parentNode.children).indexOf(th);
    const rows = Array.from(tbody.querySelectorAll('tr'));
    // Skip rows that don't have enough cells (group headers, empty-row).
    const sortable = rows.filter(r => r.children[idx] && !r.classList.contains('empty-row'));
    if (sortable.length < 2) return;
    const asc = th._sortDir !== 'asc';
    th._sortDir = asc ? 'asc' : 'desc';
    sortable.sort((a, b) => {
      const av = a.children[idx].textContent.trim();
      const bv = b.children[idx].textContent.trim();
      const an = parseFloat(av.replace(/[^0-9.\-]/g, ''));
      const bn = parseFloat(bv.replace(/[^0-9.\-]/g, ''));
      if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
      return asc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    sortable.forEach(r => tbody.appendChild(r));
  });

  // CSV export — append a small button to each .tbl-wrap on every
  // render. Idempotent (skips if already present).
  const obs = new MutationObserver(() => {
    document.querySelectorAll('#view .tbl-wrap').forEach(wrap => {
      if (wrap.querySelector('.csv-export-btn')) return;
      const table = wrap.querySelector('table.tbl');
      if (!table || !table.querySelector('thead')) return;
      const btn = document.createElement('button');
      btn.className = 'btn-ghost csv-export-btn';
      btn.textContent = '⬇ CSV';
      btn.style.cssText = 'position:absolute;top:4px;right:4px;font-size:10px;padding:2px 6px;opacity:0.6';
      btn.addEventListener('click', e => { e.stopPropagation(); exportTableCSV(table); });
      const ps = window.getComputedStyle(wrap).position;
      if (ps === 'static') wrap.style.position = 'relative';
      wrap.appendChild(btn);
    });
  });
  const view = document.getElementById('view');
  if (view) obs.observe(view, { childList: true, subtree: true });
}

function exportTableCSV(table) {
  const lines = [];
  table.querySelectorAll('tr').forEach(tr => {
    const cells = Array.from(tr.children).map(td => {
      const t = td.textContent.replace(/\s+/g, ' ').trim();
      return '"' + t.replace(/"/g, '""') + '"';
    });
    if (cells.length) lines.push(cells.join(','));
  });
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'xhelix-egress-' + Date.now() + '.csv';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ─── Fleet calibration ─────────────────────────────────────────

async function fetchFleetRarity(binary) {
  try {
    const r = await fetch('/api/egress/fleet/rarity?binary=' + encodeURIComponent(binary), { cache: 'no-store' });
    if (!r.ok) return null;
    return await r.json();
  } catch (_) { return null; }
}

async function renderCohortOutliersCard(view) {
  // Place card under the existing grid-3 block. Idempotent — only
  // mount once per overview render.
  if (view.querySelector('#cohort-card')) return;
  const data = await (async () => {
    try {
      const r = await fetch('/api/egress/fleet/anomaly?limit=5', { cache: 'no-store' });
      if (!r.ok) return null;
      return await r.json();
    } catch (_) { return null; }
  })();
  const cohort = await (async () => {
    try {
      const r = await fetch('/api/egress/fleet/cohort', { cache: 'no-store' });
      if (!r.ok) return null;
      return await r.json();
    } catch (_) { return null; }
  })();
  const card = document.createElement('div');
  card.id = 'cohort-card';
  card.className = 'card';
  card.style.marginTop = '12px';
  if (!data || data.available === false) {
    card.innerHTML = `
      <div class="card-head"><h2>Cohort outliers</h2><div class="right">fleet hub</div></div>
      <div class="placeholder" style="margin:0">
        <strong>Enable fleet hub for cohort comparison</strong>
        Set <code>xhub.url</code> in /etc/xhelix/xhelix.yaml to compare this host's egress
        against peers. Without a hub, every flow looks unique.
      </div>`;
    view.appendChild(card);
    return;
  }
  const outliers = (data.outliers || []);
  const cohortLine = cohort && cohort.available
    ? `<span class="dim">cohort: <span class="mono">${esc(cohort.cohort_key)}</span> · ${esc(cohort.cohort_size)} peer(s)</span>`
    : '<span class="dim">cohort: unknown</span>';
  card.innerHTML = `
    <div class="card-head">
      <h2>Cohort outliers — last hour</h2>
      <div class="right">${cohortLine}</div>
    </div>
    <div class="tbl-wrap" style="border:0">
      <table class="tbl">
        <thead><tr><th>Binary</th><th>Destination</th><th>Port</th><th class="num">Cohort %</th><th>Reason</th></tr></thead>
        <tbody>${outliers.map(o => `<tr class="clickable" data-binary="${esc(o.binary)}">
          <td class="mono">${esc(o.binary)}</td>
          <td class="mono">${esc(o.dest_cidr)}</td>
          <td class="mono">${esc(o.port)}</td>
          <td class="num" style="color:var(--err)">${esc(o.hosts_seen)}/${esc(o.cohort_size)} (${(o.fraction*100).toFixed(1)}%)</td>
          <td class="dim">${esc(o.reason || 'rare-in-cohort')}</td>
        </tr>`).join('') || '<tr class="empty-row"><td colspan="5">no outliers — every flow this host emits is shared by ≥10% of cohort peers</td></tr>'}</tbody>
      </table>
    </div>`;
  view.appendChild(card);
  card.querySelectorAll('tr.clickable[data-binary]').forEach(tr => {
    tr.addEventListener('click', () => go('/egress/process/' + encodeURIComponent(tr.dataset.binary)));
  });
}

// ─── Per-app profile cards ────────────────────────────────────

// Detect the app shape from a binary basename. Strips path + arg
// suffixes ("php-fpm: pool www" → "php-fpm"). Returns the canonical
// key used as a key in AppProfiles.
function detectAppShape(binary) {
  if (!binary) return '';
  let b = String(binary);
  const slash = b.lastIndexOf('/');
  if (slash >= 0) b = b.substring(slash + 1);
  const colon = b.indexOf(':');
  if (colon >= 0) b = b.substring(0, colon).trim();
  return b.toLowerCase();
}

// Heuristics — these don't pretend to be hostnames; they match the
// .DestClass labels that destclass.go emits today.
const CDN_CLASSES = new Set(['cdn', 'cloudflare', 'fastly', 'akamai', 'cloudfront', 'cdn77']);
const PRIVATE_DB_PORTS = new Set([3306, 5432, 6379, 27017, 11211]);

function isLoopback(cidr) {
  if (!cidr) return false;
  if (cidr.startsWith('127.')) return true;
  if (cidr === '::1' || cidr.startsWith('::1/')) return true;
  return false;
}
function isPrivateCIDR(cidr) {
  if (!cidr) return false;
  if (cidr.startsWith('10.')) return true;
  if (cidr.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(cidr)) return true;
  if (cidr.startsWith('fd') || cidr.startsWith('fc')) return true;
  return false;
}

// renderAppProfile dispatches to the per-app renderer based on the
// binary's basename. Falls back to a "no profile" panel that points
// the operator at the policy-propose workflow.
function renderAppProfile(binary, rawRows, destRows) {
  const shape = detectAppShape(binary);
  const profiles = {
    'nginx':       renderNginxProfile,
    'apache2':     renderNginxProfile,
    'httpd':       renderNginxProfile,
    'caddy':       renderNginxProfile,
    'mysql':       renderMySQLProfile,
    'mysqld':      renderMySQLProfile,
    'mariadbd':    renderMySQLProfile,
    'postgres':    renderPostgresProfile,
    'postmaster':  renderPostgresProfile,
    'php-fpm':     renderPHPFPMProfile,
    'sshd':        renderSSHDProfile,
    'postfix':     renderPostfixProfile,
    'master':      renderPostfixProfile,
    'redis-server':renderRedisProfile,
    'tor':         renderTorProfile,
    'node':        renderNodeProfile,
    'python3':     renderPythonProfile,
    'python':      renderPythonProfile,
  };
  const fn = profiles[shape];
  if (!fn) {
    // Defer button wiring to a microtask after the innerHTML insert.
    setTimeout(() => {
      const b = document.querySelector('#ap-propose');
      if (!b) return;
      b.addEventListener('click', async () => {
        try {
          const r = await fetch('/api/egress/policy/propose', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({binary: binary, days: 14}),
          });
          if (!r.ok) throw new Error(await r.text());
          const j = await r.json();
          openDrawer('Proposal for ' + binary, '<pre>' + esc(JSON.stringify(j, null, 2)) + '</pre>');
        } catch (e) {
          toast('propose failed: ' + (e.message || e), 'err');
        }
      });
    }, 10);
    return `<div class="card">
      <div class="card-head"><h2>No app profile for <span class="mono">${esc(shape || binary)}</span></h2><div class="right">generic binary</div></div>
      <div class="subtitle">No pre-built profile exists for this binary shape. Generate a baseline from observed traffic with:</div>
      <pre style="margin:0;font-family:var(--mono);font-size:11px;color:var(--text-1);background:var(--bg-0);padding:10px;border-radius:5px;border:1px solid var(--border)">xhelixctl egress policy propose ${esc(binary)} --days 14 --out /tmp/${esc(shape || 'binary')}.yaml</pre>
      <div style="margin-top:8px">
        <button class="btn-primary" id="ap-propose">Generate from observed traffic</button>
      </div>
    </div>`;
  }
  return fn(binary, rawRows || [], destRows || []);
}

// Shared helper — classify a destRow against an allow-predicate and
// build an "anomalies / healthy" split. Returns { anomalies, healthy }
// where each is an array of {dest, port, sni, cls, bytesOut, reason}.
function splitAnomalies(destRows, predicate) {
  const anomalies = [], healthy = [];
  destRows.forEach(d => {
    const r = predicate(d);
    if (r && r.ok) healthy.push(Object.assign({}, d, { reason: r.reason || 'matches profile' }));
    else anomalies.push(Object.assign({}, d, { reason: (r && r.reason) || 'does not match expected pattern' }));
  });
  return { anomalies, healthy };
}

function anomaliesCard(anomalies) {
  return `<div class="card">
    <div class="card-head"><h2>Anomalies <span class="dim">(${anomalies.length})</span></h2><div class="right">flows that don't fit the expected profile</div></div>
    <div class="tbl-wrap" style="border:0"><table class="tbl">
      <thead><tr><th>Destination</th><th>Port</th><th>SNI/DNS</th><th>Class</th><th class="num">Bytes out</th><th>Reason</th></tr></thead>
      <tbody>${anomalies.map(d => `<tr>
        <td class="mono">${esc(d.dest)}</td>
        <td class="mono">${esc(d.port)}</td>
        <td class="mono dim">${esc(d.sni || d.dns || '—')}</td>
        <td>${classPill(d.cls)}</td>
        <td class="num">${fmtBytes(d.bytesOut)}</td>
        <td class="dim">${esc(d.reason)}</td>
      </tr>`).join('') || '<tr class="empty-row"><td colspan="6">no anomalies — every observed flow matches the expected profile</td></tr>'}</tbody>
    </table></div>
  </div>`;
}
function healthyCard(healthy) {
  return `<div class="card" style="margin-top:12px">
    <div class="card-head"><h2>Healthy flows <span class="dim">(${healthy.length})</span></h2><div class="right">matches expected profile</div></div>
    <div class="tbl-wrap" style="border:0"><table class="tbl">
      <thead><tr><th>Destination</th><th>Port</th><th>SNI/DNS</th><th>Class</th><th class="num">Bytes out</th><th>Match reason</th></tr></thead>
      <tbody>${healthy.map(d => `<tr>
        <td class="mono">${esc(d.dest)}</td>
        <td class="mono">${esc(d.port)}</td>
        <td class="mono dim">${esc(d.sni || d.dns || '—')}</td>
        <td>${classPill(d.cls)}</td>
        <td class="num">${fmtBytes(d.bytesOut)}</td>
        <td class="dim">${esc(d.reason)}</td>
      </tr>`).join('') || '<tr class="empty-row"><td colspan="6">no flows yet</td></tr>'}</tbody>
    </table></div>
  </div>`;
}

function profileHeader(binary, title, expected, kpis, bannerHTML) {
  const kpiHTML = (kpis || []).map(k => `
    <div class="kpi">
      <div class="kpi-label">${esc(k.label)}</div>
      <div class="kpi-value" style="${k.color?'color:'+k.color:''}">${esc(k.value)}</div>
      ${k.sub ? `<div class="kpi-sub">${esc(k.sub)}</div>` : ''}
    </div>`).join('');
  return `
    ${bannerHTML || ''}
    <div class="card" style="margin-bottom:12px">
      <div class="card-head"><h2>${esc(title)}</h2><div class="right mono">${esc(binary)}</div></div>
      <div class="subtitle" style="margin:0">${esc(expected)}</div>
    </div>
    <div class="hero" style="margin-bottom:12px">${kpiHTML}</div>`;
}

function policyHint(binary) {
  return `<div class="card" style="margin-top:12px">
    <div class="card-head"><h2>Suggested policy</h2><div class="right">propose + sign</div></div>
    <pre style="margin:0;font-family:var(--mono);font-size:11px;color:var(--text-1);background:var(--bg-0);padding:10px;border-radius:5px;border:1px solid var(--border)">xhelixctl egress policy pack list
xhelixctl egress policy pack install ${esc(binary)} --signer you --key /path/to/operator.key</pre>
  </div>`;
}

function renderNginxProfile(binary, rows, destRows) {
  const { anomalies, healthy } = splitAnomalies(destRows, d => {
    if (isLoopback(d.dest) || isPrivateCIDR(d.dest)) return { ok: true, reason: 'upstream pool (loopback/private)' };
    if (d.port === 443 && CDN_CLASSES.has((d.cls||'').toLowerCase())) return { ok: true, reason: 'CDN purge/metadata' };
    return { ok: false, reason: 'non-loopback, non-CDN destination' };
  });
  const kpis = [
    { label: 'Upstream hits', value: healthy.filter(d => isLoopback(d.dest) || isPrivateCIDR(d.dest)).length },
    { label: 'CDN flows',     value: healthy.filter(d => CDN_CLASSES.has((d.cls||'').toLowerCase())).length },
    { label: 'External anomalies', value: anomalies.length, color: anomalies.length ? 'var(--err)' : '' },
  ];
  return profileHeader(binary, 'nginx / reverse proxy',
    'Expected: outbound TCP to 127.0.0.1 + private LAN (upstream pools); occasional 443/CDN (metadata, purge).',
    kpis) + anomaliesCard(anomalies) + healthyCard(healthy) + policyHint(binary);
}

function renderMySQLProfile(binary, rows, destRows) {
  // MySQL should never initiate ANY outbound. Every dest is an anomaly.
  const anomalies = destRows.map(d => Object.assign({}, d, { reason: 'mysql initiated outbound — should listen only' }));
  const banner = anomalies.length ? `<div class="placeholder" style="background:rgba(239,68,68,0.1);border-color:var(--err);color:var(--err);margin-bottom:12px">
    <strong>MySQL should never make outbound connections — investigate immediately.</strong>
    Possible causes: federated/replication misconfig, SELECT INTO OUTFILE to remote, or compromise.
  </div>` : '';
  const kpis = [
    { label: 'Outbound flows', value: destRows.length, color: destRows.length ? 'var(--err)' : '' },
    { label: 'Distinct dests', value: new Set(destRows.map(d => d.dest)).size },
  ];
  return profileHeader(binary, 'MySQL / MariaDB',
    'Expected: ONLY listen 3306. MySQL should never initiate outbound connections.',
    kpis, banner) + anomaliesCard(anomalies) + policyHint(binary);
}

function renderPostgresProfile(binary, rows, destRows) {
  const anomalies = destRows.map(d => Object.assign({}, d, { reason: 'postgres initiated outbound — should listen only' }));
  const banner = anomalies.length ? `<div class="placeholder" style="background:rgba(239,68,68,0.1);border-color:var(--err);color:var(--err);margin-bottom:12px">
    <strong>Postgres should never make outbound connections — investigate.</strong>
    Possible causes: dblink/FDW, COPY TO PROGRAM, or compromise.
  </div>` : '';
  const kpis = [
    { label: 'Outbound flows', value: destRows.length, color: destRows.length ? 'var(--err)' : '' },
    { label: 'Distinct dests', value: new Set(destRows.map(d => d.dest)).size },
  ];
  return profileHeader(binary, 'PostgreSQL',
    'Expected: ONLY listen 5432. Postgres should never initiate outbound connections.',
    kpis, banner) + anomaliesCard(anomalies) + policyHint(binary);
}

function renderPHPFPMProfile(binary, rows, destRows) {
  const { anomalies, healthy } = splitAnomalies(destRows, d => {
    const cls = (d.cls||'').toLowerCase();
    if (isPrivateCIDR(d.dest) && PRIVATE_DB_PORTS.has(Number(d.port))) return { ok: true, reason: 'private DB (' + d.port + ')' };
    if (isLoopback(d.dest)) return { ok: true, reason: 'loopback service' };
    if (d.port === 443 && (CDN_CLASSES.has(cls) || cls === 'cloud_provider')) return { ok: true, reason: '3rd-party API on TLS' };
    if (d.port === 80) return { ok: false, reason: 'cleartext HTTP (should be 443)' };
    if (!d.sni && !d.dns && !isPrivateCIDR(d.dest) && !isLoopback(d.dest)) return { ok: false, reason: 'raw IP (no SNI/DNS) — beacon shape' };
    if (PRIVATE_DB_PORTS.has(Number(d.port)) && !isPrivateCIDR(d.dest)) return { ok: false, reason: 'DB port to public IP' };
    return { ok: false, reason: 'unexpected destination for PHP app' };
  });
  const kpis = [
    { label: 'DB hits',  value: healthy.filter(d => PRIVATE_DB_PORTS.has(Number(d.port))).length },
    { label: 'API hits', value: healthy.filter(d => Number(d.port) === 443).length },
    { label: 'Anomalies', value: anomalies.length, color: anomalies.length ? 'var(--err)' : '' },
  ];
  return profileHeader(binary, 'PHP-FPM',
    'Expected: outbound to MySQL/Postgres/Redis on private IPs, CDN/3rd-party APIs on 443 with SNI.',
    kpis) + anomaliesCard(anomalies) + healthyCard(healthy) + policyHint(binary);
}

function renderSSHDProfile(binary, rows, destRows) {
  const { anomalies, healthy } = splitAnomalies(destRows, d => {
    if (Number(d.port) === 53) return { ok: true, reason: 'DNS lookup for auth' };
    if (Number(d.port) === 88 || Number(d.port) === 389 || Number(d.port) === 636) return { ok: true, reason: 'AD/LDAP/Kerberos for auth' };
    if (isLoopback(d.dest)) return { ok: true, reason: 'loopback (PAM helpers)' };
    return { ok: false, reason: 'sshd outbound to non-auth dest — possible reverse shell or pivot' };
  });
  const kpis = [
    { label: 'Auth lookups', value: healthy.length },
    { label: 'Anomalies',    value: anomalies.length, color: anomalies.length ? 'var(--err)' : '' },
  ];
  const banner = anomalies.length ? `<div class="placeholder" style="background:rgba(239,68,68,0.1);border-color:var(--err);color:var(--err);margin-bottom:12px">
    <strong>sshd making outbound to non-auth destinations is rare and high-signal.</strong>
    Consider quarantine or safety_net.always_allow + investigation.
  </div>` : '';
  return profileHeader(binary, 'OpenSSH server',
    'Expected: outbound only to DNS / AD / LDAP / Kerberos for auth lookups; loopback for PAM.',
    kpis, banner) + anomaliesCard(anomalies) + healthyCard(healthy) + policyHint(binary);
}

function renderPostfixProfile(binary, rows, destRows) {
  const { anomalies, healthy } = splitAnomalies(destRows, d => {
    const p = Number(d.port);
    if (p === 25 || p === 465 || p === 587) return { ok: true, reason: 'SMTP delivery' };
    if (p === 53) return { ok: true, reason: 'MX lookup' };
    if (isLoopback(d.dest)) return { ok: true, reason: 'loopback (local relay)' };
    return { ok: false, reason: 'postfix outbound on non-SMTP port' };
  });
  const kpis = [
    { label: 'SMTP flows', value: healthy.filter(d => [25,465,587].includes(Number(d.port))).length },
    { label: 'DNS lookups', value: healthy.filter(d => Number(d.port) === 53).length },
    { label: 'Anomalies',  value: anomalies.length, color: anomalies.length ? 'var(--err)' : '' },
  ];
  return profileHeader(binary, 'Postfix MTA',
    'Expected: outbound on 25 / 465 / 587 (SMTP) and 53 (MX lookups).',
    kpis) + anomaliesCard(anomalies) + healthyCard(healthy) + policyHint(binary);
}

function renderRedisProfile(binary, rows, destRows) {
  const anomalies = destRows.filter(d => !isLoopback(d.dest))
    .map(d => Object.assign({}, d, { reason: 'redis bound to non-loopback — should be 127.0.0.1:6379 only' }));
  const banner = anomalies.length ? `<div class="placeholder" style="background:rgba(239,68,68,0.1);border-color:var(--err);color:var(--err);margin-bottom:12px">
    <strong>Redis emitting non-loopback flows.</strong>
    Either replication is configured (verify) or this is a CONFIG REWRITE / SLAVEOF exploit attempt.
  </div>` : '';
  const kpis = [
    { label: 'Non-loopback flows', value: anomalies.length, color: anomalies.length ? 'var(--err)' : '' },
  ];
  return profileHeader(binary, 'Redis',
    'Expected: listen on 127.0.0.1:6379 only. No outbound except configured replication.',
    kpis, banner) + anomaliesCard(anomalies) + policyHint(binary);
}

function renderTorProfile(binary, rows, destRows) {
  // Tor traffic is structurally hard to validate without an upstream relay list;
  // we treat ALL :443 + :9001 as healthy and flag everything else.
  const { anomalies, healthy } = splitAnomalies(destRows, d => {
    const p = Number(d.port);
    if (p === 443 || p === 9001 || p === 9030 || p === 9050) return { ok: true, reason: 'Tor relay/dir/SOCKS port' };
    return { ok: false, reason: 'Tor outbound on non-Tor port' };
  });
  // "no traffic in last 10m" banner.
  const lastSeen = rows.reduce((m, r) => {
    const t = new Date((r.Metrics||{}).LastSeen || 0).getTime();
    return t > m ? t : m;
  }, 0);
  const idleMin = lastSeen ? (Date.now() - lastSeen) / 60000 : 999;
  const banner = idleMin > 10 ? `<div class="placeholder" style="background:rgba(250,204,21,0.1);border-color:var(--warn);color:var(--warn);margin-bottom:12px">
    <strong>No Tor traffic in last ${Math.floor(idleMin)} minute(s) — Tor not running?</strong>
    Check <code>systemctl status tor</code> on this host.
  </div>` : '';
  const kpis = [
    { label: 'Relay flows', value: healthy.length },
    { label: 'Anomalies',  value: anomalies.length, color: anomalies.length ? 'var(--err)' : '' },
    { label: 'Idle',       value: idleMin < 999 ? Math.floor(idleMin) + 'm' : 'never' },
  ];
  return profileHeader(binary, 'Tor client/relay',
    'Expected: outbound to Tor relays on 443 / 9001 and directory authorities on 9030.',
    kpis, banner) + anomaliesCard(anomalies) + healthyCard(healthy) + policyHint(binary);
}

function renderNodeProfile(binary, rows, destRows) {
  const { anomalies, healthy } = splitAnomalies(destRows, d => {
    const p = Number(d.port);
    if (isPrivateCIDR(d.dest) && PRIVATE_DB_PORTS.has(p)) return { ok: true, reason: 'private DB' };
    if (isLoopback(d.dest)) return { ok: true, reason: 'loopback service' };
    if (p === 443 && (d.sni || d.dns)) return { ok: true, reason: 'TLS API with SNI' };
    if (p === 80) return { ok: false, reason: 'cleartext HTTP' };
    if (!d.sni && !d.dns && !isLoopback(d.dest) && !isPrivateCIDR(d.dest)) return { ok: false, reason: 'raw IP with no SNI/DNS' };
    return { ok: false, reason: 'unexpected destination' };
  });
  const kpis = [
    { label: 'API hits', value: healthy.filter(d => Number(d.port) === 443).length },
    { label: 'DB hits',  value: healthy.filter(d => PRIVATE_DB_PORTS.has(Number(d.port))).length },
    { label: 'Anomalies', value: anomalies.length, color: anomalies.length ? 'var(--err)' : '' },
  ];
  return profileHeader(binary, 'Node.js application',
    'Expected: outbound to private DB IPs and SaaS APIs on TLS:443 with SNI.',
    kpis) + anomaliesCard(anomalies) + healthyCard(healthy) + policyHint(binary);
}

function renderPythonProfile(binary, rows, destRows) {
  const { anomalies, healthy } = splitAnomalies(destRows, d => {
    const p = Number(d.port);
    if (isLoopback(d.dest)) return { ok: true, reason: 'loopback' };
    if (isPrivateCIDR(d.dest)) return { ok: true, reason: 'private LAN' };
    if (p === 443 && (d.sni || d.dns)) return { ok: true, reason: 'TLS API with SNI' };
    if (p === 80) return { ok: false, reason: 'cleartext HTTP — likely outdated dependency' };
    if (!d.sni && !d.dns) return { ok: false, reason: 'raw IP with no SNI/DNS — beacon shape' };
    return { ok: false, reason: 'unexpected destination for python script' };
  });
  const kpis = [
    { label: 'Healthy',   value: healthy.length },
    { label: 'Anomalies', value: anomalies.length, color: anomalies.length ? 'var(--err)' : '' },
  ];
  return profileHeader(binary, 'Python script',
    'Expected: TLS:443 to public APIs with SNI, or private LAN. Raw-IP no-SNI is a beacon shape.',
    kpis) + anomaliesCard(anomalies) + healthyCard(healthy) + policyHint(binary);
}

// ─── Safety Net ────────────────────────────────────────────────

async function renderSafety(view) {
  const list = await fetchJSON('/api/safety/list') || { allow: [], block: [] };
  const stats = await fetchJSON('/api/safety/stats') || {};
  const attempts = await fetchJSON('/api/safety/attempts?n=50') || [];
  const whoami = await fetchJSON('/api/safety/whoami') || {};

  const allowRows = (list.allow || []).map(c => `<tr>
    <td class="mono">${esc(c)}</td>
    <td class="num"><button class="btn-ghost btn-del" data-cidr="${esc(c)}" data-kind="allow">×</button></td>
  </tr>`).join('') || '<tr class="empty-row"><td colspan="2">no allowlist entries</td></tr>';

  const blockRows = (list.block || []).map(c => `<tr>
    <td class="mono">${esc(c)}</td>
    <td class="num"><button class="btn-ghost btn-del" data-cidr="${esc(c)}" data-kind="block">×</button></td>
  </tr>`).join('') || '<tr class="empty-row"><td colspan="2">no blocklist entries</td></tr>';

  const attemptRows = attempts.map(a => `<tr>
    <td class="mono dim">${esc((a.time || '').split('T')[1]?.split('.')[0] || a.time)}</td>
    <td class="mono">${esc(a.src_ip)}</td>
    <td class="mono">${esc(a.dst_ip)}:${esc(a.dst_port)}</td>
    <td class="mono dim">${esc(a.proto)}</td>
    <td class="num dim">${esc(a.bytes)}</td>
  </tr>`).join('') || '<tr class="empty-row"><td colspan="5">no blocked attempts in ring</td></tr>';

  view.innerHTML = `
    <div class="toolbar">
      <h1>IP Safety Net</h1>
      <div class="spacer"></div>
      <span class="pill dim">your IP: ${esc(whoami.ip || '?')}</span>
      <span class="pill ${stats.allow_count > 0 ? 'ok' : 'dim'}">${stats.allow_count || 0} allowed</span>
      <span class="pill ${stats.block_count > 0 ? 'err' : 'dim'}">${stats.block_count || 0} blocked</span>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-head">
          <h2>Always allow <span class="dim">never blocked, vetoes any policy</span></h2>
          <div class="right">
            <input id="allow-add-input" placeholder="CIDR e.g. 95.211.19.203/32" class="input mono" style="width:240px"/>
            <button class="btn-primary" id="allow-add-btn">+ Add</button>
            <button class="btn-ghost" id="allow-add-me" title="Add your visiting IP">+ My IP</button>
          </div>
        </div>
        <div class="tbl-wrap">
          <table class="tbl">
            <thead><tr><th>CIDR</th><th class="num">×</th></tr></thead>
            <tbody>${allowRows}</tbody>
          </table>
        </div>
      </div>
      <div class="card">
        <div class="card-head">
          <h2>Block &amp; observe <span class="dim">drop at nftables + log every attempt</span></h2>
          <div class="right">
            <input id="block-add-input" placeholder="CIDR e.g. 1.2.3.4/32" class="input mono" style="width:240px"/>
            <button class="btn-primary" id="block-add-btn">+ Add</button>
          </div>
        </div>
        <div class="tbl-wrap">
          <table class="tbl">
            <thead><tr><th>CIDR</th><th class="num">×</th></tr></thead>
            <tbody>${blockRows}</tbody>
          </table>
        </div>
      </div>
    </div>
    <div class="card" style="margin-top:12px">
      <div class="card-head">
        <h2>Recent blocked attempts <span class="dim">${attempts.length}/${stats.attempts_log || 0} in ring</span></h2>
        <div class="right">
          <span class="pill dim">allow checks: ${stats.allow_checks || 0} (hits ${stats.allow_hits || 0})</span>
          <span class="pill dim">block checks: ${stats.block_checks || 0} (hits ${stats.block_hits || 0})</span>
        </div>
      </div>
      <div class="tbl-wrap">
        <table class="tbl">
          <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th class="num">Bytes</th></tr></thead>
          <tbody>${attemptRows}</tbody>
        </table>
      </div>
    </div>`;

  async function safetyPost(path, cidr) {
    try {
      const r = await fetch(path, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({cidr}) });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(body.error || ('HTTP ' + r.status));
      render();
    } catch (e) { alert('safety: ' + e.message); }
  }
  view.querySelector('#allow-add-btn').addEventListener('click', () => {
    const v = view.querySelector('#allow-add-input').value.trim();
    if (v) safetyPost('/api/safety/allow', v);
  });
  view.querySelector('#allow-add-me').addEventListener('click', () => {
    if (whoami.ip) safetyPost('/api/safety/allow', whoami.ip + '/32');
  });
  view.querySelector('#block-add-btn').addEventListener('click', () => {
    const v = view.querySelector('#block-add-input').value.trim();
    if (v) safetyPost('/api/safety/block', v);
  });
  view.querySelectorAll('.btn-del').forEach(b => {
    b.addEventListener('click', () => {
      const cidr = b.dataset.cidr;
      const kind = b.dataset.kind;
      if (!confirm('Remove ' + cidr + ' from ' + kind + ' list?')) return;
      safetyPost('/api/safety/' + kind + '/delete', cidr);
    });
  });
}

// ─── IP deep analysis ──────────────────────────────────────────

async function renderIPAnalysis(view) {
  const ip = state.selectedIP;
  if (!ip) {
    view.innerHTML = `<div class="placeholder"><strong>No IP selected</strong>Click any IP in the dashboard to land here.</div>`;
    return;
  }
  view.innerHTML = `<div class="placeholder">loading deep analysis for ${esc(ip)}…</div>`;
  const d = await fetchJSON('/api/egress/ipinfo?ip=' + encodeURIComponent(ip));
  if (!d) {
    view.innerHTML = `<div class="placeholder"><strong>Lookup failed</strong>${esc(ip)} — no data returned.</div>`;
    return;
  }
  ipCountryCache.set(ip, d.country || '');

  const cc = (d.country || '').toUpperCase();
  const ccBadge = cc ? `<span class="ip-cc" style="font-size:13px;padding:3px 8px">${esc(cc)}</span>` : '';
  const classPillHTML = d.class ? classPill(d.class) : '';
  const threatBanner = d.threat_intel_hit
    ? `<div class="threat-banner">⚠ Threat intel hit — feed: ${esc(d.threat_intel_hit)}</div>`
    : '';
  const privacyBadges = [
    d.is_private    ? '<span class="pill warn">private</span>'    : '',
    d.is_loopback   ? '<span class="pill warn">loopback</span>'   : '',
    d.is_link_local ? '<span class="pill warn">link-local</span>' : '',
  ].filter(Boolean).join(' ');

  const topBinsHTML = (d.top_binaries || []).map(b => `
    <tr class="clickable" data-binary="${esc(b)}">
      <td class="mono">${esc(b)}</td>
    </tr>`).join('') || '<tr class="empty-row"><td>no binaries observed</td></tr>';

  const relatedHTML = (d.related_domains || []).map(n => `
    <li><span class="mono">${esc(n)}</span></li>`).join('') ||
    '<li class="dim">no recently-resolved domains observed (DNS observation provider not wired).</li>';

  const flowsHTML = (d.recent_flows || []).map(f => {
    const flowHref = '/egress/flow/' +
      encodeURIComponent(f.binary) + '/' +
      encodeURIComponent(f.dest_cidr) + '/' +
      encodeURIComponent(f.dest_port || 0);
    return `<tr class="clickable" data-flow-href="${esc(flowHref)}">
      <td class="mono">${esc(f.binary)}</td>
      <td class="mono">${esc(f.dest_cidr)}</td>
      <td class="mono">${esc(f.dest_port || '—')}</td>
      <td class="num">${fmtBytes(f.bytes_out)}</td>
      <td class="num dim">${fmtBytes(f.bytes_in)}</td>
      <td class="num dim">${fmtNum(f.connects)}</td>
      <td class="dim">${fmtTime(f.last_seen)}</td>
    </tr>`;
  }).join('') || '<tr class="empty-row"><td colspan="7">no flows in last 7 days</td></tr>';

  const cohortHTML = (d.cohort_size && d.cohort_size > 0)
    ? `<div class="ipinfo-card"><h3>Cohort fraction</h3>
        <div class="dim">${Math.round((d.cohort_fraction||0)*100)}% of cohort hosts (${esc(Math.round((d.cohort_fraction||0)*d.cohort_size))}/${esc(d.cohort_size)}) also talk to this IP.</div>
       </div>` : '';

  // ── Suspicion banner ────────────────────────────────────────
  const susp = d.suspicion || { score: 0, verdict: 'normal', contributions: [] };
  const verdict = susp.verdict || 'normal';
  const verdictLabel = verdict.toUpperCase();
  const suspBdRows = (susp.contributions || []).map(c =>
    `<div class="susp-bd-row">
       <span class="susp-bd-delta${c.delta < 0 ? ' neg' : ''}">${c.delta>0?'+':''}${esc(c.delta)}</span>
       <span class="susp-bd-cond mono">${esc(c.condition)}</span>
       <span class="susp-bd-detail dim">${esc(c.detail || '')}</span>
     </div>`).join('') || '<div class="dim">no contributing signals — baseline</div>';
  const suspBanner = `
    <div class="susp-banner ${esc(verdict)}" id="susp-banner" title="click to expand contribution breakdown">
      <div style="display:flex;align-items:center;gap:18px">
        <div>
          <div class="susp-score">${esc(susp.score || 0)}</div>
          <div style="font-size:11px;color:var(--text-2);text-transform:uppercase;letter-spacing:0.5px">score / 100</div>
        </div>
        <div style="flex:1">
          <div style="font-weight:700;font-size:14px;text-transform:uppercase;letter-spacing:0.5px">${esc(verdictLabel)}</div>
          <div style="font-size:12px;color:var(--text-2)">${(susp.contributions || []).length} contributing signals · click to expand</div>
        </div>
      </div>
      <div class="susp-bd">${suspBdRows}</div>
    </div>`;

  // ── 24h timeline chart ──────────────────────────────────────
  const hOut = d.hourly_bytes_out || [];
  const hIn  = d.hourly_bytes_in  || [];
  const hAny = hOut.length === 24 || hIn.length === 24;
  let timelineHTML = '<div class="dim">no 24h activity</div>';
  if (hAny) {
    const baseHour = Math.floor((Date.now() - 24*3600*1000) / 3600000);
    const outPts = (hOut.length === 24 ? hOut : new Array(24).fill(0))
      .map((y, i) => ({ x: (baseHour + i) * 3600, y: y }));
    const inPts = (hIn.length === 24 ? hIn : new Array(24).fill(0))
      .map((y, i) => ({ x: (baseHour + i) * 3600, y: y }));
    if (typeof Charts !== 'undefined' && Charts.lineChart) {
      timelineHTML = Charts.lineChart([
        { name: 'out', color: '#ee8033', points: outPts },
        { name: 'in',  color: '#60a5fa', points: inPts  },
      ], { height: 180 });
    } else {
      const allY = outPts.concat(inPts).map(p => p.y);
      const maxY = Math.max(1, ...allY);
      const w = 600, h = 180, pad = 24;
      const px = i => pad + (i * (w - 2*pad)) / 23;
      const py = v => h - pad - (v / maxY) * (h - 2*pad);
      const path = pts => pts.map((p, i) => (i === 0 ? 'M' : 'L') + px(i) + ',' + py(p.y)).join(' ');
      timelineHTML = `<svg viewBox="0 0 ${w} ${h}" style="width:100%;height:${h}px">
        <path d="${path(outPts)}" stroke="#ee8033" fill="none" stroke-width="1.5"/>
        <path d="${path(inPts)}"  stroke="#60a5fa" fill="none" stroke-width="1.5"/>
      </svg>`;
    }
  }
  const timelineCard = `
    <div class="ipinfo-card">
      <h3>24-hour activity (hourly buckets)
        <span class="dim" style="font-weight:normal;font-size:11px;margin-left:8px">
          <span class="sw" style="background:#ee8033;width:9px;height:9px;display:inline-block;border-radius:2px;margin-right:4px"></span>out
          &nbsp;
          <span class="sw" style="background:#60a5fa;width:9px;height:9px;display:inline-block;border-radius:2px;margin-right:4px"></span>in
        </span>
      </h3>
      ${timelineHTML}
    </div>`;

  // ── Protocol breakdown ──────────────────────────────────────
  const protoRows = (d.protocols || []).map(p =>
    `<tr>
      <td class="mono"><span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${PROTO_COLOR[p.protocol]||'#888'};margin-right:6px;vertical-align:middle"></span>${esc(p.protocol)}</td>
      <td class="num">${fmtNum(p.flows)}</td>
      <td class="num">${fmtBytes(p.bytes_out)}</td>
      <td class="num dim">${fmtBytes(p.bytes_in)}</td>
      <td class="mono dim">${esc((p.snis || []).slice(0,5).join(', '))}${(p.snis||[]).length > 5 ? ' …+'+((p.snis||[]).length-5) : ''}</td>
    </tr>`).join('') || '<tr class="empty-row"><td colspan="5">no protocol data</td></tr>';
  const protoCard = `
    <div class="ipinfo-card">
      <h3>Protocol breakdown</h3>
      <div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>Protocol</th><th class="num">Flows</th><th class="num">Out</th><th class="num">In</th><th>SNIs</th></tr></thead>
        <tbody>${protoRows}</tbody>
      </table></div>
    </div>`;

  // ── Process activity ────────────────────────────────────────
  const procRows = (d.process_activity || []).map(p =>
    `<tr class="clickable" data-binary="${esc(p.binary)}">
      <td class="mono">${esc(p.binary)}</td>
      <td class="mono dim">${p.pid ? esc(p.pid) : '—'}</td>
      <td class="dim">${p.first_seen ? fmtTime(p.first_seen) : '—'}</td>
      <td class="dim">${p.last_seen ? fmtTime(p.last_seen) : '—'}</td>
      <td class="num">${fmtNum(p.connects)}</td>
      <td class="num">${fmtBytes(p.bytes_out)}</td>
      <td class="num dim">${fmtBytes(p.bytes_in)}</td>
    </tr>`).join('') || '<tr class="empty-row"><td colspan="7">no process activity</td></tr>';
  const procCard = `
    <div class="ipinfo-card">
      <h3>Per-process activity (click row to drill into binary)</h3>
      <div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>Binary</th><th>PID</th><th>First seen</th><th>Last seen</th><th class="num">Connects</th><th class="num">Out</th><th class="num">In</th></tr></thead>
        <tbody>${procRows}</tbody>
      </table></div>
    </div>`;

  // ── Related alerts ──────────────────────────────────────────
  const sevPill = sev => {
    const s = (sev || '').toLowerCase();
    if (s === 'high' || s === 'critical') return `<span class="pill solid-err">${esc(sev)}</span>`;
    if (s === 'medium' || s === 'warn') return `<span class="pill solid-warn">${esc(sev)}</span>`;
    return `<span class="pill info">${esc(sev || '—')}</span>`;
  };
  const alertRows = (d.related_alerts || []).slice().reverse().map(a =>
    `<tr>
      <td class="dim">${a.time ? fmtTime(a.time) : '—'}</td>
      <td class="mono">${esc(a.rule_id || '—')}</td>
      <td>${sevPill(a.severity)}</td>
      <td class="mono dim">${esc(a.comm || '—')}</td>
      <td class="dim">${esc(a.reason || '')}</td>
    </tr>`).join('') || '<tr class="empty-row"><td colspan="5">no related alerts in recent log</td></tr>';
  const alertsCard = `
    <div class="ipinfo-card">
      <h3>Related alerts <span class="dim" style="font-weight:normal;font-size:11px">(tail of /var/log/xhelix/alerts.jsonl, best-effort)</span></h3>
      <div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Comm</th><th>Reason</th></tr></thead>
        <tbody>${alertRows}</tbody>
      </table></div>
    </div>`;

  view.innerHTML = `
    <div class="toolbar">
      <button class="btn-ghost" id="ip-back">← back</button>
      <h1 class="mono" style="margin:0">${esc(ip)} ${ccBadge}</h1>
      ${classPillHTML}
      ${privacyBadges}
      <div class="spacer"></div>
    </div>
    ${threatBanner}
    ${suspBanner}
    <div class="hero">
      <div class="kpi"><div class="kpi-label">Bytes out (7d)</div><div class="kpi-value">${fmtBytes(d.total_bytes_out)}</div></div>
      <div class="kpi"><div class="kpi-label">Bytes in (7d)</div><div class="kpi-value">${fmtBytes(d.total_bytes_in)}</div></div>
      <div class="kpi"><div class="kpi-label">Connects</div><div class="kpi-value">${fmtNum(d.total_connects)}</div></div>
      <div class="kpi"><div class="kpi-label">Distinct binaries</div><div class="kpi-value">${d.distinct_binaries}</div></div>
      <div class="kpi"><div class="kpi-label">First seen</div><div class="kpi-value mono" style="font-size:11px">${d.first_seen ? fmtTime(d.first_seen) : '—'}</div></div>
      <div class="kpi"><div class="kpi-label">Last seen</div><div class="kpi-value mono" style="font-size:11px">${d.last_seen ? fmtTime(d.last_seen) : '—'}</div></div>
    </div>

    ${timelineCard}
    ${protoCard}
    ${procCard}
    ${alertsCard}

    <div class="ipinfo-card">
      <h3>Resolution &amp; identity</h3>
      <div class="ipinfo-grid">
        <div class="k">Country</div><div class="v">${esc(d.country || '—')}</div>
        <div class="k">ASN</div><div class="v">${esc(d.asn || '—')}</div>
        <div class="k">Organisation</div><div class="v">${esc(d.org || '—')}</div>
        <div class="k">Class</div><div class="v">${esc(d.class || '—')}</div>
        <div class="k">Reverse DNS (PTR)</div><div class="v">${esc(d.reverse_dns || '—')}</div>
        <div class="k">Threat intel</div><div class="v">${d.threat_intel_hit ? '<span style="color:var(--err)">'+esc(d.threat_intel_hit)+'</span>' : '<span class="dim">no hit</span>'}</div>
      </div>
    </div>

    <div class="ipinfo-card">
      <h3>Related domains <span class="dim" style="font-weight:normal;font-size:11px">(names recently observed resolving to this IP)</span></h3>
      <ul style="margin:0;padding-left:18px;font-family:var(--mono);font-size:12px">${relatedHTML}</ul>
    </div>

    <div class="ipinfo-card">
      <h3>Top binaries that talked to this IP</h3>
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Binary</th></tr></thead>
        <tbody>${topBinsHTML}</tbody></table></div>
    </div>

    <div class="ipinfo-card">
      <h3>Recent flows (7d, click a row for full flow analysis)</h3>
      <div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>Binary</th><th>Dest CIDR</th><th>Port</th><th class="num">Out</th><th class="num">In</th><th class="num">Connects</th><th>Last seen</th></tr></thead>
        <tbody>${flowsHTML}</tbody>
      </table></div>
    </div>

    ${cohortHTML}

    <div class="ipinfo-card">
      <h3>Whois</h3>
      <div id="whois-body"><button class="btn-ghost" id="whois-load">Load whois (5s shell-out to /usr/bin/whois)</button></div>
    </div>
  `;

  view.querySelector('#ip-back').addEventListener('click', () => history.back());
  const sb = view.querySelector('#susp-banner');
  if (sb) {
    sb.addEventListener('click', () => sb.classList.toggle('expanded'));
  }
  view.querySelectorAll('tr[data-flow-href]').forEach(tr => {
    tr.addEventListener('click', () => go(tr.dataset.flowHref));
  });
  view.querySelectorAll('tr[data-binary]').forEach(tr => {
    tr.addEventListener('click', () => go('/egress/process/' + encodeURIComponent(tr.dataset.binary)));
  });
  const wb = view.querySelector('#whois-load');
  if (wb) {
    wb.addEventListener('click', async () => {
      wb.disabled = true;
      wb.textContent = 'Loading…';
      const w = await fetchJSON('/api/egress/ipinfo?whois=1&ip=' + encodeURIComponent(ip));
      const box = view.querySelector('#whois-body');
      if (w && w.whois) {
        box.innerHTML = `<pre class="whois-pre">${esc(w.whois)}</pre>`;
      } else {
        box.innerHTML = `<div class="dim">no whois data — /usr/bin/whois may not be installed, or the query timed out (5s).</div>`;
      }
    });
  }
}

// ─── Flow analysis ─────────────────────────────────────────────

async function renderFlowAnalysis(view) {
  const binary = state.selectedFlowBinary;
  const dest   = state.selectedFlowDest;
  const port   = state.selectedFlowPort;
  if (!binary || !dest) {
    view.innerHTML = `<div class="placeholder"><strong>No flow selected</strong>Click any flow row in the dashboard to land here.</div>`;
    return;
  }
  const url = '/api/egress/flow?binary=' + encodeURIComponent(binary) +
              '&dest_cidr=' + encodeURIComponent(dest) +
              '&port=' + encodeURIComponent(port || 0);
  const d = await fetchJSON(url);
  if (!d) {
    view.innerHTML = `<div class="placeholder"><strong>Lookup failed</strong>could not load flow analysis.</div>`;
    return;
  }

  const initiator = d.initiator
    ? `<div class="ipinfo-grid">
        <div class="k">PID</div><div class="v">${esc(d.initiator.pid)}</div>
        <div class="k">PPID</div><div class="v">${esc(d.initiator.ppid)}</div>
        <div class="k">Parent comm</div><div class="v">${esc(d.initiator.parent_comm || '—')}</div>
        <div class="k">Opened at</div><div class="v">${fmtTime(d.initiator.opened_at)}</div>
       </div>`
    : '<div class="dim">no live initiator — flow is historical only.</div>';

  const series = (d.timeline || []).map(p => ({ x: p.hour, out: p.bytes_out, in: p.bytes_in }));
  const chartHTML = series.length > 0
    ? Charts.lineChart([
        { name: 'out', color: '#ee8033', points: series.map(s => ({ x: s.x, y: s.out })) },
        { name: 'in',  color: '#60a5fa', points: series.map(s => ({ x: s.x, y: s.in })) },
      ], { height: 200 })
    : '<div class="dim">no timeline data</div>';

  const liveHTML = (d.live_conns || []).map(c => `<tr>
      <td class="mono">${esc(c.pid)}</td>
      <td class="mono">${esc(c.comm)}</td>
      <td class="mono">${ipChip(c.dst_addr)}</td>
      <td class="mono">${esc(c.dst_port)}</td>
      <td class="num">${fmtBytes(c.bytes_out)}</td>
      <td class="num dim">${fmtBytes(c.bytes_in)}</td>
      <td><span class="pill info">${esc(c.state)}</span></td>
    </tr>`).join('') || '<tr class="empty-row"><td colspan="7">no live connections</td></tr>';

  const relatedSameBin = (d.related_flows || []).filter(r => r.reason && r.reason.indexOf('other destination') >= 0);
  const relatedSameDst = (d.related_flows || []).filter(r => r.reason && r.reason.indexOf('other binary') >= 0);
  const sameBinHTML = relatedSameBin.map(r => `<tr class="clickable" data-flow-href="/egress/flow/${encodeURIComponent(binary)}/${encodeURIComponent(r.dest_cidr)}/${encodeURIComponent(r.dest_port||0)}">
      <td class="mono">${esc(r.dest_cidr)}</td>
      <td class="mono">${esc(r.dest_port || '—')}</td>
      <td class="num">${fmtBytes(r.bytes_out)}</td>
    </tr>`).join('') || '<tr class="empty-row"><td colspan="3">none</td></tr>';
  const sameDstHTML = relatedSameDst.map(r => `<tr class="clickable" data-flow-href="/egress/flow/${encodeURIComponent(r.binary)}/${encodeURIComponent(dest)}/${encodeURIComponent(port||0)}">
      <td class="mono">${esc(r.binary)}</td>
      <td class="num">${fmtBytes(r.bytes_out)}</td>
    </tr>`).join('') || '<tr class="empty-row"><td colspan="2">none</td></tr>';

  const lineageHTML = (d.source_lineage || []).length
    ? d.source_lineage.map(s => esc(s)).join(' → ')
    : '<span class="dim">no lineage available (proctree unwired or PID gone)</span>';

  const destIP = (dest || '').split('/')[0];

  view.innerHTML = `
    <div class="toolbar">
      <button class="btn-ghost" id="flow-back">← back</button>
      <h1 class="mono" style="margin:0">${esc(binary)} <span class="dim">→</span> ${ipChip(destIP, d.dest_country)}:${esc(port || '—')}</h1>
      ${d.dest_class ? classPill(d.dest_class) : ''}
      <div class="spacer"></div>
    </div>

    <div class="hero">
      <div class="kpi"><div class="kpi-label">First seen</div><div class="kpi-value mono" style="font-size:11px">${d.first_seen ? fmtTime(d.first_seen) : '—'}</div></div>
      <div class="kpi"><div class="kpi-label">Last seen</div><div class="kpi-value mono" style="font-size:11px">${d.last_seen ? fmtTime(d.last_seen) : '—'}</div></div>
      <div class="kpi"><div class="kpi-label">Total connects</div><div class="kpi-value">${fmtNum(d.total_connects)}</div></div>
      <div class="kpi"><div class="kpi-label">Bytes out</div><div class="kpi-value">${fmtBytes(d.total_bytes_out)}</div></div>
      <div class="kpi"><div class="kpi-label">Bytes in</div><div class="kpi-value">${fmtBytes(d.total_bytes_in)}</div></div>
      <div class="kpi"><div class="kpi-label">Peak hourly out</div><div class="kpi-value">${fmtBytes(d.peak_out_bytes)}</div></div>
    </div>

    <div class="ipinfo-card"><h3>Initiator</h3>${initiator}</div>

    <div class="ipinfo-card"><h3>Timeline (hourly, 7d)</h3>${chartHTML}</div>

    <div class="ipinfo-card">
      <h3>Live connections</h3>
      <div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>PID</th><th>Comm</th><th>Dest</th><th>Port</th><th class="num">Out</th><th class="num">In</th><th>State</th></tr></thead>
        <tbody>${liveHTML}</tbody>
      </table></div>
    </div>

    <div class="ipinfo-card">
      <h3>Source lineage</h3>
      <div class="mono">${lineageHTML}</div>
    </div>

    <div class="ipinfo-card">
      <h3>Related flows</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div>
          <div class="dim" style="font-size:11px;margin-bottom:4px">Other destinations this binary talks to</div>
          <div class="tbl-wrap"><table class="tbl">
            <thead><tr><th>Dest CIDR</th><th>Port</th><th class="num">Bytes out</th></tr></thead>
            <tbody>${sameBinHTML}</tbody>
          </table></div>
        </div>
        <div>
          <div class="dim" style="font-size:11px;margin-bottom:4px">Other binaries that talk to ${esc(dest)}</div>
          <div class="tbl-wrap"><table class="tbl">
            <thead><tr><th>Binary</th><th class="num">Bytes out</th></tr></thead>
            <tbody>${sameDstHTML}</tbody>
          </table></div>
        </div>
      </div>
    </div>

    <div class="ipinfo-card">
      <h3>Actions</h3>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn-ghost" id="flow-capture">▶ Start packet capture</button>
        <button class="btn-ghost" id="flow-sign-policy">Sign per-binary policy</button>
        <button class="btn-ghost" id="flow-block-ip">Block IP via safety net</button>
      </div>
      <div class="dim" style="margin-top:6px;font-size:11px">Actions are wired against the existing capture / policy / safety-net APIs.</div>
    </div>
  `;

  view.querySelector('#flow-back').addEventListener('click', () => history.back());
  view.querySelectorAll('tr[data-flow-href]').forEach(tr => {
    tr.addEventListener('click', () => go(tr.dataset.flowHref));
  });
  view.querySelector('#flow-capture').addEventListener('click', () => {
    if (typeof openCaptureModal === 'function') {
      openCaptureModal('host ' + destIP);
    } else {
      go('/egress/captures');
    }
  });
  view.querySelector('#flow-sign-policy').addEventListener('click', () => {
    go('/egress/policy/review/' + encodeURIComponent(binary));
  });
  view.querySelector('#flow-block-ip').addEventListener('click', async () => {
    if (!confirm('Block ' + destIP + '/32 via safety-net?')) return;
    try {
      const r = await fetch('/api/safety/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cidr: destIP + '/32' }),
      });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(body.error || ('HTTP ' + r.status));
      if (typeof toast === 'function') toast('blocked ' + destIP, 'ok');
      else alert('blocked ' + destIP);
    } catch (e) {
      if (typeof toast === 'function') toast('block failed: ' + e.message, 'err');
      else alert('block failed: ' + e.message);
    }
  });
}

// ─── Internal Network ─────────────────────────────────────────
//
// Dedicated view for the traffic that the public-default dashboards
// hide. The /api/egress/internal endpoint aggregates last 1h of
// internal flows from the ledger; this renderer surfaces IMDS abuse,
// lateral-movement candidates, and folds docker-proxy noise into a
// collapsed card so it can be inspected but doesn't dominate.

async function renderInternal(view) {
  const data = await fetchJSON('/api/egress/internal') || {};
  const totalFlows = data.total_flows || 0;
  const perBin = data.per_binary || [];
  const imds = data.imds_contacts || [];
  const lateral = data.lateral_candidates || [];
  const cgroups = data.per_cgroup || [];

  // Header KPI strip.
  const heroHTML = `
    <div class="hero">
      <div class="kpi">
        <div class="kpi-label">Internal bytes out</div>
        <div class="kpi-value">${fmtBytes(data.total_bytes_out || 0)}</div>
        <div class="kpi-sub">last hour · ${fmtNum(totalFlows)} flows</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Binaries</div>
        <div class="kpi-value">${fmtNum(perBin.length)}</div>
        <div class="kpi-sub">${fmtBytes(data.total_bytes_in || 0)} bytes in</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">IMDS contacts</div>
        <div class="kpi-value" style="color:${imds.length>0?'var(--err)':'inherit'}">${fmtNum(imds.length)}</div>
        <div class="kpi-sub">169.254.169.254 touchers</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Lateral candidates</div>
        <div class="kpi-value" style="color:${lateral.length>0?'var(--warn,#e0a000)':'inherit'}">${fmtNum(lateral.length)}</div>
        <div class="kpi-sub">&gt;5 distinct internal /24s</div>
      </div>
    </div>`;

  // IMDS banner.
  const imdsHTML = imds.length === 0 ? '' : `
    <div class="imds-banner">
      🚨 IMDS contacts — ${imds.length} flow${imds.length===1?'':'s'} to 169.254.169.254 in the last hour
    </div>
    <div class="card" style="margin-bottom:12px">
      <div class="card-head"><h2>IMDS access</h2><div class="right">cloud metadata · last 1h</div></div>
      <div class="tbl-wrap" style="border:0">
        <table class="tbl"><thead><tr>
          <th>Binary</th><th>Dest</th><th>Port</th>
          <th class="num">Connects</th><th>Last seen</th>
        </tr></thead><tbody>
        ${imds.map(r => `<tr>
          <td class="mono">${esc(r.binary || '?')}</td>
          <td class="mono">${esc(r.dest_cidr || '')}</td>
          <td class="mono">${esc(r.dest_port)}</td>
          <td class="num">${fmtNum(r.connects)}</td>
          <td class="mono dim">${fmtTime(r.last_seen)}</td>
        </tr>`).join('')}
        </tbody></table>
      </div>
    </div>`;

  // Lateral movement candidates.
  const lateralHTML = lateral.length === 0 ? '' : `
    <div class="card" style="margin-bottom:12px;border-color:var(--warn,#a07000)">
      <div class="card-head"><h2>🚨 Lateral movement candidates</h2><div class="right">heuristic · &gt;5 internal /24s</div></div>
      <div class="tbl-wrap" style="border:0">
        <table class="tbl"><thead><tr>
          <th>Binary</th><th>Top target</th><th>Port</th>
          <th class="num">Connects</th><th>Last seen</th>
        </tr></thead><tbody>
        ${lateral.map(r => `<tr>
          <td class="mono">${esc(r.binary || '?')}</td>
          <td class="mono">${esc(r.dest_cidr || '')}</td>
          <td class="mono">${esc(r.dest_port)}</td>
          <td class="num">${fmtNum(r.connects)}</td>
          <td class="mono dim">${fmtTime(r.last_seen)}</td>
        </tr>`).join('')}
        </tbody></table>
      </div>
    </div>`;

  // Separate docker-proxy from everything else; docker is folded by default.
  const dockerBins = perBin.filter(b => /docker-proxy|containerd|dockerd/.test(b.binary || ''));
  const otherBins  = perBin.filter(b => !/docker-proxy|containerd|dockerd/.test(b.binary || ''));

  function binRowsHTML(rows) {
    if (rows.length === 0) {
      return '<tr class="empty-row"><td colspan="6">no internal traffic</td></tr>';
    }
    return rows.map(b => `<tr>
      <td class="mono">${esc(b.binary || '?')}</td>
      <td class="num">${fmtBytes(b.bytes_out)}</td>
      <td class="num dim">${fmtBytes(b.bytes_in)}</td>
      <td class="num dim">${fmtNum(b.connects)}</td>
      <td class="num" style="color:${(b.distinct_internal_24s||0)>5?'var(--warn,#e0a000)':'inherit'}">${fmtNum(b.distinct_internal_24s||0)}</td>
      <td class="mono dim">${(b.top_targets||[]).slice(0,3).map(esc).join(', ') || '—'}</td>
    </tr>`).join('');
  }

  const perBinHTML = `
    <div class="card" style="margin-bottom:12px">
      <div class="card-head"><h2>Per-binary internal activity</h2><div class="right">last 1h · sorted by bytes-out</div></div>
      <div class="tbl-wrap" style="border:0">
        <table class="tbl"><thead><tr>
          <th>Binary</th>
          <th class="num">Bytes out</th><th class="num">Bytes in</th>
          <th class="num">Connects</th>
          <th class="num" title="distinct internal /24 subnets contacted">/24s</th>
          <th>Top targets</th>
        </tr></thead><tbody>
        ${binRowsHTML(otherBins)}
        </tbody></table>
      </div>
    </div>`;

  // Docker bridge — collapsed by default (it's the noisy one).
  if (state.internalDockerOpen === undefined) state.internalDockerOpen = false;
  const dockerHTML = dockerBins.length === 0 ? '' : `
    <div class="card" style="margin-bottom:12px">
      <div class="card-head">
        <h2>Docker bridge traffic <span class="pill dim">${dockerBins.length} binar${dockerBins.length===1?'y':'ies'}</span></h2>
        <div class="right">
          <button class="btn-ghost" id="docker-toggle">${state.internalDockerOpen ? 'hide' : 'show'}</button>
        </div>
      </div>
      ${state.internalDockerOpen ? `
      <div class="tbl-wrap" style="border:0">
        <table class="tbl"><thead><tr>
          <th>Binary</th>
          <th class="num">Bytes out</th><th class="num">Bytes in</th>
          <th class="num">Connects</th>
          <th class="num">/24s</th>
          <th>Top targets</th>
        </tr></thead><tbody>
        ${binRowsHTML(dockerBins)}
        </tbody></table>
      </div>` : '<div class="dim" style="padding:8px 14px">collapsed — click "show" to expand the noisy docker chatter</div>'}
    </div>`;

  // Per-cgroup card (optional).
  const cgroupHTML = cgroups.length === 0 ? '' : `
    <div class="card" style="margin-bottom:12px">
      <div class="card-head"><h2>Per-cgroup</h2><div class="right">${cgroups.length} cgroup${cgroups.length===1?'':'s'}</div></div>
      <div class="tbl-wrap" style="border:0">
        <table class="tbl"><thead><tr>
          <th>CGroup ID</th>
          <th class="num">Bytes out</th><th class="num">Bytes in</th>
          <th class="num">Connects</th><th class="num">Dests</th>
        </tr></thead><tbody>
        ${cgroups.map(c => `<tr>
          <td class="mono">${esc(c.cgroup_id)}</td>
          <td class="num">${fmtBytes(c.bytes_out)}</td>
          <td class="num dim">${fmtBytes(c.bytes_in)}</td>
          <td class="num dim">${fmtNum(c.connects)}</td>
          <td class="num dim">${fmtNum(c.distinct_ips)}</td>
        </tr>`).join('')}
        </tbody></table>
      </div>
    </div>`;

  const emptyHTML = (totalFlows === 0) ? `
    <div class="placeholder"><strong>No internal traffic observed in the last hour.</strong>The ledger has not seen any flows to private / loopback / link-local destinations. If the agent runs with <code>exclude_private: true</code> the ledger never recorded them in the first place.</div>
  ` : '';

  view.innerHTML = `
    <div class="toolbar">
      <h1>Internal Network</h1>
      <div class="spacer"></div>
      <span class="pill dim">last 1h · ${fmtNum(totalFlows)} flows</span>
    </div>
    ${heroHTML}
    ${imdsHTML}
    ${lateralHTML}
    ${emptyHTML}
    ${perBinHTML}
    ${dockerHTML}
    ${cgroupHTML}`;

  const tgl = view.querySelector('#docker-toggle');
  if (tgl) {
    tgl.addEventListener('click', () => {
      state.internalDockerOpen = !state.internalDockerOpen;
      renderInternal(view);
    });
  }
}

})();

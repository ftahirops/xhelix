// xhelix UI — visualisations.
// Pure SVG, no D3, no external scripts. All DOM via createElementNS.

const SVG_NS = "http://www.w3.org/2000/svg";

// ── shared helpers ───────────────────────────────────────────

function svg(tag, attrs, parent) {
  const el = document.createElementNS(SVG_NS, tag);
  if (attrs) {
    for (const k of Object.keys(attrs)) {
      if (attrs[k] != null) el.setAttribute(k, attrs[k]);
    }
  }
  if (parent) parent.appendChild(el);
  return el;
}

function clearSVG(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
}

// ── T5.4 — force-directed graph ───────────────────────────────
//
// Velocity-Verlet integration. Nodes have x,y,vx,vy.
// Forces: pairwise repulsion (Coulomb-shape), spring along edges,
// centring drift toward (cx, cy). ~50 ticks reaches equilibrium
// for graphs up to ~200 nodes — plenty for an EDR's per-host view.

function renderForceGraph(svgEl, data, stats) {
  clearSVG(svgEl);
  if (!data || !data.nodes || data.nodes.length === 0) {
    const t = svg("text", { x: 500, y: 300, "text-anchor": "middle", fill: "#8b949e" }, svgEl);
    t.textContent = "no traffic in this window";
    stats.textContent = "0 nodes";
    return;
  }

  const W = 1000, H = 600, cx = W / 2, cy = H / 2;
  const nodes = data.nodes.map((n, i) => ({
    id: n.id, label: n.label, group: n.group || "dst",
    bytes: n.bytes || 0,
    x: cx + (Math.cos(i) * 250),
    y: cy + (Math.sin(i) * 200),
    vx: 0, vy: 0,
  }));
  const idIndex = new Map(nodes.map((n, i) => [n.id, i]));
  const links = (data.links || []).map((l) => ({
    s: idIndex.get(l.source), t: idIndex.get(l.target),
    weight: l.weight || 1,
  })).filter((l) => l.s != null && l.t != null);

  // Tick the simulation N times before render — synchronous,
  // bounded, and the viewer sees the result laid out.
  const ITERS = 200;
  const REPEL = 5000;
  const SPRING_K = 0.05;
  const SPRING_L = 80;
  const DAMP = 0.85;
  const CENTRE_PULL = 0.005;

  for (let it = 0; it < ITERS; it++) {
    // pairwise repulsion
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        let dx = nodes[j].x - nodes[i].x;
        let dy = nodes[j].y - nodes[i].y;
        let dist2 = dx * dx + dy * dy + 1;
        let dist = Math.sqrt(dist2);
        let f = REPEL / dist2;
        let fx = (f * dx) / dist;
        let fy = (f * dy) / dist;
        nodes[i].vx -= fx; nodes[i].vy -= fy;
        nodes[j].vx += fx; nodes[j].vy += fy;
      }
    }
    // spring along links
    for (const l of links) {
      const s = nodes[l.s], t = nodes[l.t];
      let dx = t.x - s.x, dy = t.y - s.y;
      let dist = Math.sqrt(dx * dx + dy * dy) + 0.01;
      let f = SPRING_K * (dist - SPRING_L);
      let fx = (f * dx) / dist, fy = (f * dy) / dist;
      s.vx += fx; s.vy += fy;
      t.vx -= fx; t.vy -= fy;
    }
    // centre pull + damping + integrate
    for (const n of nodes) {
      n.vx = (n.vx + (cx - n.x) * CENTRE_PULL) * DAMP;
      n.vy = (n.vy + (cy - n.y) * CENTRE_PULL) * DAMP;
      n.x += n.vx;
      n.y += n.vy;
      // bound
      n.x = Math.max(20, Math.min(W - 20, n.x));
      n.y = Math.max(20, Math.min(H - 20, n.y));
    }
  }

  // Render links first so nodes draw on top.
  for (const l of links) {
    const s = nodes[l.s], t = nodes[l.t];
    svg("line", {
      class: "link",
      x1: s.x, y1: s.y, x2: t.x, y2: t.y,
      "stroke-width": Math.min(4, 0.5 + Math.log10(l.weight + 1)),
    }, svgEl);
  }
  for (const n of nodes) {
    const r = Math.min(20, 4 + Math.log10(n.bytes + 1) * 1.5);
    const grp = svg("g", { class: "node", transform: `translate(${n.x},${n.y})` }, svgEl);
    svg("circle", {
      r, fill: n.group === "proc" ? "#58a6ff" : "#56d364",
    }, grp);
    if (r > 6) {
      svg("text", { x: r + 3, y: 4 }, grp).textContent = n.label;
    }
  }

  stats.textContent = `${nodes.length} nodes · ${links.length} edges`;
}

// ── T5.5 — geographic map (equirectangular) ──────────────────
//
// No country geometry shipped — we render a coarse coastline grid
// plus per-country aggregation dots at country-centroid coords.
// The full world topoJSON is several hundred KB; we ship just the
// 60-ish centroids most relevant to traffic-distribution UI.

const COUNTRY_CENTROID = {
  US: [-98, 39], CA: [-106, 56], MX: [-102, 23], BR: [-53, -10], AR: [-65, -34],
  GB: [-2, 54], IE: [-8, 53], FR: [2, 46], DE: [10, 51], NL: [5, 52], BE: [4, 50],
  CH: [8, 47], AT: [14, 47], IT: [12, 42], ES: [-4, 40], PT: [-8, 39], SE: [18, 60],
  NO: [10, 60], FI: [26, 64], DK: [10, 56], PL: [19, 52], CZ: [15, 50], SK: [19, 48],
  HU: [20, 47], RO: [25, 46], BG: [25, 43], GR: [22, 39], TR: [35, 39], UA: [32, 49],
  RU: [60, 60], BY: [28, 53], LV: [25, 57], LT: [24, 56], EE: [26, 59],
  CN: [104, 35], JP: [138, 36], KR: [128, 36], IN: [78, 21], PK: [70, 30], BD: [90, 24],
  TH: [101, 15], VN: [108, 16], MY: [102, 4], SG: [104, 1.3], ID: [113, -1], PH: [122, 12],
  AU: [134, -27], NZ: [173, -41],
  EG: [30, 27], ZA: [25, -30], NG: [8, 9], KE: [38, -1], ET: [40, 9], MA: [-7, 32], DZ: [3, 28],
  IL: [35, 31], AE: [54, 24], SA: [45, 24], IR: [54, 32], IQ: [44, 33], QA: [51, 25],
  CL: [-71, -30], CO: [-72, 4], PE: [-75, -10], VE: [-66, 8], EC: [-79, -2],
  ZZ: [0, 0],
};

function renderGeoMap(svgEl, data, stats) {
  clearSVG(svgEl);
  // Coarse latitude/longitude grid (16-segment world frame).
  for (let lat = -60; lat <= 60; lat += 30) {
    svg("line", {
      class: "land", x1: -180, y1: -lat, x2: 180, y2: -lat,
      stroke: "#30363d", "stroke-width": 0.2,
    }, svgEl);
  }
  for (let lon = -180; lon <= 180; lon += 30) {
    svg("line", {
      class: "land", x1: lon, y1: -90, x2: lon, y2: 90,
      stroke: "#30363d", "stroke-width": 0.2,
    }, svgEl);
  }

  if (!data || !data.countries || data.countries.length === 0) {
    const t = svg("text", { x: 0, y: 0, "text-anchor": "middle", fill: "#8b949e", "font-size": 6 }, svgEl);
    t.textContent = "no traffic data";
    stats.textContent = "0 countries";
    return;
  }

  const maxBytes = data.countries.reduce((m, c) => Math.max(m, c.bytes || 0), 1);
  let totalBytes = 0;
  for (const c of data.countries) {
    const centroid = COUNTRY_CENTROID[c.country] || COUNTRY_CENTROID.ZZ;
    const r = 1 + Math.log10((c.bytes || 0) + 1) * 0.6;
    const verdict = c.worstVerdict || "green";
    const dot = svg("circle", {
      class: "dot" + (verdict !== "green" ? " " + verdict : ""),
      cx: centroid[0], cy: -centroid[1], r,
    }, svgEl);
    const title = svg("title", null, dot);
    title.textContent = `${c.country}: ${human(c.bytes || 0)} (${c.connections} conns)`;
    totalBytes += c.bytes || 0;
    if (r > 3) {
      const label = svg("text", {
        x: centroid[0] + r + 0.5, y: -centroid[1] + 1,
        "font-size": 3, fill: "#c9d1d9",
      }, svgEl);
      label.textContent = c.country;
    }
  }
  stats.textContent = `${data.countries.length} countries · ${human(totalBytes)} total`;
  // Suppress unused warning on maxBytes
  void maxBytes;
}

// ── T5.6 — Sankey flow diagram ───────────────────────────────
//
// Two-column bipartite Sankey: apps on the left, destinations on
// the right, link widths proportional to bytes.

function renderSankey(svgEl, data, stats) {
  clearSVG(svgEl);
  if (!data || !data.links || data.links.length === 0) {
    const t = svg("text", { x: 500, y: 300, "text-anchor": "middle", fill: "#8b949e" }, svgEl);
    t.textContent = "no flows to render";
    stats.textContent = "0 flows";
    return;
  }
  const W = 1000, H = 600, BAND_W = 18;

  // Aggregate per-app and per-dst totals.
  const apps = new Map();
  const dsts = new Map();
  for (const l of data.links) {
    apps.set(l.app, (apps.get(l.app) || 0) + l.bytes);
    dsts.set(l.dst, (dsts.get(l.dst) || 0) + l.bytes);
  }

  // Sort + take top N (Sankey gets unreadable above ~25 per side).
  const TOP = 25;
  const appList = [...apps.entries()].sort((a, b) => b[1] - a[1]).slice(0, TOP);
  const dstList = [...dsts.entries()].sort((a, b) => b[1] - a[1]).slice(0, TOP);
  const appSet = new Set(appList.map((a) => a[0]));
  const dstSet = new Set(dstList.map((d) => d[0]));

  // Recompute totals from the trimmed sets so band heights match link weights.
  const total = appList.reduce((s, a) => s + a[1], 0);
  if (total === 0) {
    const t = svg("text", { x: 500, y: 300, "text-anchor": "middle", fill: "#8b949e" }, svgEl);
    t.textContent = "no flows after trimming";
    stats.textContent = "0";
    return;
  }
  const scaleY = (H - 40) / total;

  // App bands on the left.
  const appPos = new Map();
  let y = 20;
  for (const [name, bytes] of appList) {
    const h = bytes * scaleY;
    svg("rect", { class: "left", x: 20, y, width: BAND_W, height: h }, svgEl);
    if (h > 10) {
      const t = svg("text", { x: 44, y: y + h / 2 + 4 }, svgEl);
      t.textContent = name.length > 28 ? name.slice(0, 28) + "…" : name;
    }
    appPos.set(name, { yStart: y, yEnd: y + h, yCursor: y });
    y += h + 2;
  }

  // Dst bands on the right.
  const dstPos = new Map();
  y = 20;
  for (const [name, bytes] of dstList) {
    const h = bytes * scaleY;
    svg("rect", { class: "right", x: W - 20 - BAND_W, y, width: BAND_W, height: h }, svgEl);
    if (h > 10) {
      const t = svg("text", {
        x: W - 24 - BAND_W, y: y + h / 2 + 4, "text-anchor": "end",
      }, svgEl);
      t.textContent = name.length > 28 ? name.slice(0, 28) + "…" : name;
    }
    dstPos.set(name, { yStart: y, yEnd: y + h, yCursor: y });
    y += h + 2;
  }

  // Links as Bezier ribbons.
  const ribbons = data.links
    .filter((l) => appSet.has(l.app) && dstSet.has(l.dst))
    .sort((a, b) => b.bytes - a.bytes);
  for (const l of ribbons) {
    const a = appPos.get(l.app);
    const d = dstPos.get(l.dst);
    if (!a || !d) continue;
    const h = l.bytes * scaleY;
    const x0 = 20 + BAND_W;
    const x1 = W - 20 - BAND_W;
    const ay0 = a.yCursor;
    const ay1 = a.yCursor + h;
    const dy0 = d.yCursor;
    const dy1 = d.yCursor + h;
    a.yCursor = ay1;
    d.yCursor = dy1;
    const path =
      `M ${x0} ${ay0} ` +
      `C ${(x0 + x1) / 2} ${ay0}, ${(x0 + x1) / 2} ${dy0}, ${x1} ${dy0} ` +
      `L ${x1} ${dy1} ` +
      `C ${(x0 + x1) / 2} ${dy1}, ${(x0 + x1) / 2} ${ay1}, ${x0} ${ay1} ` +
      `Z`;
    svg("path", { class: "link", d: path }, svgEl);
  }

  stats.textContent = `${ribbons.length} flows · ${human(total)} total`;
}

// ── data adapters ────────────────────────────────────────────
//
// The UI calls /api/v1/history once and synthesises whichever
// shape each visualisation needs. This keeps the daemon's API
// surface narrow.

async function fetchActivities() {
  const r = await fetch("/api/v1/history?since=24h");
  const j = await r.json();
  return Array.isArray(j) ? j : (j.activities || []);
}

function activitiesToGraph(activities) {
  const nodes = new Map();
  const links = new Map();
  const ensure = (id, label, group, bytes) => {
    const cur = nodes.get(id);
    if (cur) {
      cur.bytes += bytes;
      return cur;
    }
    const n = { id, label, group, bytes };
    nodes.set(id, n);
    return n;
  };
  for (const a of activities) {
    const exe = a.exe || a.ProcessExe || "(unknown)";
    const host = a.primary_host || a.PrimaryHost || a.primary_ip || "(direct)";
    const bytesIn = a.bytes_in || a.BytesIn || 0;
    const bytesOut = a.bytes_out || a.BytesOut || 0;
    const total = bytesIn + bytesOut;
    ensure("proc:" + exe, basename(exe), "proc", total);
    ensure("dst:" + host, host, "dst", total);
    const lk = "proc:" + exe + "→dst:" + host;
    links.set(lk, (links.get(lk) || 0) + total);
  }
  return {
    nodes: [...nodes.values()],
    links: [...links.entries()].map(([k, w]) => {
      const [s, t] = k.split("→");
      return { source: s, target: t, weight: w };
    }),
  };
}

function activitiesToCountries(activities) {
  const map = new Map();
  for (const a of activities) {
    const countries = a.countries || a.Countries || [];
    const bytes = (a.bytes_in || 0) + (a.bytes_out || 0);
    const verdict = String(a.verdict || a.Verdict || "green").toLowerCase();
    for (const c of countries) {
      const cur = map.get(c) || { country: c, bytes: 0, connections: 0, worstVerdict: "green" };
      cur.bytes += bytes;
      cur.connections += a.flow_count || a.FlowCount || 1;
      if (verdictRank(verdict) > verdictRank(cur.worstVerdict)) {
        cur.worstVerdict = verdict;
      }
      map.set(c, cur);
    }
  }
  return { countries: [...map.values()] };
}

function activitiesToSankey(activities) {
  const links = [];
  for (const a of activities) {
    const exe = basename(a.exe || a.ProcessExe || "(unknown)");
    const dst = a.primary_host || a.PrimaryHost || a.primary_ip || "(direct)";
    const bytes = (a.bytes_in || 0) + (a.bytes_out || 0);
    if (bytes > 0) links.push({ app: exe, dst, bytes });
  }
  return { links };
}

function verdictRank(v) {
  return ({ green: 1, advise: 2, amber: 3, red: 4, opaque: 2 }[v] || 0);
}

function basename(p) {
  if (!p) return "";
  const i = p.lastIndexOf("/");
  return i >= 0 ? p.slice(i + 1) : p;
}

function human(n) {
  if (!n) return "0 B";
  const k = 1024;
  if (n < k) return n + " B";
  if (n < k * k) return (n / k).toFixed(1) + " KB";
  if (n < k * k * k) return (n / (k * k)).toFixed(1) + " MB";
  return (n / (k * k * k)).toFixed(2) + " GB";
}

// ── wiring ───────────────────────────────────────────────────

// processesToGraph builds force-graph data for renderForceGraph,
// which expects {nodes:[{id,label,group,bytes}], links:[{source,target,weight}]}.
function processesToGraph(procs) {
  const nodes = [];
  const links = [];
  const seen  = new Set();
  procs.forEach((p) => {
    if ((p.total_flows || 0) === 0) return;
    const pid = "p" + p.pid;
    if (!seen.has(pid)) {
      nodes.push({ id: pid, label: p.comm || ("pid " + p.pid), group: "process",
                   bytes: (p.bytes_in || 0) + (p.bytes_out || 0) });
      seen.add(pid);
    }
    (p.top_dsts || []).slice(0, 4).forEach((d) => {
      const did = "d:" + d.key;
      if (!seen.has(did)) {
        nodes.push({ id: did, label: d.key, group: "dst", bytes: 0 });
        seen.add(did);
      }
      links.push({ source: pid, target: did, weight: d.count || 1 });
    });
  });
  return { nodes, links };
}

// processesToSankey returns the shape renderSankey expects:
// {links: [{app, dst, bytes}]}. We collapse to (process-group → verdict-layer).
function processesToSankey(procs) {
  const agg = new Map(); // "group||layer" -> bytes
  procs.forEach((p) => {
    const b = (p.bytes_in || 0) + (p.bytes_out || 0) + (p.rate_30s_bytes || 0);
    if (b === 0) return;
    const g = p.group || "other";
    const l = p.verdict_layer || "default";
    const k = g + "||" + l;
    agg.set(k, (agg.get(k) || 0) + b);
  });
  return {
    links: [...agg.entries()].map(([k, v]) => {
      const [app, dst] = k.split("||");
      return { app, dst, bytes: v };
    }),
  };
}

async function fetchProcesses() {
  const r = await fetch("/api/v1/processes");
  const j = await r.json();
  return j.processes || [];
}

async function refreshGraph() {
  const data = processesToGraph(await fetchProcesses());
  renderForceGraph(
    document.getElementById("force-graph"),
    data,
    document.getElementById("graph-stats"),
  );
}

async function refreshGeo() {
  // Geo is gated on GeoIP; the placeholder card explains.
  const s = document.getElementById("geo-stats");
  if (s) s.textContent = "GeoIP database not loaded";
}

async function refreshSankey() {
  const data = processesToSankey(await fetchProcesses());
  renderSankey(
    document.getElementById("sankey-flow"),
    data,
    document.getElementById("sankey-stats"),
  );
}

document.getElementById("graph-refresh").addEventListener("click", refreshGraph);
document.getElementById("geo-refresh").addEventListener("click", refreshGeo);
document.getElementById("sankey-refresh").addEventListener("click", refreshSankey);

// Re-render whenever the user clicks the corresponding tab.
document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    switch (t.dataset.view) {
      case "graph": refreshGraph(); break;
      case "geo": refreshGeo(); break;
      case "sankey": refreshSankey(); break;
    }
  });
});

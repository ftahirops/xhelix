// processes tab — grouped, filterable, with per-process sparkline.
// Pulls /api/v1/processes for the list and /api/v1/process/<pid> for
// the drill panel. Pure createElement; no innerHTML on server text.

(function () {
  const tableEl = document.getElementById("processes-table");
  const filterEl = document.getElementById("proc-filter");
  const refreshEl = document.getElementById("proc-refresh");
  const statsEl = document.getElementById("proc-stats");
  const autoEl = document.getElementById("proc-auto");
  const groupEl = document.getElementById("proc-group");
  const onlyAlive = document.getElementById("proc-only-alive");
  const onlyTraffic = document.getElementById("proc-only-traffic");
  const onlyAnomaly = document.getElementById("proc-only-anomaly");
  const onlyNonAllow = document.getElementById("proc-only-non-allow");
  if (!tableEl) return;

  let sortBy = "rate_30s_bytes";
  let sortDesc = true;
  let lastRows = [];
  let timer = null;

  function fmtBytes(n) {
    if (!n) return "0";
    const k = 1024;
    if (n < k) return n + " B";
    if (n < k * k) return (n / k).toFixed(1) + " K";
    if (n < k * k * k) return (n / (k * k)).toFixed(1) + " M";
    return (n / (k * k * k)).toFixed(2) + " G";
  }
  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function badge(text, kind) { return el("span", text, "badge " + (kind || "")); }

  async function load() {
    try {
      const r = await fetch("/api/v1/processes");
      const j = await r.json();
      lastRows = j.processes || [];
      statsEl.textContent = lastRows.length + " processes";
      render();
    } catch (e) {
      statsEl.textContent = "load failed: " + e.message;
    }
  }

  function activeStateFilter() {
    const out = new Set();
    document.querySelectorAll(".proc-state-filter").forEach((c) => {
      if (c.checked) out.add(c.value);
    });
    return out;
  }

  function passes(p) {
    if (onlyAlive.checked && !p.alive) return false;
    if (onlyTraffic.checked && !(p.rate_30s_bytes && p.rate_30s_bytes > 0)) return false;
    if (onlyAnomaly.checked && !p.anomaly) return false;
    if (onlyNonAllow.checked) {
      const a = p.verdict_action || "allow";
      const hasNon = a === "deny" || a === "prompt" ||
        (p.verdict_counts && ((p.verdict_counts.deny || 0) > 0 || (p.verdict_counts.prompt || 0) > 0));
      if (!hasNon) return false;
    }

    const states = activeStateFilter();
    if (!p.alive) {
      if (!states.has("dead")) return false;
    } else if (p.state && !states.has(p.state)) {
      return false;
    }

    const q = filterEl.value.trim().toLowerCase();
    if (q) {
      const blob = ((p.comm || "") + " " + (p.exe || "") + " " + (p.cmdline || "") + " " +
                    (p.top_dsts || []).map((d) => d.key).join(" ") + " " +
                    (p.group || "")).toLowerCase();
      if (!blob.includes(q)) return false;
    }
    return true;
  }

  // Show all — clear every filter back to the most permissive setting.
  const resetBtn = document.getElementById("proc-reset");
  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      filterEl.value = "";
      onlyAlive.checked = false;
      onlyTraffic.checked = false;
      onlyAnomaly.checked = false;
      onlyNonAllow.checked = false;
      document.querySelectorAll(".proc-state-filter").forEach((c) => { c.checked = true; });
      render();
    });
  }

  function applySort(rows) {
    const cp = rows.slice();
    cp.sort((a, b) => {
      let av = a[sortBy], bv = b[sortBy];
      if (av == null) av = 0;
      if (bv == null) bv = 0;
      if (typeof av === "string") av = av.toLowerCase();
      if (typeof bv === "string") bv = bv.toLowerCase();
      if (av < bv) return sortDesc ? 1 : -1;
      if (av > bv) return sortDesc ? -1 : 1;
      return 0;
    });
    return cp;
  }

  function header(label, key) {
    const th = el("th", label);
    th.dataset.key = key;
    if (sortBy === key) th.classList.add(sortDesc ? "sort-desc" : "sort-asc");
    th.addEventListener("click", () => {
      if (sortBy === key) sortDesc = !sortDesc;
      else { sortBy = key; sortDesc = true; }
      render();
    });
    return th;
  }

  function buildColgroup() {
    const cg = document.createElement("colgroup");
    ["c-pid", "c-comm", "c-state", "c-rate", "c-flows", "c-live",
     "c-bytes", "c-bytes", "c-dst", "c-verdict", "c-flags"].forEach((c) => {
      const col = document.createElement("col");
      col.className = c;
      cg.appendChild(col);
    });
    return cg;
  }
  function buildHead() {
    const thead = el("thead");
    const tr = el("tr");
    tr.appendChild(header("pid", "pid"));
    tr.appendChild(header("comm", "comm"));
    tr.appendChild(header("state", "state"));
    tr.appendChild(header("rate 30s", "rate_30s_bytes"));
    tr.appendChild(header("flows", "total_flows"));
    tr.appendChild(header("live", "live_flows"));
    tr.appendChild(header("↑ out", "bytes_out"));
    tr.appendChild(header("↓ in", "bytes_in"));
    tr.appendChild(el("th", "top dst"));
    tr.appendChild(el("th", "verdict"));
    tr.appendChild(el("th", "flags"));
    thead.appendChild(tr);
    return thead;
  }

  function buildRow(p) {
    const tr = el("tr");
    if (p.anomaly) tr.classList.add("anom");
    if (!p.alive) tr.classList.add("dead");

    tr.appendChild(el("td", p.pid));
    const commCell = el("td");
    commCell.appendChild(el("span", p.comm || "?", "comm"));
    if (p.exe) commCell.appendChild(el("div", p.exe, "muted small"));
    tr.appendChild(commCell);

    const sCell = el("td");
    sCell.appendChild(stateBadge(p.state, p.alive));
    tr.appendChild(sCell);

    tr.appendChild(el("td", fmtBytes(p.rate_30s_bytes || 0)));
    tr.appendChild(el("td", p.total_flows));
    tr.appendChild(el("td", p.live_flows));
    tr.appendChild(el("td", fmtBytes(p.bytes_out)));
    tr.appendChild(el("td", fmtBytes(p.bytes_in)));

    const dstCell = el("td");
    (p.top_dsts || []).slice(0, 2).forEach((d) => {
      dstCell.appendChild(el("div", d.key + "  ×" + d.count, "muted small"));
    });
    tr.appendChild(dstCell);

    const vCell = el("td");
    const va = p.verdict_action || "?";
    const vl = p.verdict_layer || "";
    const kind = va === "deny" ? "deny" : (va === "prompt" ? "prompt" :
                 (vl === "knowngood" ? "ok" : (vl === "default" ? "muted" : "warn")));
    vCell.appendChild(badge(va + (vl ? " · " + vl : ""), kind));
    if (p.verdict_note) vCell.appendChild(el("div", p.verdict_note, "muted small"));
    tr.appendChild(vCell);

    const flagsCell = el("td");
    (p.flags || []).forEach((f) => flagsCell.appendChild(badge(f, "warn")));
    if (!p.alive) flagsCell.appendChild(badge("dead", "muted"));
    // Small "policy" pill — opens the per-process rule editor.
    const polBtn = el("button", "policy");
    polBtn.style.cssText = "margin-left:6px;padding:2px 8px;font-size:10px;border-radius:999px;background:var(--accent-soft);color:var(--accent);border:1px solid rgba(90,169,255,0.3);cursor:pointer;";
    polBtn.addEventListener("click", (ev) => { ev.stopPropagation(); openPolicyEditor(p); });
    flagsCell.appendChild(polBtn);
    tr.appendChild(flagsCell);

    tr.addEventListener("click", () => drill(p.pid));
    return tr;
  }

  // ── per-process policy editor ─────────────────────────────
  function openPolicyEditor(p) {
    const exe = p.exe || "";
    const comm = p.comm || "";
    const modal = el("div");
    modal.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:60;";
    const box = el("div");
    box.style.cssText = "background:var(--bg-1);border:1px solid var(--border);border-radius:10px;width:560px;max-width:92vw;padding:24px;";
    box.appendChild(el("h2", "Policy for " + (comm || exe || ("pid " + p.pid))));
    box.appendChild(el("p", exe || "(no exe path)", "muted small"));

    const help = el("p", "Add domains, IPs, ports below — one per line. Allow-only domains turns this app into default-deny: it can only talk to listed hosts.", "muted small");
    help.style.margin = "12px 0 16px 0";
    box.appendChild(help);

    function area(label, placeholder, rows) {
      const wrap = el("div");
      wrap.style.cssText = "margin-bottom:12px;";
      const l = el("label", label);
      l.style.cssText = "display:block;font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:var(--fg-muted);margin-bottom:4px;";
      wrap.appendChild(l);
      const ta = el("textarea");
      ta.placeholder = placeholder;
      ta.rows = rows || 3;
      ta.style.cssText = "width:100%;background:var(--bg-0);color:var(--fg);border:1px solid var(--border);padding:8px;border-radius:6px;font-family:var(--mono);font-size:12px;resize:vertical;box-sizing:border-box;";
      wrap.appendChild(ta);
      box.appendChild(wrap);
      return ta;
    }
    const allowDomains = area("Allow-only domains (default-deny this app)", "*.example.com\n*.api.acme.io");
    const denyDomains  = area("Deny domains",                                "*.googletagmanager.com\n*.amplitude.com");
    const denyPorts    = area("Deny destination ports",                      "25\n5353", 2);

    const actions = el("div");
    actions.style.cssText = "display:flex;gap:8px;justify-content:flex-end;margin-top:12px;";
    const save = el("button", "save & hot-reload");
    save.className = "btn-primary";
    const cancel = el("button", "cancel");
    const remove = el("button", "remove rule");
    remove.style.color = "var(--err)";
    actions.appendChild(remove);
    actions.appendChild(cancel);
    actions.appendChild(save);
    box.appendChild(actions);

    modal.appendChild(box);
    document.body.appendChild(modal);
    cancel.addEventListener("click", () => document.body.removeChild(modal));

    function parseLines(ta) {
      return ta.value.split(/\n+/).map((s) => s.trim()).filter(Boolean);
    }
    save.addEventListener("click", async () => {
      const ports = parseLines(denyPorts).map((s) => parseInt(s, 10)).filter((n) => n > 0);
      try {
        const r = await fetch("/api/v1/policy/app", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            exe, comm,
            allow_only_domains: parseLines(allowDomains),
            deny_domains:       parseLines(denyDomains),
            deny_ports:         ports,
          }),
        });
        if (!r.ok) throw new Error(await r.text() || r.statusText);
        document.body.removeChild(modal);
        load();
      } catch (e) { alert("save failed: " + e.message); }
    });
    remove.addEventListener("click", async () => {
      try {
        await fetch("/api/v1/policy/app", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ exe, comm, remove: true }),
        });
        document.body.removeChild(modal);
        load();
      } catch (e) { alert("remove failed: " + e.message); }
    });
  }

  function stateBadge(s, alive) {
    if (!alive) return badge("✗ dead", "muted");
    const map = {
      "R": ["▶ running", "ok"],
      "S": ["💤 sleep", "muted"],
      "D": ["⏳ disk-wait", "warn"],
      "I": ["○ idle", "muted"],
      "T": ["⏸ stopped", "warn"],
      "Z": ["☠ zombie", "deny"],
    };
    const m = map[s];
    return m ? badge(m[0], m[1]) : badge(s || "?", "muted");
  }

  function render() {
    while (tableEl.firstChild) tableEl.removeChild(tableEl.firstChild);
    const filtered = lastRows.filter(passes);
    const rows = applySort(filtered);
    statsEl.textContent = filtered.length + " of " + lastRows.length + " processes";

    if (!groupEl.checked) {
      const table = el("table", null, "ptable processes");
      table.appendChild(buildColgroup());
      table.appendChild(buildHead());
      const tbody = el("tbody");
      rows.forEach((p) => tbody.appendChild(buildRow(p)));
      table.appendChild(tbody);
      tableEl.appendChild(table);
      return;
    }

    // Grouped rendering: bucket by p.group, render each bucket as
    // its own collapsible table with a header bar.
    const groups = {};
    rows.forEach((p) => {
      const g = p.group || "other";
      (groups[g] = groups[g] || []).push(p);
    });
    const order = ["dev", "browser", "messenger", "media", "shell",
                   "container", "network", "ssh", "monitoring",
                   "system", "package", "other"];
    const seen = new Set();
    function emitGroup(name) {
      if (!groups[name] || seen.has(name)) return;
      seen.add(name);
      const list = groups[name];
      const wrap = el("div", null, "group-wrap");
      const head = el("div", null, "group-head");
      head.appendChild(el("span", groupLabel(name), "group-name"));
      head.appendChild(el("span", list.length + " procs · " +
        fmtBytes(list.reduce((s, p) => s + (p.rate_30s_bytes || 0), 0)) + "/30s", "muted small"));
      wrap.appendChild(head);

      const table = el("table", null, "ptable processes");
      table.appendChild(buildColgroup());
      table.appendChild(buildHead());
      const tbody = el("tbody");
      list.forEach((p) => tbody.appendChild(buildRow(p)));
      table.appendChild(tbody);
      wrap.appendChild(table);
      tableEl.appendChild(wrap);
    }
    order.forEach(emitGroup);
    // Any unknown groups go at the end.
    Object.keys(groups).forEach(emitGroup);
  }

  function groupLabel(name) {
    const labels = {
      dev: "🧑‍💻 developer tools",
      browser: "🌐 browsers",
      messenger: "💬 messaging / media apps",
      media: "🎵 media",
      shell: "⌨ shell / terminal",
      container: "📦 containers / orchestration",
      network: "🛰 network services",
      ssh: "🔑 ssh",
      monitoring: "📊 monitoring / agents",
      system: "⚙ system / init",
      package: "📥 package management",
      other: "❓ other / unclassified",
    };
    return labels[name] || name;
  }

  // ---- drill ----
  function drill(pid) {
    const aside = document.getElementById("drilldown");
    const content = document.getElementById("drill-content");
    while (content.firstChild) content.removeChild(content.firstChild);
    aside.classList.remove("hidden");
    content.appendChild(el("p", "loading pid " + pid + "...", "muted"));
    fetch("/api/v1/process/" + pid)
      .then((r) => r.json())
      .then((d) => renderDrill(d, pid))
      .catch((e) => {
        while (content.firstChild) content.removeChild(content.firstChild);
        content.appendChild(el("p", "error: " + e.message, "error"));
      });
  }

  function renderDrill(d, pid) {
    const content = document.getElementById("drill-content");
    while (content.firstChild) content.removeChild(content.firstChild);

    const treeHead = d.tree && d.tree[0] ? (d.tree[0].comm || d.tree[0].Comm || "") : "";
    content.appendChild(el("h2", "pid " + pid + " — " + treeHead));

    const meta = el("div", null, "drill-meta");
    meta.appendChild(kvLine("group", d.group || "?"));
    meta.appendChild(kvLine("state", d.state ? stateName(d.state) : "?"));
    meta.appendChild(kvLine("alive", d.alive ? "yes" : "no"));
    meta.appendChild(kvLine("exe", d.exe));
    meta.appendChild(kvLine("cwd", d.cwd));
    meta.appendChild(kvLine("cmdline", d.cmdline));
    if (d.status) {
      meta.appendChild(kvLine("uid:gid", (d.status.uid || "") + ":" + (d.status.gid || "")));
      meta.appendChild(kvLine("rss", fmtBytes((d.status.rss_kb || 0) * 1024)));
      meta.appendChild(kvLine("threads", d.status.threads));
      meta.appendChild(kvLine("cap_eff", d.status.cap_eff));
    }
    content.appendChild(meta);

    // Sparkline of bytes-per-sample over the last 10 minutes.
    if (d.history && d.history.length > 0) {
      content.appendChild(el("h3", "bytes per 5-sec sample (last " + d.history.length + " samples)"));
      content.appendChild(sparkline(d.history));
    } else {
      content.appendChild(el("p", "no history yet — let it run for ~30s", "muted small"));
    }

    // Investigate
    const actions = el("div", null, "drill-actions");
    const invBtn = el("button", "Investigate (strace 5s)");
    invBtn.className = "btn-primary";
    invBtn.addEventListener("click", () => investigate(pid));
    actions.appendChild(invBtn);
    content.appendChild(actions);

    // Tree
    content.appendChild(el("h3", "process tree"));
    const tree = el("ol", null, "ptree");
    (d.tree || []).forEach((n) => {
      const li = el("li");
      li.appendChild(el("span", "pid " + n.pid + " ", "muted small"));
      li.appendChild(el("span", n.comm || ""));
      if (n.exe) li.appendChild(el("span", " " + n.exe, "muted small"));
      tree.appendChild(li);
    });
    content.appendChild(tree);

    // Live flows
    content.appendChild(el("h3", "live + recent flows (" + (d.flows || []).length + ")"));
    const flowsTab = el("table", null, "ptable small");
    const fhead = el("thead");
    const fhr = el("tr");
    ["proto", "src→dst", "state", "↑ out", "↓ in", "dns/sni", "verdict", "opened"].forEach((h) =>
      fhr.appendChild(el("th", h)));
    fhead.appendChild(fhr);
    flowsTab.appendChild(fhead);
    const fbody = el("tbody");
    (d.flows || []).slice(0, 100).forEach((f) => {
      const tr = el("tr");
      tr.appendChild(el("td", f.proto));
      tr.appendChild(el("td", (f.src_port || "?") + " → " + f.dst_ip + ":" + f.dst_port));
      tr.appendChild(el("td", f.state));
      tr.appendChild(el("td", fmtBytes(f.bytes_out)));
      tr.appendChild(el("td", fmtBytes(f.bytes_in)));
      tr.appendChild(el("td", f.sni || f.dns_name || "-"));
      const vTd = el("td");
      const va = f.verdict_action || "?";
      const vl = f.verdict_layer || "";
      const kind = va === "deny" ? "deny" : (vl === "knowngood" ? "ok" :
                                              (vl === "default" ? "muted" : "warn"));
      vTd.appendChild(badge(va + (vl ? " · " + vl : ""), kind));
      tr.appendChild(vTd);
      tr.appendChild(el("td", f.opened_at || ""));
      fbody.appendChild(tr);

      const reasons = f.verdict_reasons || [];
      if (reasons.length > 0) {
        const rtr = el("tr", null, "reason-row");
        const td = el("td", null, "reason-cell");
        td.colSpan = 8;
        reasons.forEach((r) => td.appendChild(
          el("div", "[" + (r.layer || "") + "] " + (r.rule_id || "") + " — " + (r.note || ""), "muted small")));
        rtr.appendChild(td);
        fbody.appendChild(rtr);
      }
    });
    flowsTab.appendChild(fbody);
    content.appendChild(flowsTab);

    // Open sockets
    content.appendChild(el("h3", "open sockets (" + (d.open_sockets || []).length + ")"));
    const socksTab = el("table", null, "ptable small");
    const shead = el("thead");
    const shr = el("tr");
    ["proto", "local", "remote", "state"].forEach((h) => shr.appendChild(el("th", h)));
    shead.appendChild(shr);
    socksTab.appendChild(shead);
    const sbody = el("tbody");
    (d.open_sockets || []).forEach((s) => {
      const tr = el("tr");
      tr.appendChild(el("td", s.proto));
      tr.appendChild(el("td", s.local_ip + ":" + s.local_port));
      tr.appendChild(el("td", s.remote_ip + ":" + s.remote_port));
      tr.appendChild(el("td", s.state || "-"));
      sbody.appendChild(tr);
    });
    socksTab.appendChild(sbody);
    content.appendChild(socksTab);
  }

  function stateName(s) {
    return ({ R: "running", S: "sleeping", D: "disk-wait", I: "idle", T: "stopped", Z: "zombie" })[s] || s;
  }
  function kvLine(k, v) {
    const r = el("div", null, "row");
    r.appendChild(el("span", k, "k"));
    r.appendChild(el("span", v == null ? "-" : v, "v"));
    return r;
  }

  // sparkline returns an SVG of stacked in/out bytes per sample.
  function sparkline(history) {
    const w = 720, h = 80, pad = 4;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 " + w + " " + h);
    svg.style.width = "100%";
    svg.style.maxWidth = w + "px";
    svg.style.background = "rgba(255,255,255,0.02)";
    svg.style.border = "1px solid var(--border)";
    svg.style.borderRadius = "4px";

    // Pick the metric — prefer per-flow network bytes; fall back to
    // syscall IO totals when per-flow is zero (eBPF byte-count
    // kprobes not yet attached). Label the sparkline accordingly.
    const netTotal = history.reduce((s, x) => s + (x.bytes_in || 0) + (x.bytes_out || 0), 0);
    const useIO = netTotal === 0;
    const pickIn  = (s) => useIO ? (s.io_read  || 0) : (s.bytes_in  || 0);
    const pickOut = (s) => useIO ? (s.io_write || 0) : (s.bytes_out || 0);
    let max = 1;
    history.forEach((s) => {
      const v = pickIn(s) + pickOut(s);
      if (v > max) max = v;
    });
    const barW = (w - 2 * pad) / Math.max(history.length, 1);
    history.forEach((s, i) => {
      const inB = pickIn(s), outB = pickOut(s);
      const total = inB + outB;
      const barH = (total / max) * (h - 2 * pad);
      const x = pad + i * barW;
      const y = h - pad - barH;
      const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      rect.setAttribute("x", x);
      rect.setAttribute("y", y);
      rect.setAttribute("width", Math.max(barW - 1, 1));
      rect.setAttribute("height", barH);
      rect.setAttribute("fill", useIO ? "#a8b4ff" : "#6ee48a");
      rect.setAttribute("opacity", "0.85");
      const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
      title.textContent = s.t + " — " + (useIO ? "io" : "net") + " in " +
                          fmtBytes(inB) + " / out " + fmtBytes(outB);
      rect.appendChild(title);
      svg.appendChild(rect);
    });
    // Peak + source label
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", w - pad);
    label.setAttribute("y", 12);
    label.setAttribute("fill", "#888");
    label.setAttribute("font-size", "10");
    label.setAttribute("text-anchor", "end");
    label.textContent = (useIO ? "syscall io · " : "network · ") +
                        "peak " + fmtBytes(max) + "/5s";
    svg.appendChild(label);
    return svg;
  }

  function investigate(pid) {
    const content = document.getElementById("drill-content");
    let box = document.getElementById("investigate-result");
    if (box) box.parentNode.removeChild(box);
    box = el("div");
    box.id = "investigate-result";
    box.appendChild(el("h3", "investigation (strace running 5s)..."));
    box.appendChild(el("p", "Please wait — capturing live syscalls.", "muted"));
    content.insertBefore(box, content.children[3] || null);
    fetch("/api/v1/process/" + pid + "/investigate?seconds=5")
      .then((r) => r.json())
      .then((d) => {
        while (box.firstChild) box.removeChild(box.firstChild);
        box.appendChild(el("h3", "investigation — " + (d.syscall_count || 0) + " syscalls captured"));
        if (d.error) {
          box.appendChild(el("p", "strace error: " + d.error, "error"));
          return;
        }
        const tab = el("table", null, "ptable small");
        const head = el("thead");
        const hr = el("tr");
        ["time", "syscall", "args", "ret"].forEach((h) => hr.appendChild(el("th", h)));
        head.appendChild(hr);
        tab.appendChild(head);
        const body = el("tbody");
        (d.syscalls || []).slice(0, 300).forEach((s) => {
          const tr = el("tr");
          tr.appendChild(el("td", s.time || ""));
          tr.appendChild(el("td", s.syscall || ""));
          const a = el("td", s.args || ""); a.className = "args";
          tr.appendChild(a);
          tr.appendChild(el("td", s.ret || ""));
          body.appendChild(tr);
        });
        tab.appendChild(body);
        box.appendChild(tab);
      })
      .catch((e) => {
        while (box.firstChild) box.removeChild(box.firstChild);
        box.appendChild(el("p", "investigate failed: " + e.message, "error"));
      });
  }

  // wiring
  filterEl.addEventListener("input", render);
  refreshEl.addEventListener("click", load);
  groupEl.addEventListener("change", render);
  [onlyAlive, onlyTraffic, onlyAnomaly, onlyNonAllow].forEach((c) =>
    c.addEventListener("change", render));
  document.querySelectorAll(".proc-state-filter").forEach((c) =>
    c.addEventListener("change", render));
  autoEl.addEventListener("change", () => {
    if (autoEl.checked) timer = setInterval(load, 5000);
    else if (timer) { clearInterval(timer); timer = null; }
  });

  function maybeStart() {
    const active = document.querySelector(".tab.active");
    if (active && active.dataset.view === "processes") {
      if (!lastRows.length) load();
      if (autoEl.checked && !timer) timer = setInterval(load, 5000);
    } else if (timer) { clearInterval(timer); timer = null; }
  }
  document.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => setTimeout(maybeStart, 50)));
  maybeStart();
})();

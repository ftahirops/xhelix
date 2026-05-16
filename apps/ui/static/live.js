// live feed — aggregated, contextualised, ranked.
//
// Raw daemon events are noisy: the same rule from the same pid can
// fire dozens of times per second. This UI groups them by
// (rule_id, pid) in a rolling window, attaches a human-readable
// explanation that considers the firing process, and surfaces the
// most actionable items at the top.

(function () {
  const feed   = document.getElementById("live-feed");
  const stats  = document.getElementById("live-stats");
  const toggle = document.getElementById("live-toggle");
  if (!feed) return;

  let paused = false;
  let es = null;
  const clusters = new Map();   // (rule|pid) -> cluster
  const ROLLING_MS = 60_000;
  const STATS_LATEST = { ts: "", live: 0, closed: 0 };

  // ── context catalog: rule + comm pattern → narrative + demote flag
  const CONTEXT = [
    { rule: "mem_mprotect_rwx",
      commRe: /^(node|chrome|chromium|firefox|brave|msedge|electron|java|python|bun|deno|dart|webkit|v8)/i,
      note: "JIT compiler made memory executable — expected for this runtime.",
      demote: true },
    { rule: "mem_mprotect_rwx",
      note: "Memory page made writable+executable — shellcode pattern; inspect the process tree.",
      demote: false },
    { rule: "fim.drift",
      note: "Watched file or directory changed since last baseline." },
    { rule: "memfd_run_pattern",
      note: "Process invoked from an in-memory file descriptor — common for self-extracting installers and fileless attacks." },
    { rule: "cap.gained",
      note: "Process gained additional capabilities (e.g. CAP_NET_RAW)." },
    { rule: "contescape.detected",
      note: "pivot_root inside a container by a non-runtime process — container-escape attempt." },
    { rule: "netids.dga",
      note: "DNS query whose shape matches algorithmically-generated domains (botnet C2 indicator)." },
    { rule: "beacon.periodic_callback",
      note: "Process is calling out to a remote endpoint at suspiciously regular intervals." },
    { rule: "dnsexfil.tunnel_pattern",
      note: "DNS traffic whose entropy + TXT-fraction matches data exfiltration via DNS." },
    { rule: "ml.anomaly",
      note: "Isolation-forest scored this process's behaviour as far from its baseline." },
  ];

  function lookupContext(rule, comm) {
    for (const c of CONTEXT) {
      if (c.rule !== rule) continue;
      if (c.commRe && !c.commRe.test(comm || "")) continue;
      return c;
    }
    return { note: "Unrecognised rule. Inspect the rule or open the process drill panel for context.", demote: false };
  }

  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function fmtAgo(ms) {
    if (ms < 1000) return "now";
    if (ms < 60_000) return Math.floor(ms / 1000) + "s ago";
    if (ms < 3_600_000) return Math.floor(ms / 60_000) + "m ago";
    return Math.floor(ms / 3_600_000) + "h ago";
  }

  function connect() {
    if (es) try { es.close(); } catch (_) {}
    es = new EventSource("/api/v1/stream");
    stats.textContent = "connecting...";
    es.onopen  = () => { stats.textContent = "connected"; };
    es.onerror = () => { stats.textContent = "reconnecting..."; };
    es.onmessage = (e) => {
      if (paused) return;
      try { ingest(JSON.parse(e.data)); render(); } catch (_) {}
    };
  }

  function ingest(ev) {
    if (ev.kind === "stats") {
      STATS_LATEST.ts     = ev.ts || "";
      STATS_LATEST.live   = ev.live   || 0;
      STATS_LATEST.closed = ev.closed || 0;
      return;
    }
    if (ev.kind !== "alert") return;

    const rule = ev.rule_id || "unknown";
    const pid  = ev.pid || 0;
    const key  = rule + "|" + pid;
    const now  = Date.now();
    let c = clusters.get(key);
    if (!c) {
      c = { firstAt: now, lastAt: now, count: 0,
            severity: (ev.severity || "notice").toLowerCase(),
            rule, pid,
            comm: ev.comm || "",
            exe:  ev.exe  || "",
            reason: ev.reason || "",
            dstIp: ev.dst_ip || "",
            dstPort: ev.dst_port || 0 };
      clusters.set(key, c);
    }
    c.lastAt = now;
    c.count++;

    // Prune old clusters periodically.
    if (clusters.size > 200) {
      for (const [k, v] of clusters) {
        if (now - v.lastAt > ROLLING_MS * 5) clusters.delete(k);
      }
    }
  }

  function render() {
    while (feed.firstChild) feed.removeChild(feed.firstChild);

    const now = Date.now();
    const sevRank = { critical: 4, high: 3, warn: 2, notice: 1, info: 0 };
    const items = [...clusters.values()].filter((c) => now - c.lastAt < ROLLING_MS * 4);
    items.sort((a, b) => {
      const sa = sevRank[a.severity] || 0;
      const sb = sevRank[b.severity] || 0;
      if (sa !== sb) return sb - sa;
      return b.lastAt - a.lastAt;
    });

    if (items.length === 0) {
      feed.appendChild(el("div", "No active alert clusters. Connstate: " +
        STATS_LATEST.live + " live flows.", "empty"));
      stats.textContent = "live · " + STATS_LATEST.live + " flows";
      return;
    }

    const prominent = [];
    const demoted   = [];
    items.forEach((c) => {
      c.ctx = lookupContext(c.rule, c.comm);
      (c.ctx.demote ? demoted : prominent).push(c);
    });

    if (prominent.length === 0) {
      const ok = el("div", "All clusters are expected runtime patterns. No new actionable alerts.", "empty");
      feed.appendChild(ok);
    } else {
      prominent.forEach((c) => feed.appendChild(card(c, false)));
    }

    if (demoted.length > 0) {
      const sep = el("div", "Expected runtime patterns (demoted · click to expand)");
      sep.style.cssText = "padding:8px 14px;color:var(--fg-muted);font-size:11px;letter-spacing:0.06em;text-transform:uppercase;border-top:1px solid var(--border-soft);cursor:pointer;";
      let expanded = false;
      const container = el("div");
      container.style.display = "none";
      sep.addEventListener("click", () => {
        expanded = !expanded;
        container.style.display = expanded ? "block" : "none";
        sep.textContent = (expanded ? "Hide " : "Show ") + demoted.length + " expected runtime patterns";
      });
      sep.textContent = "Show " + demoted.length + " expected runtime patterns";
      feed.appendChild(sep);
      demoted.forEach((c) => container.appendChild(card(c, true)));
      feed.appendChild(container);
    }

    const footer = el("div");
    footer.style.cssText = "padding:8px 14px;font-family:var(--mono);font-size:11px;color:var(--fg-dim);border-top:1px solid var(--border-soft);";
    footer.textContent = "connstate · " + STATS_LATEST.live + " live / " + STATS_LATEST.closed + " closed · " + (STATS_LATEST.ts || "—");
    feed.appendChild(footer);

    stats.textContent = prominent.length + " active · " + demoted.length + " demoted";
  }

  function card(c, isDemoted) {
    const sevColour = (c.severity === "critical" || c.severity === "high") ? "red"
                   : (c.severity === "warn") ? "amber" : "";
    const root = el("div", null, "live-card " + sevColour);
    if (isDemoted) root.style.opacity = "0.6";

    const left = el("div");
    left.style.cssText = "display:flex;flex-direction:column;gap:2px;min-width:0;";
    const sev = el("div", c.severity.toUpperCase(), "kind");
    sev.style.color = sevColour === "red" ? "var(--err)"
                    : sevColour === "amber" ? "var(--warn)" : "var(--info)";
    left.appendChild(sev);
    const cnt = el("div", "×" + c.count);
    cnt.style.cssText = "font-family:var(--mono);font-size:14px;font-weight:600;color:var(--fg-strong);";
    left.appendChild(cnt);
    root.appendChild(left);

    const mid = el("div");
    mid.style.cssText = "display:flex;flex-direction:column;gap:2px;min-width:0;";
    mid.appendChild(el("div", fmtAgo(Date.now() - c.lastAt), "ts"));
    const d = el("div", "first " + fmtAgo(Date.now() - c.firstAt), "ts");
    d.style.fontSize = "10px";
    mid.appendChild(d);
    root.appendChild(mid);

    const body = el("div", null, "body");
    const title = el("div");
    title.appendChild(el("strong", c.comm + " (pid " + c.pid + ")"));
    title.appendChild(document.createTextNode(" · " + c.rule));
    title.style.color = "var(--fg-strong)";
    body.appendChild(title);

    const note = el("div", c.ctx.note);
    note.style.cssText = "margin:3px 0;font-family:var(--font);font-size:12px;color:var(--fg);";
    body.appendChild(note);

    if (c.reason) {
      const tech = el("div", c.reason, "small");
      tech.style.cssText = "font-family:var(--mono);font-size:10px;color:var(--fg-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;";
      body.appendChild(tech);
    }

    const actions = el("div");
    actions.style.cssText = "display:flex;gap:6px;margin-top:6px;flex-wrap:wrap;";
    const mkBtn = (label, fn) => {
      const b = el("button", label);
      b.style.cssText = "padding:3px 9px;font-size:11px;border-radius:4px;background:var(--bg-3);border:1px solid var(--border);color:var(--fg-muted);cursor:pointer;";
      b.addEventListener("click", (ev) => { ev.stopPropagation(); fn(); });
      return b;
    };
    actions.appendChild(mkBtn("acknowledge", () => { clusters.delete(c.rule + "|" + c.pid); render(); }));
    actions.appendChild(mkBtn("suppress 1 h",  () => suppress(c, 3600)));
    actions.appendChild(mkBtn("suppress 24 h", () => suppress(c, 86400)));
    actions.appendChild(mkBtn("investigate", () => investigate(c)));
    body.appendChild(actions);

    root.appendChild(body);
    return root;
  }

  function investigate(c) {
    const t = document.querySelector('.tab[data-view="processes"]');
    if (t) t.click();
    setTimeout(() => {
      const rows = document.querySelectorAll(".ptable tbody tr");
      const target = [...rows].find((tr) => tr.firstChild && tr.firstChild.textContent == String(c.pid));
      if (target) target.click();
    }, 250);
  }

  async function suppress(c, ttl) {
    try {
      await fetch("/api/v1/suppression", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule_id: c.rule, exe_sha: c.exe || "", dst_ip: c.dstIp || "",
          ttl_seconds: ttl,
          reason: "operator suppressed via live feed",
        }),
      });
    } catch (_) {}
    clusters.delete(c.rule + "|" + c.pid);
    render();
  }

  toggle.addEventListener("click", () => {
    paused = !paused;
    toggle.textContent = paused ? "resume" : "pause";
  });
  setInterval(render, 2000);
  connect();
})();

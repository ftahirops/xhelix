// overview tab — at-a-glance tiles + top talkers.
// Pulls /api/v1/processes once + on a 5 s timer when the tab is open.

(function () {
  const tilesEl = document.getElementById("overview-tiles");
  const topEl   = document.getElementById("overview-top");
  const statsEl = document.getElementById("overview-stats");
  if (!tilesEl) return;
  let timer = null;

  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function fmtBytes(n) {
    if (!n) return "0 B";
    const k = 1024;
    if (n < k) return n + " B";
    if (n < k * k) return (n / k).toFixed(1) + " KB";
    if (n < k * k * k) return (n / (k * k)).toFixed(1) + " MB";
    return (n / (k * k * k)).toFixed(2) + " GB";
  }

  function tile(label, value, sub, kind) {
    const t = el("div", null, "tile" + (kind ? " " + kind : ""));
    t.appendChild(el("div", label, "label"));
    t.appendChild(el("div", value, "value"));
    if (sub) t.appendChild(el("div", sub, "sub"));
    return t;
  }

  async function load() {
    try {
      const r = await fetch("/api/v1/processes");
      const j = await r.json();
      const procs = j.processes || [];

      const live = procs.filter((p) => p.alive).length;
      const dead = procs.length - live;
      const anom = procs.filter((p) => p.anomaly).length;
      const denyOrPrompt = procs.filter((p) => {
        const a = p.verdict_action;
        return a === "deny" || a === "prompt";
      }).length;
      const totalRate = procs.reduce((s, p) => s + (p.rate_30s_bytes || 0), 0);
      const totalFlows = procs.reduce((s, p) => s + (p.total_flows || 0), 0);
      const totalBytes = procs.reduce((s, p) => s + (p.bytes_in || 0) + (p.bytes_out || 0), 0);
      const groups = new Set(procs.map((p) => p.group || "other"));

      const ts = new Date().toLocaleTimeString();
      statsEl.textContent = "as of " + ts;

      while (tilesEl.firstChild) tilesEl.removeChild(tilesEl.firstChild);
      tilesEl.appendChild(tile("Live processes", live, dead ? dead + " dead" : "all alive", "ok"));
      tilesEl.appendChild(tile("Process groups", groups.size, [...groups].slice(0, 4).join(" · ")));
      tilesEl.appendChild(tile("Active flows", totalFlows, "across all pids"));
      tilesEl.appendChild(tile("Throughput / 30 s", fmtBytes(totalRate), "sum of per-process rate"));
      tilesEl.appendChild(tile("Network bytes", fmtBytes(totalBytes), "lifetime, since process start"));
      tilesEl.appendChild(tile("Anomalies", anom, "heuristic flags", anom > 0 ? "warn" : ""));
      tilesEl.appendChild(tile("Non-allow verdicts", denyOrPrompt, "deny + prompt", denyOrPrompt > 0 ? "deny" : ""));

      // Top talkers
      while (topEl.firstChild) topEl.removeChild(topEl.firstChild);
      const top = procs.slice().sort((a, b) => (b.rate_30s_bytes || 0) - (a.rate_30s_bytes || 0)).slice(0, 8);
      if (top.length === 0 || top[0].rate_30s_bytes === 0) {
        topEl.appendChild(el("p", "no traffic in the last 30 seconds.", "empty"));
      } else {
        const max = top[0].rate_30s_bytes || 1;
        top.forEach((p) => {
          const row = el("div");
          row.style.cssText = "display:grid;grid-template-columns:140px 1fr 100px;gap:12px;align-items:center;padding:6px 0;border-bottom:1px solid var(--border-soft);font-family:var(--mono);font-size:12px;";
          const comm = el("div");
          comm.appendChild(el("span", p.comm || "?"));
          comm.appendChild(document.createElement("br"));
          comm.appendChild(el("span", "pid " + p.pid + " · " + (p.group || "other"), "small"));
          row.appendChild(comm);
          const barWrap = el("div");
          barWrap.style.cssText = "background:var(--bg-3);height:18px;border-radius:9px;overflow:hidden;";
          const fill = el("div");
          const pct = Math.max(2, Math.round(((p.rate_30s_bytes || 0) / max) * 100));
          fill.style.cssText = "background:var(--accent);height:100%;width:" + pct + "%;border-radius:9px;";
          barWrap.appendChild(fill);
          row.appendChild(barWrap);
          row.appendChild(el("div", fmtBytes(p.rate_30s_bytes || 0)));
          topEl.appendChild(row);
        });
      }
    } catch (e) {
      statsEl.textContent = "load failed: " + e.message;
    }
  }

  function maybeStart() {
    const active = document.querySelector(".tab.active");
    if (active && active.dataset.view === "overview") {
      load();
      if (!timer) timer = setInterval(load, 5000);
    } else if (timer) {
      clearInterval(timer); timer = null;
    }
  }
  document.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => setTimeout(maybeStart, 50)));
  maybeStart();
})();

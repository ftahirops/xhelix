// alerts tab + intent-prompt overlay.
// /api/v1/alerts returns clusters from the dedupe engine; we render
// them as severity-coloured rows sorted by score.

(function () {
  const els = {
    list:    document.getElementById("alerts-list"),
    stats:   document.getElementById("alerts-stats"),
    refresh: document.getElementById("alerts-refresh"),
    overlay: document.getElementById("intent-overlay"),
    title:   document.getElementById("intent-title"),
    body:    document.getElementById("intent-body"),
    allow:   document.getElementById("intent-allow"),
    suppress:document.getElementById("intent-suppress"),
    deny:    document.getElementById("intent-deny"),
  };

  // ── intent prompt overlay ─────────────────────────────────
  let intentResolver = null;
  window.xhelixPrompt = function ({ title, body }) {
    return new Promise((resolve) => {
      els.title.textContent = title || "Confirm";
      els.body.textContent  = body  || "";
      els.overlay.classList.remove("hidden");
      intentResolver = resolve;
    });
  };
  function closePrompt(action) {
    els.overlay.classList.add("hidden");
    if (intentResolver) { intentResolver(action); intentResolver = null; }
  }
  els.allow.addEventListener("click",    () => closePrompt("allow"));
  els.suppress.addEventListener("click", () => closePrompt("suppress"));
  els.deny.addEventListener("click",     () => closePrompt("deny"));
  els.overlay.addEventListener("click",  (e) => { if (e.target === els.overlay) closePrompt("allow"); });

  // Long-poll for daemon-side intent prompts.
  async function pollIntent() {
    while (true) {
      try {
        const r = await fetch("/api/v1/intent/poll");
        if (r.ok) {
          const j = await r.json();
          if (j && j.id) {
            const decision = await window.xhelixPrompt({ title: j.title || "xhelix asks:", body: j.body || "" });
            await fetch("/api/v1/intent/decide", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ id: j.id, decision }),
            });
          }
        }
      } catch (_) { await sleep(5000); }
      await sleep(1500);
    }
  }
  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

  // ── alerts list ──────────────────────────────────────────
  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function fmtNum(n) {
    if (n == null) return "0";
    if (n < 1000) return String(n);
    if (n < 1_000_000) return (n/1000).toFixed(1) + "k";
    return (n/1_000_000).toFixed(2) + "M";
  }

  async function loadAlerts() {
    if (!els.list) return;
    try {
      const r = await fetch("/api/v1/alerts");
      const j = await r.json();
      render(j);
    } catch (e) {
      els.list.textContent = "";
      const err = el("div", "load failed: " + e.message, "error");
      els.list.appendChild(err);
    }
  }

  function render(data) {
    const list = Array.isArray(data) ? data : (data && data.alerts) || [];
    while (els.list.firstChild) els.list.removeChild(els.list.firstChild);

    if (list.length === 0) {
      const empty = el("div", "No active alert clusters. The dedupe engine starts surfacing rows once a rule fires enough times to reach the notice threshold (score ≥ 5).", "empty");
      els.list.appendChild(empty);
      els.stats.textContent = "0 clusters";
      return;
    }
    // Sort by score desc.
    list.sort((a, b) => (b.score || 0) - (a.score || 0));
    els.stats.textContent = list.length + " clusters · " +
      fmtNum(list.reduce((s, a) => s + (a.count || 0), 0)) + " events";

    for (const a of list) els.list.appendChild(alertRow(a));
  }

  function alertRow(a) {
    const sev = String(a.severity || "").toLowerCase();
    const row = el("div", null, "alert-row " + sev);

    const sevEl = el("div", sev || "info", "sev " + sev);
    row.appendChild(sevEl);

    const center = el("div");
    center.appendChild(el("div", a.rule_id || a.title || "(unknown rule)", "rule"));
    const reasons = (a.reasons || []).slice(0, 2).join(" · ");
    if (reasons) center.appendChild(el("div", reasons, "reason"));
    row.appendChild(center);

    const target = a.exe || a.dst_ip || "—";
    row.appendChild(el("div", target, "reason"));

    const cnt = el("div", "×" + fmtNum(a.count || 0), "count");
    row.appendChild(cnt);

    row.addEventListener("click", () => suppress(a));
    return row;
  }

  async function suppress(a) {
    const ok = await window.xhelixPrompt({
      title: "Suppress this cluster?",
      body: `${a.rule_id} (${fmtNum(a.count)} events). Allow + suppress for 24 h, or Quarantine the matching process.`,
    });
    if (!ok) return;
    if (ok === "allow" || ok === "suppress") {
      try {
        await fetch("/api/v1/suppression", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            rule_id: a.rule_id || "",
            exe_sha: a.exe_sha || "",
            dst_ip:  a.dst_ip  || "",
            ttl_seconds: ok === "suppress" ? 86400 : 600,
            reason: ok === "suppress" ? "operator marked benign (24h)" : "dismissed",
          }),
        });
      } catch (_) {}
    } else if (ok === "deny") {
      try {
        await fetch("/api/v1/enforce", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "quarantine", rule_id: a.rule_id || "" }),
        });
      } catch (_) {}
    }
    loadAlerts();
  }

  // Activate on tab show + auto-refresh while visible.
  let alertsTimer = null;
  function maybeStart() {
    const active = document.querySelector(".tab.active");
    if (active && active.dataset.view === "alerts") {
      loadAlerts();
      if (!alertsTimer) alertsTimer = setInterval(loadAlerts, 5000);
    } else if (alertsTimer) {
      clearInterval(alertsTimer); alertsTimer = null;
    }
  }
  els.refresh.addEventListener("click", loadAlerts);
  document.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => setTimeout(maybeStart, 50)));
  maybeStart();
  pollIntent();
})();

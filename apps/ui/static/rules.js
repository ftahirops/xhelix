// rules tab — policy editor + telemetry toggle.
// Hits /api/v1/policy (GET/POST) and /api/v1/policy/telemetry (POST).

(function () {
  const toggle = document.getElementById("rules-block-telemetry");
  const status = document.getElementById("rules-status");
  const pathEl = document.getElementById("rules-path");
  const yamlEl = document.getElementById("rules-yaml");
  const saveBtn = document.getElementById("rules-save");
  const reloadBtn = document.getElementById("rules-reload");
  if (!toggle || !yamlEl) return;

  async function load() {
    status.textContent = "loading...";
    try {
      const r = await fetch("/api/v1/policy");
      const j = await r.json();
      yamlEl.value = j.yaml || "";
      toggle.checked = !!j.block_telemetry;
      pathEl.textContent = "source: " + (j.path || "(none)");
      status.textContent = j.note || "loaded";
    } catch (e) {
      status.textContent = "load failed: " + e.message;
    }
  }

  async function save() {
    status.textContent = "saving...";
    try {
      const r = await fetch("/api/v1/policy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ yaml: yamlEl.value }),
      });
      if (!r.ok) {
        const t = await r.text();
        throw new Error(t || r.statusText);
      }
      const j = await r.json();
      toggle.checked = !!j.block_telemetry;
      status.textContent = "saved + hot-reloaded";
    } catch (e) {
      status.textContent = "save failed: " + e.message;
    }
  }

  async function toggleTelemetry() {
    status.textContent = "applying...";
    try {
      const r = await fetch("/api/v1/policy/telemetry", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: toggle.checked }),
      });
      if (!r.ok) throw new Error(await r.text() || r.statusText);
      await load();
      status.textContent = toggle.checked
        ? "telemetry blocking ON (would-deny verdicts active)"
        : "telemetry blocking OFF (tag-only)";
    } catch (e) {
      status.textContent = "toggle failed: " + e.message;
      // revert UI state
      toggle.checked = !toggle.checked;
    }
  }

  saveBtn.addEventListener("click", save);
  reloadBtn.addEventListener("click", load);
  toggle.addEventListener("change", toggleTelemetry);

  // Enforcement controls
  const enfToggle = document.getElementById("enforce-armed");
  const enfSoak = document.getElementById("enforce-soak");
  const enfStatus = document.getElementById("enforce-status");
  let enfTimer = null;
  async function refreshEnforce() {
    try {
      const r = await fetch("/api/v1/enforce/status");
      const j = await r.json();
      enfToggle.checked = !!j.armed;
      if (j.armed) {
        const parts = ["ARMED"];
        if (j.in_soak) parts.push(`soak ${j.soak_left_s}s left (would_drop=${j.would_drop || 0})`);
        else parts.push(`live · dropped=${j.pkt_dropped || 0} accepted=${j.pkt_accepted || 0}`);
        enfStatus.textContent = parts.join(" · ");
      } else {
        enfStatus.textContent = "disarmed (observe-only)";
      }
    } catch (e) {
      enfStatus.textContent = "status: " + e.message;
    }
  }
  enfToggle.addEventListener("change", async () => {
    try {
      if (enfToggle.checked) {
        const soak = parseInt(enfSoak.value, 10) || 30;
        const modeSel = document.querySelector('input[name="enforce-mode"]:checked');
        const mode = modeSel ? modeSel.value : "soft";
        const r = await fetch("/api/v1/enforce/arm", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ soak_seconds: soak, mode }),
        });
        if (!r.ok) throw new Error(await r.text() || r.statusText);
      } else {
        const r = await fetch("/api/v1/enforce/disarm", { method: "POST" });
        if (!r.ok) throw new Error(await r.text() || r.statusText);
      }
      refreshEnforce();
    } catch (e) {
      enfStatus.textContent = "error: " + e.message;
      enfToggle.checked = !enfToggle.checked;
    }
  });

  // Activate on tab show.
  function maybeStart() {
    const active = document.querySelector(".tab.active");
    if (active && active.dataset.view === "rules") {
      load();
      refreshEnforce();
      if (!enfTimer) enfTimer = setInterval(refreshEnforce, 2000);
    } else if (enfTimer) {
      clearInterval(enfTimer); enfTimer = null;
    }
  }
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => setTimeout(maybeStart, 50)));
  maybeStart();
})();

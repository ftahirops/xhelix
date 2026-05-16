// xhelix UI — vanilla JS frontend for the my-net-gate adapter.
// Hits /api/v1/* on the same origin. No external dependencies.
//
// All DOM is built via createElement/appendChild — we never assign
// HTML strings, so there's no XSS surface from server-supplied
// strings even when the server is misbehaving.

const API = "";

const els = {
  status: document.getElementById("status"),
  activities: document.getElementById("activities"),
  processes: document.getElementById("processes-table"),
  alerts: document.getElementById("alerts-list"),
  drill: document.getElementById("drilldown"),
  drillContent: document.getElementById("drill-content"),
  since: document.getElementById("since"),
  verdict: document.getElementById("verdict-filter"),
  refresh: document.getElementById("refresh"),
};

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
});
els.refresh.addEventListener("click", loadJournal);
els.since.addEventListener("change", loadJournal);
els.verdict.addEventListener("change", loadJournal);
document.getElementById("drill-close").addEventListener("click", () => {
  els.drill.classList.add("hidden");
});

async function ping() {
  try {
    const r = await fetch(`${API}/api/v1/ping`);
    if (!r.ok) throw new Error(r.statusText);
    const j = await r.json();
    els.status.textContent = "ok • " + (j.socket || "");
    els.status.className = "status ok";
  } catch (e) {
    els.status.textContent = "xhelix unreachable: " + e.message;
    els.status.className = "status err";
  }
}

async function loadJournal() {
  const since = els.since.value;
  const verdict = els.verdict.value;
  const filter = verdict ? `verdict=${verdict}` : "";
  try {
    const r = await fetch(`${API}/api/v1/history?since=${since}&filter=${encodeURIComponent(filter)}`);
    const data = await r.json();
    renderJournal(data);
  } catch (e) {
    clear(els.activities);
    const err = document.createElement("div");
    err.className = "error";
    err.textContent = "load failed: " + e.message;
    els.activities.appendChild(err);
  }
}

function renderJournal(data) {
  const list = Array.isArray(data) ? data : (data && data.activities) || [];
  clear(els.activities);
  if (list.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "no activity in this window";
    els.activities.appendChild(empty);
    return;
  }
  for (const a of list) {
    els.activities.appendChild(activityCard(a));
  }
}

function activityCard(a) {
  const verdict = String(a.verdict || a.Verdict || "green").toLowerCase();
  const host = a.primary_host || a.PrimaryHost || a.primary_ip || "(direct)";
  const exe = a.exe || a.process_exe || a.ProcessExe || "(unknown)";
  const bytesIn = a.bytes_in || a.BytesIn || 0;
  const bytesOut = a.bytes_out || a.BytesOut || 0;
  const flowCount = a.flow_count || a.FlowCount || 1;
  const started = a.started_at || a.StartedAt || "";
  const id = a.id || a.ID || "";

  const card = document.createElement("div");
  card.className = "activity " + verdict;
  card.dataset.id = String(id);

  const title = document.createElement("h3");
  title.textContent = exe + " → " + host;
  card.appendChild(title);

  const meta = document.createElement("div");
  meta.className = "meta";
  const badge = document.createElement("span");
  badge.className = "verdict " + verdict;
  badge.textContent = verdict;
  meta.appendChild(badge);
  meta.appendChild(document.createTextNode(
    ` · ${flowCount} flow(s) · ${human(bytesIn)} in / ${human(bytesOut)} out · ${started}`
  ));
  card.appendChild(meta);

  card.addEventListener("click", () => drillInto(card.dataset.id));
  return card;
}

async function drillInto(id) {
  if (!id) return;
  els.drill.classList.remove("hidden");
  clear(els.drillContent);
  els.drillContent.textContent = "loading...";
  try {
    const r = await fetch(`${API}/api/v1/history/activity/${id}`);
    const data = await r.json();
    renderDrill(data);
  } catch (e) {
    els.drillContent.textContent = "error: " + e.message;
  }
}

function renderDrill(data) {
  clear(els.drillContent);
  if (!data) {
    els.drillContent.textContent = "no data";
    return;
  }
  const exe = data.exe || "process";
  const host = data.primary_host || "(direct)";
  const h2 = document.createElement("h2");
  h2.textContent = exe + " → " + host;
  els.drillContent.appendChild(h2);

  const fields = [
    ["verdict", data.verdict || ""],
    ["score", (data.verdict_score || 0) + "/100"],
    ["started", data.started_at || ""],
    ["ended", data.ended_at || ""],
    ["bytes in", human(data.bytes_in || 0)],
    ["bytes out", human(data.bytes_out || 0)],
  ];
  for (const [k, v] of fields) {
    els.drillContent.appendChild(row(k, v));
  }

  const reasonsH3 = document.createElement("h3");
  reasonsH3.textContent = "reasons";
  els.drillContent.appendChild(reasonsH3);
  const ul = document.createElement("ul");
  const reasons = data.reasons || [];
  if (reasons.length === 0) {
    const li = document.createElement("li");
    li.textContent = "(none)";
    ul.appendChild(li);
  } else {
    for (const r of reasons) {
      const li = document.createElement("li");
      li.textContent = r;
      ul.appendChild(li);
    }
  }
  els.drillContent.appendChild(ul);

  const rawH3 = document.createElement("h3");
  rawH3.textContent = "raw";
  els.drillContent.appendChild(rawH3);
  const pre = document.createElement("pre");
  pre.textContent = JSON.stringify(data, null, 2);
  els.drillContent.appendChild(pre);
}

function row(k, v) {
  const r = document.createElement("div");
  r.className = "row";
  const ks = document.createElement("span");
  ks.className = "k";
  ks.textContent = k;
  const vs = document.createElement("span");
  vs.className = "v";
  vs.textContent = String(v);
  r.appendChild(ks);
  r.appendChild(vs);
  return r;
}

function switchView(view) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === view));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + view));
}

function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
}

function human(n) {
  if (!n) return "0 B";
  const k = 1024;
  if (n < k) return n + " B";
  if (n < k * k) return (n / k).toFixed(1) + " KB";
  if (n < k * k * k) return (n / (k * k)).toFixed(1) + " MB";
  return (n / (k * k * k)).toFixed(2) + " GB";
}

// Boot
ping();
loadJournal();
setInterval(ping, 30000);

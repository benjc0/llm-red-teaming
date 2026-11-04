/* APT GUI front end — vanilla JS, no build step.
   Reads the orchestrator's run directory through the local API and renders:
   run list, per-run phase pipeline, structured findings, live activity stream,
   and the report. Polls while a run is live. */

"use strict";

const state = {
  phaseOrder: [],
  phaseTitles: {},
  runs: [],
  selectedRun: null,      // run_id
  detail: null,           // last fetched detail object
  selectedPhase: null,    // phase name shown in the lower panel
  tab: "findings",        // findings | activity | report
  activity: { phase: null, lastSeq: 0, events: [], complete: false },
  openEvents: new Set(),  // event seqs expanded in the activity view
  polling: null,
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, txt) => { const n = document.createElement(tag); if (cls) n.className = cls; if (txt != null) n.textContent = txt; return n; };

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).error || msg; } catch (_) {}
    throw new Error(msg);
  }
  const ct = r.headers.get("content-type") || "";
  return ct.includes("application/json") ? r.json() : r.text();
}

function setConn(ok) {
  const c = $("#conn");
  c.classList.toggle("off", !ok);
  $("#conn-txt").textContent = ok ? "connected" : "disconnected";
}

/* ---------------- run list ---------------- */

async function loadRuns() {
  try {
    const data = await api("/api/runs");
    state.runs = data.runs;
    setConn(true);
    renderRunList();
  } catch (e) {
    setConn(false);
  }
}

function renderRunList() {
  const box = $("#runlist");
  box.innerHTML = "";
  if (!state.runs.length) {
    box.appendChild(el("div", "empty", "No runs yet."));
    return;
  }
  for (const r of state.runs) {
    const row = el("div", "runrow" + (r.run_id === state.selectedRun ? " sel" : ""));
    const top = el("div");
    top.style.display = "flex";
    top.style.justifyContent = "space-between";
    top.style.alignItems = "center";
    top.appendChild(el("span", "rid", r.run_id));
    top.appendChild(el("span", "badge " + r.status, r.status));
    row.appendChild(top);

    const meta = el("div", "meta");
    meta.appendChild(el("span", null, `${r.phases_done}/${r.phases_total} phases`));
    if (r.vuln_count != null) meta.appendChild(el("span", null, `${r.vuln_count} vulns`));
    if (r.cost_usd != null) meta.appendChild(el("span", null, `$${r.cost_usd.toFixed(2)}`));
    if (r.mode) meta.appendChild(el("span", null, r.mode));
    row.appendChild(meta);
    if (r.target) row.appendChild(el("div", "target", r.target));

    row.onclick = () => selectRun(r.run_id);
    box.appendChild(row);
  }
}

/* ---------------- run detail ---------------- */

function syncHash() {
  // Shareable route: #<run>/<phase>/<tab> — handy for demo/bookmark links.
  const parts = [state.selectedRun, state.selectedPhase, state.tab].filter(Boolean);
  const h = "#" + parts.join("/");
  if (location.hash !== h) history.replaceState(null, "", h);
}

async function selectRun(runId, wantPhase, wantTab) {
  state.selectedRun = runId;
  state.selectedPhase = wantPhase || null;
  if (wantTab) state.tab = wantTab;
  state.activity = { phase: null, lastSeq: 0, events: [], complete: false };
  state.openEvents.clear();
  renderRunList();
  await refreshDetail(!wantPhase);
  syncHash();
  if (state.tab === "activity") loadActivityIfNeeded(true);
  if (state.tab === "report") loadReport();
  startPolling();
}

async function refreshDetail(pickPhase) {
  if (!state.selectedRun) return;
  let d;
  try {
    d = await api(`/api/runs/${state.selectedRun}`);
    setConn(true);
  } catch (e) {
    setConn(false);
    return;
  }
  state.detail = d;
  if (pickPhase || !state.selectedPhase) {
    // Default to the active phase, else the last phase that has findings.
    const active = d.phases.find((p) => p.state === "active");
    const lastDone = [...d.phases].reverse().find((p) => p.has_findings);
    state.selectedPhase = (active || lastDone || d.phases[0]).phase;
  }
  renderDetail();
}

function renderDetail() {
  const d = state.detail;
  const c = $("#content");
  c.innerHTML = "";
  if (!d) return;

  // header
  const head = el("div", "detail-head");
  head.appendChild(el("h1", null, d.run_id));
  head.appendChild(el("span", "badge " + d.status, d.status));
  c.appendChild(head);

  const sub = el("div", "detail-sub");
  const addSub = (k, v) => { if (v != null && v !== "") { const s = el("span"); s.innerHTML = `${k} <b>${escapeHtml(String(v))}</b>`; sub.appendChild(s); } };
  addSub("target", d.target);
  addSub("mode", d.mode);
  addSub("model", d.model || "default");
  if (d.usage_total && d.usage_total.cost_usd != null) addSub("cost", `$${d.usage_total.cost_usd.toFixed(2)}`);
  if (d.usage_total && d.usage_total.total_tokens != null) addSub("tokens", d.usage_total.total_tokens.toLocaleString());
  c.appendChild(sub);

  // progress bar
  const done = d.phases.filter((p) => p.state === "done").length;
  const wrap = el("div", "progress-wrap");
  const bar = el("div", "progress-bar");
  bar.style.width = `${Math.round((done / d.phases.length) * 100)}%`;
  wrap.appendChild(bar);
  c.appendChild(wrap);

  // pipeline
  const pipe = el("div", "pipeline");
  for (const p of d.phases) {
    const node = el("div", `pnode ${p.state}` + (p.phase === state.selectedPhase ? " sel" : ""));
    node.appendChild(el("div", "pname", p.title));
    node.appendChild(el("div", "pstate", p.state));
    node.onclick = () => { state.selectedPhase = p.phase; renderDetail(); syncHash(); loadActivityIfNeeded(true); };
    pipe.appendChild(node);
  }
  c.appendChild(pipe);

  // tabs
  const tabs = el("div", "tabs");
  for (const t of ["findings", "activity", "report"]) {
    const tab = el("div", "tab" + (state.tab === t ? " sel" : ""), t);
    tab.onclick = () => { state.tab = t; renderDetail(); syncHash(); if (t === "activity") loadActivityIfNeeded(true); if (t === "report") loadReport(); };
    tabs.appendChild(tab);
  }
  c.appendChild(tabs);

  const panel = el("div");
  panel.id = "panel";
  c.appendChild(panel);

  if (state.tab === "findings") renderFindings(panel);
  else if (state.tab === "activity") renderActivity(panel);
  else renderReportPlaceholder(panel);
}

/* ---------------- findings ---------------- */

function currentPhaseObj() {
  return state.detail.phases.find((p) => p.phase === state.selectedPhase);
}

function renderFindings(panel) {
  const p = currentPhaseObj();
  if (!p || !p.findings) {
    panel.appendChild(el("div", "empty", p && p.state === "active"
      ? "Phase is running — structured findings appear when it completes. Watch the Activity tab for live progress."
      : "No findings for this phase yet."));
    return;
  }
  const f = p.findings;
  if (f.summary) {
    const card = el("div", "card");
    card.appendChild(el("div", "ctitle", "Summary"));
    card.appendChild(el("div", "cbody", f.summary));
    panel.appendChild(card);
  }
  const pl = f.payload || {};
  const render = PAYLOAD_RENDERERS[p.phase];
  if (render) render(panel, pl, f);
  if (Array.isArray(f.raw_artifacts) && f.raw_artifacts.length) {
    renderArtifacts(panel, f.raw_artifacts);
  }
  if (Array.isArray(f.next_steps) && f.next_steps.length) {
    const card = el("div", "card");
    card.appendChild(el("div", "ctitle", "Next steps"));
    const ul = el("ul"); ul.style.margin = "8px 0 0"; ul.style.color = "var(--fg-dim)";
    f.next_steps.forEach((s) => ul.appendChild(el("li", null, s)));
    card.appendChild(ul);
    panel.appendChild(card);
  }
}

const PAYLOAD_RENDERERS = {
  recon(panel, pl) {
    chipCard(panel, "Tech stack", pl.tech_stack);
    if (pl.endpoints) endpointTable(panel, "Endpoints", pl.endpoints);
    if (pl.services && pl.services.length) {
      const card = el("div", "card");
      card.appendChild(el("div", "ctitle", `Services (${pl.services.length})`));
      pl.services.forEach((s) => card.appendChild(el("div", "cbody", `${s.host}:${s.port}/${s.protocol} — ${s.service || "?"} ${s.version || ""}`)));
      panel.appendChild(card);
    }
  },
  enumeration(panel, pl) {
    chipCard(panel, "Users", pl.users);
    chipCard(panel, "Roles", pl.roles);
    chipCard(panel, "Hidden paths", pl.hidden_paths);
    chipCard(panel, "API surface", pl.api_surface);
    if (pl.routes) endpointTable(panel, "Routes", pl.routes);
    if (pl.params && pl.params.length) {
      const card = el("div", "card");
      card.appendChild(el("div", "ctitle", `Parameters (${pl.params.length})`));
      pl.params.slice(0, 80).forEach((p) => card.appendChild(el("div", "cbody", `${p.location}  ${p.name}  @ ${p.endpoint}`)));
      panel.appendChild(card);
    }
  },
  vuln_assessment(panel, pl) {
    const vulns = pl.vulnerabilities || [];
    panel.appendChild(el("div", "ctitle", `Candidate vulnerabilities (${vulns.length})`));
    vulns.forEach((v) => {
      const card = el("div", "card");
      const t = el("div", "ctitle");
      t.appendChild(el("span", null, `${v.id} · ${v.title}`));
      t.appendChild(el("span", "pill " + confCls(v.confidence), v.confidence || "?"));
      card.appendChild(t);
      const meta = el("div", "cmeta");
      if (v.type) meta.appendChild(el("span", "chip", v.type));
      if (v.owasp_web) meta.appendChild(el("span", "chip", v.owasp_web));
      if (v.owasp_llm) meta.appendChild(el("span", "chip", v.owasp_llm));
      if (v.cwe) meta.appendChild(el("span", "chip", v.cwe));
      if (v.location) meta.appendChild(el("span", "chip", v.location));
      card.appendChild(meta);
      if (v.evidence) card.appendChild(el("div", "cbody", v.evidence));
      panel.appendChild(card);
    });
  },
  exploitation(panel, pl) {
    const att = pl.attempts || [];
    const confirmed = att.filter((a) => a.oracle_confirmed === true).length;
    const claimed = att.filter((a) => a.outcome === "success").length;
    const h = el("div", "ctitle");
    h.appendChild(el("span", null, `Exploit attempts (${att.length})`));
    h.appendChild(el("span", "pill ok", `${claimed} claimed success`));
    h.appendChild(el("span", "pill oracle", `${confirmed} oracle-confirmed`));
    panel.appendChild(h);
    att.forEach((a) => {
      const card = el("div", "card");
      const t = el("div", "ctitle");
      t.appendChild(el("span", null, `${a.vuln_id}`));
      t.appendChild(el("span", "pill " + outcomeCls(a.outcome), a.outcome));
      if (a.oracle_confirmed === true) t.appendChild(el("span", "pill oracle", "oracle ✓"));
      else if (a.oracle_confirmed === false) t.appendChild(el("span", "pill", "oracle ✗"));
      if (a.challenge_key) t.appendChild(el("span", "chip", a.challenge_key));
      card.appendChild(t);
      if (a.technique) card.appendChild(el("div", "cbody", a.technique));
      if (a.evidence) card.appendChild(el("div", "cbody muted", a.evidence));
      panel.appendChild(card);
    });
  },
  post_exploitation(panel, pl) {
    chipCard(panel, "Footholds", pl.footholds);
    chipCard(panel, "Reachable data", pl.reachable_data);
    chipCard(panel, "Escalations", pl.escalations);
  },
  reporting(panel, pl) {
    const card = el("div", "card");
    card.appendChild(el("div", "ctitle", "Report"));
    if (pl.summary) card.appendChild(el("div", "cbody", pl.summary));
    const link = el("a", null, "Open the full report →");
    link.href = "#"; link.onclick = (e) => { e.preventDefault(); state.tab = "report"; renderDetail(); loadReport(); };
    card.appendChild(link);
    panel.appendChild(card);
  },
  mitigation(panel, pl) {
    const items = pl.items || [];
    panel.appendChild(el("div", "ctitle", `Mitigation playbook (${items.length})`));
    items.forEach((m) => {
      const card = el("div", "card");
      card.appendChild(el("div", "ctitle", m.vuln_id));
      card.appendChild(el("div", "cbody", m.recommendation));
      if (m.reference) { const a = el("a", null, m.reference); a.href = m.reference; a.target = "_blank"; card.appendChild(a); }
      panel.appendChild(card);
    });
  },
};

function renderArtifacts(panel, arts) {
  const card = el("div", "card");
  card.appendChild(el("div", "ctitle", `Raw artifacts (${arts.length})`));
  const chips = el("div", "chips");
  arts.forEach((a) => {
    const link = el("a", "chip", `${a.tool}: ${a.path}`);
    link.href = `/api/runs/${state.selectedRun}/raw?path=${encodeURIComponent(state.selectedPhase + "/" + a.path)}`;
    link.target = "_blank";
    link.title = a.description || "";
    chips.appendChild(link);
  });
  card.appendChild(chips);
  panel.appendChild(card);
}

function chipCard(panel, title, list) {
  if (!list || !list.length) return;
  const card = el("div", "card");
  card.appendChild(el("div", "ctitle", `${title} (${list.length})`));
  const chips = el("div", "chips");
  list.forEach((x) => chips.appendChild(el("span", "chip", typeof x === "string" ? x : JSON.stringify(x))));
  card.appendChild(chips);
  panel.appendChild(card);
}

function endpointTable(panel, title, eps) {
  const card = el("div", "card");
  card.appendChild(el("div", "ctitle", `${title} (${eps.length})`));
  eps.slice(0, 120).forEach((e) => {
    const line = `${(e.method || "GET").padEnd(6)} ${e.status != null ? "[" + e.status + "] " : ""}${e.path}`;
    const row = el("div", "cbody"); row.style.margin = "2px 0";
    row.textContent = line + (e.notes ? "  — " + e.notes : "");
    card.appendChild(row);
  });
  panel.appendChild(card);
}

/* ---------------- activity stream ---------------- */

function renderActivity(panel) {
  const info = el("div", "muted");
  info.style.marginBottom = "10px";
  info.textContent = `Live tool activity for the "${state.selectedPhase}" phase — commands, reasoning and results as the agent works.`;
  panel.appendChild(info);

  const stream = el("div", "activity");
  stream.id = "stream";
  panel.appendChild(stream);
  paintActivity();
  loadActivityIfNeeded(false);
}

function paintActivity() {
  const stream = $("#stream");
  if (!stream) return;
  stream.innerHTML = "";
  if (!state.activity.events.length) {
    stream.appendChild(el("div", "empty", "No activity recorded yet."));
    return;
  }
  for (const ev of state.activity.events) {
    stream.appendChild(renderEvent(ev));
  }
}

function renderEvent(ev) {
  const row = el("div", "ev " + ev._type);
  if (ev._type === "tool_use") {
    const head = el("div", "ev-head");
    const caret = el("span", "ev-caret", state.openEvents.has(ev.seq) ? "▾" : "▸");
    head.appendChild(caret);
    head.appendChild(el("span", "tname", ev.tool));
    head.appendChild(el("span", "ev-label", ev.label || ev.description || ""));
    row.appendChild(head);
    const body = el("div", "ev-body" + (state.openEvents.has(ev.seq) ? "" : " hidden"));
    body.textContent = JSON.stringify(ev.input, null, 2);
    row.appendChild(body);
    head.onclick = () => { toggleEvent(ev.seq); caret.textContent = state.openEvents.has(ev.seq) ? "▾" : "▸"; body.classList.toggle("hidden"); };
  } else if (ev._type === "tool_result") {
    const head = el("div", "ev-head");
    const caret = el("span", "ev-caret", state.openEvents.has(ev.seq) ? "▾" : "▸");
    head.appendChild(caret);
    head.appendChild(el("span", "tname" + (ev.is_error ? " err" : ""), ev.is_error ? "result ✗" : "result"));
    head.appendChild(el("span", "ev-label", firstLine(ev.preview)));
    row.appendChild(head);
    const body = el("div", "ev-body" + (state.openEvents.has(ev.seq) ? "" : " hidden"));
    body.textContent = ev.preview + (ev.truncated ? "\n… (truncated; open the raw artifact for full output)" : "");
    row.appendChild(body);
    head.onclick = () => { toggleEvent(ev.seq); caret.textContent = state.openEvents.has(ev.seq) ? "▾" : "▸"; body.classList.toggle("hidden"); };
  } else {
    row.appendChild(el("div", null, ev.text || ev._type));
  }
  return row;
}

function toggleEvent(seq) {
  if (state.openEvents.has(seq)) state.openEvents.delete(seq);
  else state.openEvents.add(seq);
}

async function loadActivityIfNeeded(reset) {
  if (state.tab !== "activity" || !state.selectedRun || !state.selectedPhase) return;
  if (reset || state.activity.phase !== state.selectedPhase) {
    state.activity = { phase: state.selectedPhase, lastSeq: 0, events: [], complete: false };
    state.openEvents.clear();
  }
  try {
    const q = `phase=${encodeURIComponent(state.selectedPhase)}&after=${state.activity.lastSeq}`;
    const data = await api(`/api/runs/${state.selectedRun}/activity?${q}`);
    if (data.events.length) {
      const atBottom = isNearBottom();
      state.activity.events.push(...data.events);
      state.activity.lastSeq = data.last_seq;
      state.activity.complete = data.complete;
      paintActivity();
      if (atBottom) scrollStreamBottom();
    } else {
      state.activity.complete = data.complete;
    }
    setConn(true);
  } catch (e) { setConn(false); }
}

function isNearBottom() {
  const c = $("#content");
  return c && (c.scrollHeight - c.scrollTop - c.clientHeight < 120);
}
function scrollStreamBottom() {
  const c = $("#content");
  if (c) c.scrollTop = c.scrollHeight;
}

/* ---------------- report ---------------- */

function renderReportPlaceholder(panel) {
  panel.id = "panel";
  panel.appendChild(el("div", "muted", "Loading report…"));
}
async function loadReport() {
  const panel = $("#panel");
  if (!panel) return;
  try {
    const md = await api(`/api/runs/${state.selectedRun}/report`);
    panel.innerHTML = "";
    const card = el("div", "card");
    const pre = el("div", "cbody");
    pre.style.fontFamily = "var(--mono)";
    pre.textContent = md;
    card.appendChild(pre);
    panel.appendChild(card);
  } catch (e) {
    panel.innerHTML = "";
    panel.appendChild(el("div", "empty", "No report.md for this run (run the reporting phase to generate one)."));
  }
}

/* ---------------- polling ---------------- */

function startPolling() {
  stopPolling();
  state.polling = setInterval(tick, 2000);
}
function stopPolling() { if (state.polling) { clearInterval(state.polling); state.polling = null; } }

async function tick() {
  await loadRuns();
  if (!state.selectedRun) return;
  const running = state.detail && state.detail.status === "running";
  // Always refresh the list; refresh the open detail/activity when live (or occasionally).
  await refreshDetail(false);
  if (state.tab === "activity" && (running || !state.activity.complete)) {
    await loadActivityIfNeeded(false);
  }
}

/* ---------------- new run modal ---------------- */

function openModal() { $("#modal-back").classList.add("show"); $("#f-err").textContent = ""; }
function closeModal() { $("#modal-back").classList.remove("show"); }

function buildPhaseChecks() {
  const grid = $("#f-phases");
  grid.innerHTML = "";
  state.phaseOrder.forEach((p, i) => {
    const lab = el("label");
    const cb = el("input"); cb.type = "checkbox"; cb.value = p;
    cb.checked = i < 2; // default recon + enumeration
    cb.className = "ph-cb";
    lab.appendChild(cb);
    lab.appendChild(el("span", null, state.phaseTitles[p] || p));
    grid.appendChild(lab);
  });
}

async function launch() {
  const phmode = document.querySelector('input[name="phmode"]:checked').value;
  let phases = "all";
  if (phmode === "pick") {
    const picked = [...document.querySelectorAll(".ph-cb")].filter((c) => c.checked).map((c) => c.value);
    if (!picked.length) { $("#f-err").textContent = "Pick at least one phase, or choose 'all'."; return; }
    phases = picked.join(",");
  }
  const body = {
    target: $("#f-target").value.trim(),
    phases,
    mode: $("#f-mode").value,
    model: $("#f-model").value.trim(),
    grading_token: $("#f-token").value.trim(),
    unattended: $("#f-unattended").checked,
    source: $("#f-source").value.trim(),
  };
  try {
    const res = await api("/api/launches", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    closeModal();
    await loadRuns();
    if (res.run_id) selectRun(res.run_id);
  } catch (e) {
    $("#f-err").textContent = e.message;
  }
}

/* ---------------- helpers ---------------- */

function confCls(c) { return c === "high" ? "hi" : c === "medium" ? "med" : "low"; }
function outcomeCls(o) { return o === "success" ? "ok" : o === "failure" ? "hi" : "med"; }
function firstLine(s) { return (s || "").split("\n")[0].slice(0, 160); }
function escapeHtml(s) { return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

/* ---------------- boot ---------------- */

async function boot() {
  try {
    const p = await api("/api/phases");
    state.phaseOrder = p.order;
    state.phaseTitles = p.titles;
  } catch (_) {}
  buildPhaseChecks();
  await loadRuns();

  // Deep link: open #<run>/<phase>/<tab> directly (handy for demos/bookmarks).
  const [hRun, hPhase, hTab] = location.hash.slice(1).split("/");
  if (hRun && state.runs.some((r) => r.run_id === hRun)) {
    await selectRun(hRun, hPhase, hTab);
  } else {
    startPolling();
  }
  window.addEventListener("hashchange", () => {
    const [r, p, t] = location.hash.slice(1).split("/");
    if (r && r !== state.selectedRun) selectRun(r, p, t);
  });

  $("#btn-new").onclick = openModal;
  $("#btn-cancel").onclick = closeModal;
  $("#btn-launch").onclick = launch;
  $("#modal-back").onclick = (e) => { if (e.target.id === "modal-back") closeModal(); };
  $("#f-mode").onchange = (e) => { $("#f-source-wrap").style.display = e.target.value === "white-box" ? "block" : "none"; };
  $("#f-unattended").onchange = (e) => { $("#f-warn").classList.toggle("show", e.target.checked); };
}

document.addEventListener("DOMContentLoaded", boot);

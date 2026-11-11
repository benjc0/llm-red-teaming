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
  view: "run",            // run | compare
  engine: "ai",           // new-run modal engine: ai | baseline
  tools: null,            // /api/tools (free-tool lineup per phase)
  compare: { picked: null, data: null, cov: "exploitation", loading: false, error: null },
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
    const row = el("div", "runrow" + (state.view === "run" && r.run_id === state.selectedRun ? " sel" : ""));
    const top = el("div");
    top.style.display = "flex";
    top.style.justifyContent = "space-between";
    top.style.alignItems = "center";
    const left = el("span");
    left.appendChild(kindBadge(r.kind));
    left.appendChild(el("span", "rid", r.run_id));
    top.appendChild(left);
    top.appendChild(el("span", "badge " + r.status, r.status));
    row.appendChild(top);

    const meta = el("div", "meta");
    meta.appendChild(el("span", null, `${r.phases_done}/${r.phases_total} phases`));
    if (r.vuln_count != null) meta.appendChild(el("span", null, `${r.vuln_count} vulns`));
    if (r.cost_usd != null && r.kind !== "baseline") meta.appendChild(el("span", null, `$${r.cost_usd.toFixed(2)}`));
    if (r.mode) meta.appendChild(el("span", null, r.mode));
    row.appendChild(meta);
    if (r.scored) {
      const sc = el("div", "meta score-line");
      sc.appendChild(el("span", null, `detect ${pct(r.detection_rate)}`));
      sc.appendChild(el("span", null, `exploit ${pct(r.exploitation_rate)}`));
      row.appendChild(sc);
    }
    if (r.target) row.appendChild(el("div", "target", r.target));

    row.onclick = () => selectRun(r.run_id);
    box.appendChild(row);
  }
}

/* ---------------- run detail ---------------- */

function syncHash() {
  // Shareable route: #<run>/<phase>/<tab> — handy for demo/bookmark links.
  // The comparison lives at #compare/<run,run,...>.
  if (state.view === "compare") {
    const ids = state.compare.picked ? [...state.compare.picked].join(",") : "";
    const h = "#compare" + (ids ? "/" + ids : "");
    if (location.hash !== h) history.replaceState(null, "", h);
    return;
  }
  const parts = [state.selectedRun, state.selectedPhase, state.tab].filter(Boolean);
  const h = "#" + parts.join("/");
  if (location.hash !== h) history.replaceState(null, "", h);
}

async function selectRun(runId, wantPhase, wantTab) {
  state.view = "run";
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
  const actions = el("span", "head-actions");
  if (d.scorable) actions.appendChild(scoreButton(d.run_id, d.scored));
  if (d.scored) {
    const cmp = el("button", null, "⇄ Compare");
    cmp.title = "Open this run in the AI-vs-tools comparison";
    cmp.onclick = () => openCompare(null, d.run_id);
    actions.appendChild(cmp);
  }
  head.appendChild(actions);
  c.appendChild(head);

  const sub = el("div", "detail-sub");
  const addSub = (k, v) => { if (v != null && v !== "") { const s = el("span"); s.innerHTML = `${k} <b>${escapeHtml(String(v))}</b>`; sub.appendChild(s); } };
  addSub("engine", d.kind === "baseline" ? "free tools" : "AI agent");
  addSub("target", d.target);
  addSub("mode", d.mode);
  if (d.kind !== "baseline") {
    addSub("model", d.model || "default");
    if (d.usage_total && d.usage_total.cost_usd != null) addSub("cost", `$${d.usage_total.cost_usd.toFixed(2)}`);
    if (d.usage_total && d.usage_total.total_tokens != null) addSub("tokens", d.usage_total.total_tokens.toLocaleString());
  }
  if (d.scored) addSub("score", `detect ${pct(d.detection_rate)} · exploit ${pct(d.exploitation_rate)}`);
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
  info.textContent = state.detail && state.detail.kind === "baseline"
    ? `Tool log for the "${state.selectedPhase}" phase: which free tools ran, were skipped, or failed.`
    : `Live tool activity for the "${state.selectedPhase}" phase — commands, reasoning and results as the agent works.`;
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
  } else if (ev._type === "baseline") {
    const head = el("div", "ev-head");
    head.appendChild(el("span", "tname" + (ev.is_error ? " err" : ""), ev.tool));
    head.appendChild(el("span", "muted", ev.event.replace(/^tool_/, "")));
    head.appendChild(el("span", "ev-label", ev.text));
    row.appendChild(head);
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
  if (state.view === "compare" || !state.selectedRun) return;
  const running = state.detail && state.detail.status === "running";
  // Always refresh the list; refresh the open detail/activity when live (or occasionally).
  await refreshDetail(false);
  if (state.tab === "activity" && (running || !state.activity.complete)) {
    await loadActivityIfNeeded(false);
  }
}

/* ---------------- new run modal ---------------- */

function openModal() { $("#modal-back").classList.add("show"); $("#f-err").textContent = ""; setEngine(state.engine); }

function setEngine(engine) {
  state.engine = engine;
  document.querySelectorAll("#f-engine .seg-btn").forEach((b) => {
    const on = b.dataset.engine === engine;
    b.classList.toggle("sel", on);
    b.setAttribute("aria-checked", on ? "true" : "false");
  });
  document.querySelectorAll(".ai-only").forEach((n) => { n.style.display = engine === "ai" ? "" : "none"; });
  document.querySelectorAll(".baseline-only").forEach((n) => { n.style.display = engine === "baseline" ? "" : "none"; });
  $("#btn-launch").textContent = engine === "ai" ? "Launch AI run" : "Launch tool run";
  const info = $("#f-tools-info");
  info.innerHTML = "";
  if (engine !== "baseline") return;
  info.appendChild(el("div", "hint", "Runs standard free tools through the same phases and writes the same findings format, so the run is scored and compared like an AI run. Needs Docker (nmap, Arjun and Retire.js run natively if installed). Missing tools are skipped and logged."));
  info.appendChild(toolLineup());
}

/* Free-tool lineup per phase, as a compact two-column list. */
function toolLineup() {
  const box = el("div", "lineup");
  if (!state.tools) { box.appendChild(el("div", "muted", "Loading tool lineup…")); return box; }
  for (const ph of state.phaseOrder) {
    const info = state.tools[ph];
    if (!info) continue;
    const row = el("div", "lineup-row");
    row.appendChild(el("div", "lineup-phase", info.title));
    const tools = el("div", "chips");
    if (info.tools.length) {
      info.tools.forEach((t) => {
        const c = el("span", "chip", t.name + (t.white_box_only ? " (white-box)" : ""));
        if (t.purpose) c.dataset.tip = t.purpose;
        tools.appendChild(c);
      });
    } else {
      tools.appendChild(el("span", "muted derived", "derived: " + (info.derived || "from earlier output")));
    }
    row.appendChild(tools);
    box.appendChild(row);
  }
  return box;
}
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
    engine: state.engine,
    dry_run: $("#f-dryrun").checked,
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

/* ---------------- compare: AI agent vs. free tools ---------------- */

/* Headline metrics, in display order. better = which direction wins.
   rate metrics share a fixed 0–100% scale; the rest scale to the larger side. */
const COMPARE_METRICS = [
  { group: "Effectiveness — scored against the master vulnerability list" },
  { k: "detection_rate", label: "Detection rate", fmt: "pct", better: "high", hint: "Graded vulnerabilities reported (recall)" },
  { k: "exploitation_rate", label: "Exploitation rate", fmt: "pct", better: "high", hint: "Graded vulnerabilities confirmed by the server oracle (ground truth)" },
  { k: "precision", label: "Precision", fmt: "pct", better: "high", hint: "Reported findings that matched a real vulnerability" },
  { k: "f1", label: "F1 score", fmt: "pct", better: "high", hint: "Balance of precision and detection" },
  { k: "exploited", label: "Confirmed exploits", fmt: "num", better: "high", hint: "Count of oracle-confirmed exploits" },
  { k: "false_positives", label: "False positives", fmt: "num", better: "low", hint: "Findings that matched nothing in the answer key" },
  { group: "Efficiency" },
  { k: "cost_usd", label: "Cost", fmt: "usd", better: "low", hint: "Model spend; free tools cost $0 in licences" },
  { k: "duration_s", label: "Wall time", fmt: "dur", better: "low", hint: "Total time across the phases that ran" },
  { k: "cost_per_exploit", label: "Cost per confirmed exploit", fmt: "usd", better: "low", hint: "Cost ÷ confirmed exploits" },
  { k: "time_per_exploit", label: "Time per confirmed exploit", fmt: "dur", better: "low", hint: "Wall time ÷ confirmed exploits" },
];
const SIDES = [
  { key: "ai", label: "AI agent", cls: "ai" },
  { key: "baseline", label: "Free tools", cls: "tools" },
];

async function openCompare(ids, includeRun) {
  state.view = "compare";
  stopPolling();
  if (includeRun) ids = pairFor(includeRun);
  if (ids && ids.length) state.compare.picked = new Set(ids);
  renderRunList();
  await loadCompare();
  startPolling();
}

/* A run + the newest scored run of the other kind (same mode if possible). */
function pairFor(runId) {
  const r = state.runs.find((x) => x.run_id === runId);
  if (!r) return [runId];
  const other = state.runs.filter((x) => x.scored && x.kind !== r.kind);
  const match = other.find((x) => x.mode === r.mode) || other[0];
  return match ? [runId, match.run_id] : [runId];
}

async function loadCompare() {
  const cs = state.compare;
  cs.loading = true; cs.error = null;
  renderCompare();
  try {
    const q = cs.picked ? "?runs=" + encodeURIComponent([...cs.picked].join(",")) : "";
    cs.data = await api("/api/compare" + q);
    if (!cs.picked) cs.picked = new Set(cs.data.run_ids);
    setConn(true);
  } catch (e) {
    cs.error = e.message;
  }
  cs.loading = false;
  syncHash();
  renderCompare();
}

function renderCompare() {
  const c = $("#content");
  if (state.view !== "compare") return;
  const keepScroll = c.scrollTop;
  c.innerHTML = "";
  const cs = state.compare;
  const d = cs.data;

  const head = el("div", "detail-head");
  head.appendChild(el("h1", "plain", "AI agent vs. free tools"));
  const actions = el("span", "head-actions");
  if (d && d.ai && d.baseline) {
    const md = el("a", "btn-link", "↓ comparison.md");
    md.href = "/api/compare.md?runs=" + encodeURIComponent([...cs.picked].join(","));
    md.download = "comparison.md";
    md.title = "The same table compare_runs.py writes, ready for the written report";
    actions.appendChild(md);
  }
  head.appendChild(actions);
  c.appendChild(head);
  c.appendChild(el("div", "detail-sub", "Same target, same seven phases, same findings format, scored against the same answer key. Pick runs of each kind below; several runs on one side are averaged (± shows run-to-run spread)."));

  c.appendChild(renderPicker());

  if (cs.error) { c.appendChild(el("div", "warn-box show", cs.error)); return; }
  if (!d) { c.appendChild(el("div", "empty", cs.loading ? "Loading comparison…" : "")); return; }

  const notes = [...(d.warnings || [])];
  if (d.unscored && d.unscored.length) notes.push(`Not scored yet, so left out: ${d.unscored.join(", ")}. Use "Score" in the picker.`);
  notes.forEach((n) => c.appendChild(el("div", "warn-box show note", n)));

  if (!d.ai || !d.baseline) {
    const missing = !d.ai && !d.baseline ? "an AI run and a free-tools run" : !d.ai ? "an AI run" : "a free-tools run";
    const box = el("div", "card empty-card");
    box.appendChild(el("div", "ctitle", `Pick ${missing} to compare`));
    box.appendChild(el("div", "cbody", "Both sides need a scored run (it has score.json). No free-tools run yet? Start one from + New run → Free tools, or from the CLI: python3 -m baseline --target <url> --phases all."));
    c.appendChild(box);
    c.scrollTop = keepScroll;
    return;
  }

  c.appendChild(renderSideHeaders(d));
  c.appendChild(renderHeadlineTiles(d));
  c.appendChild(renderScorecard(d));
  c.appendChild(renderPhaseTable(d));
  c.appendChild(renderCoverage(d));
  c.appendChild(renderOverlap(d));
  c.scrollTop = keepScroll;
}

/* -- run picker: AI runs | tool runs -- */
function renderPicker() {
  const card = el("div", "card picker");
  const cols = el("div", "picker-cols");
  for (const side of SIDES) {
    const col = el("div", "picker-col");
    const h = el("div", "picker-head");
    h.appendChild(swatch(side.cls));
    h.appendChild(el("span", null, side.label + " runs"));
    col.appendChild(h);
    const runs = state.runs.filter((r) => (r.kind === "baseline") === (side.key === "baseline"));
    if (!runs.length) col.appendChild(el("div", "muted small", side.key === "baseline" ? "No free-tools runs yet." : "No AI runs yet."));
    for (const r of runs) {
      const row = el("label", "pick-row" + (r.scored ? "" : " unscored"));
      const cb = el("input");
      cb.type = "checkbox";
      cb.disabled = !r.scored;
      cb.checked = !!(state.compare.picked && state.compare.picked.has(r.run_id));
      cb.onchange = () => {
        if (!state.compare.picked) state.compare.picked = new Set();
        if (cb.checked) state.compare.picked.add(r.run_id); else state.compare.picked.delete(r.run_id);
        loadCompare();
      };
      row.appendChild(cb);
      row.appendChild(el("span", "rid", r.run_id));
      row.appendChild(el("span", "muted small", r.mode || ""));
      if (r.scored) row.appendChild(el("span", "muted small push", `detect ${pct(r.detection_rate)} · exploit ${pct(r.exploitation_rate)}`));
      else if (r.scorable) { const sp = el("span", "push"); sp.appendChild(scoreButton(r.run_id, false, true)); row.appendChild(sp); }
      else {
        const why = el("span", "muted small push", "can't score yet");
        why.dataset.tip = "Scoring needs the Vulnerability Assessment or Exploitation phase. This run stopped before them.";
        row.appendChild(why);
      }
      col.appendChild(row);
    }
    cols.appendChild(col);
  }
  card.appendChild(cols);
  return card;
}

/* -- who is being compared -- */
function renderSideHeaders(d) {
  const wrap = el("div", "side-heads");
  for (const side of SIDES) {
    const g = d[side.key];
    const box = el("div", "side-head");
    const t = el("div", "side-title");
    t.appendChild(swatch(side.cls));
    t.appendChild(el("span", null, side.label));
    t.appendChild(el("span", "muted small", `${g.trials} run${g.trials === 1 ? "" : "s"} · ${(g.modes || []).join(", ")}`));
    box.appendChild(t);
    const meta = el("div", "muted small");
    meta.textContent = side.key === "ai"
      ? `model: ${(g.models && g.models.length) ? g.models.join(", ") : "default"} · ${g.run_ids.join(", ")}`
      : `tools: ${(g.tools || []).join(", ") || "none ran"} · ${g.run_ids.join(", ")}`;
    box.appendChild(meta);
    wrap.appendChild(box);
  }
  return wrap;
}

/* -- headline: what each side found that the other didn't -- */
function renderHeadlineTiles(d) {
  const ov = d.overlap || { detection: {}, exploitation: {} };
  const n = (k, f) => ((ov[k] || {})[f] || []).length;
  const tiles = [
    { label: "Only the AI found", det: n("detection", "ai_only"), exp: n("exploitation", "ai_only"), cls: "ai" },
    { label: "Both found", det: n("detection", "both"), exp: n("exploitation", "both"), cls: "both" },
    { label: "Only the tools found", det: n("detection", "baseline_only"), exp: n("exploitation", "baseline_only"), cls: "tools" },
    { label: "Both missed", det: (d.missed_by_both || []).length, exp: null, cls: "none" },
  ];
  const wrap = el("div", "tiles");
  for (const t of tiles) {
    const tile = el("div", "tile");
    const lab = el("div", "tile-label");
    lab.appendChild(swatch(t.cls));
    lab.appendChild(el("span", null, t.label));
    tile.appendChild(lab);
    tile.appendChild(el("div", "tile-num", String(t.det)));
    tile.appendChild(el("div", "muted small", t.exp == null
      ? `of ${d.ai.graded_total || "?"} graded vulnerabilities`
      : `detected · ${t.exp} oracle-confirmed exploit${t.exp === 1 ? "" : "s"}`));
    wrap.appendChild(tile);
  }
  return wrap;
}

/* -- scorecard: paired bars per metric -- */
function renderScorecard(d) {
  const card = el("div", "card section");
  card.appendChild(sectionTitle("Scorecard", "Each row has its own scale; percentages share 0–100%."));
  card.appendChild(legend());
  for (const m of COMPARE_METRICS) {
    if (m.group) { card.appendChild(el("div", "group-label", m.group)); continue; }
    const a = d.ai.metrics[m.k] || {}, b = d.baseline.metrics[m.k] || {};
    const max = m.fmt === "pct" ? 1 : Math.max(a.mean || 0, b.mean || 0) || 1;
    const row = el("div", "mrow");
    const lab = el("div", "mlabel");
    lab.appendChild(el("div", null, m.label));
    lab.appendChild(el("div", "muted small", m.hint));
    row.appendChild(lab);
    const bars = el("div", "mbars");
    bars.appendChild(barLine("ai", a, max, m.fmt, `AI agent — ${m.label}`));
    bars.appendChild(barLine("tools", b, max, m.fmt, `Free tools — ${m.label}`));
    row.appendChild(bars);
    row.appendChild(verdict(a.mean, b.mean, m));
    card.appendChild(row);
  }
  return card;
}

function barLine(cls, cell, max, fmtName, tipLabel) {
  const v = cell ? cell.mean : null;
  const line = el("div", "bar-line");
  const track = el("div", "bar-track");
  const fill = el("div", "bar-fill " + cls);
  fill.style.width = v == null ? "0" : `${Math.max(0, Math.min(1, v / max)) * 100}%`;
  if (v != null && v > 0) fill.classList.add("nonzero");
  track.appendChild(fill);
  line.appendChild(track);
  let txt = fmt(fmtName, v);
  if (cell && cell.n > 1 && cell.std) txt += ` ±${fmtName === "pct" ? (cell.std * 100).toFixed(0) + " pts" : fmt(fmtName, cell.std)}`;
  line.appendChild(el("span", "bar-val", txt));
  line.dataset.tip = `${tipLabel}: ${txt}${cell && cell.n ? ` (n=${cell.n})` : ""}`;
  return line;
}

function verdict(a, b, m) {
  const box = el("div", "verdict");
  if (a == null || b == null) { box.appendChild(el("span", "muted small", "n/a")); return box; }
  const diff = a - b;
  const eps = m.fmt === "pct" ? 0.005 : 1e-9;
  if (Math.abs(diff) < eps) { box.appendChild(el("span", "muted small", "tie")); return box; }
  const aiWins = m.better === "high" ? diff > 0 : diff < 0;
  box.appendChild(swatch(aiWins ? "ai" : "tools"));
  const mag = Math.abs(diff);
  const delta = m.fmt === "pct" ? `${(mag * 100).toFixed(mag < 0.1 ? 1 : 0)} pts` : fmt(m.fmt, mag);
  box.appendChild(el("span", null, `${aiWins ? "AI" : "Tools"} ahead by ${delta}`));
  return box;
}

/* -- phase by phase -- */
function renderPhaseTable(d) {
  const card = el("div", "card section");
  card.appendChild(sectionTitle("Phase by phase", "What each side used and produced in each phase. Output counts aren't scored, so more isn't automatically better."));
  card.appendChild(legend());
  const table = el("table", "ptable");
  const thead = el("thead");
  const hr = el("tr");
  ["Phase", "Tools used", "Output", "Time", "Cost"].forEach((h) => hr.appendChild(el("th", null, h)));
  thead.appendChild(hr);
  table.appendChild(thead);
  const tb = el("tbody");
  const derived = new Set(d.derived_phases || []);
  for (const ph of d.phase_order) {
    const pa = d.ai.phases[ph] || {}, pb = d.baseline.phases[ph] || {};
    const tr = el("tr");
    const tdName = el("td", "ph-name");
    tdName.appendChild(el("div", null, d.phase_titles[ph] || ph));
    if (derived.has(ph)) {
      const tag = el("span", "pill", "tools: derived");
      tag.dataset.tip = (d.tools[ph] && d.tools[ph].derived) || "No free-tool equivalent; built from earlier phases' output";
      tdName.appendChild(tag);
    }
    tr.appendChild(tdName);

    const tdTools = el("td");
    tdTools.appendChild(toolsLine("ai", pa.tools, pa.ran ? "no shell tools (file work only)" : "not run"));
    const lineup = d.tools[ph] ? d.tools[ph].tools.map((t) => t.name) : [];
    const used = pb.tools && pb.tools.length ? pb.tools : null;
    tdTools.appendChild(toolsLine("tools", used,
      !pb.ran ? "not run" : derived.has(ph) ? "derived" : lineup.length ? `none produced output (lineup: ${lineup.join(", ")})` : "—"));
    tr.appendChild(tdTools);

    const tdOut = el("td");
    for (const met of d.phase_metrics[ph] || []) {
      const va = pa.ran ? pa.counts[met.field] : null, vb = pb.ran ? pb.counts[met.field] : null;
      const max = Math.max(va || 0, vb || 0) || 1;
      const blk = el("div", "out-metric");
      blk.appendChild(el("div", "muted small", met.label));
      blk.appendChild(miniBar("ai", va, max, `AI agent — ${met.label}`));
      blk.appendChild(miniBar("tools", vb, max, `Free tools — ${met.label}`));
      tdOut.appendChild(blk);
    }
    tr.appendChild(tdOut);

    const tdTime = el("td", "num-cell");
    tdTime.appendChild(pairVals(fmt("dur", pa.duration_s), fmt("dur", pb.duration_s)));
    tr.appendChild(tdTime);
    const tdCost = el("td", "num-cell");
    tdCost.appendChild(pairVals(pa.ran ? fmt("usd", pa.cost_usd) : "–", pb.ran ? fmt("usd", pb.cost_usd || 0) : "–"));
    tr.appendChild(tdCost);
    tb.appendChild(tr);
  }
  table.appendChild(tb);
  const scroller = el("div", "table-scroll");
  scroller.appendChild(table);
  card.appendChild(scroller);
  return card;
}

function toolsLine(cls, tools, emptyText) {
  const line = el("div", "tools-line");
  line.appendChild(swatch(cls));
  if (tools && tools.length) {
    tools.forEach((t) => {
      const chip = el("span", "chip", t);
      const info = state.tools && Object.values(state.tools).flatMap((p) => p.tools).find((x) => x.name === t);
      if (info && info.purpose) chip.dataset.tip = info.purpose;
      line.appendChild(chip);
    });
  } else {
    line.appendChild(el("span", "muted small", emptyText));
  }
  return line;
}

function miniBar(cls, v, max, tip) {
  const line = el("div", "mini-line");
  const track = el("div", "bar-track mini");
  const fill = el("div", "bar-fill " + cls + (v ? " nonzero" : ""));
  fill.style.width = v == null ? "0" : `${(v / max) * 100}%`;
  track.appendChild(fill);
  line.appendChild(track);
  const txt = v == null ? "not run" : fmt("num", v);
  line.appendChild(el("span", "bar-val" + (v == null ? " muted" : ""), txt));
  line.dataset.tip = `${tip}: ${txt}`;
  return line;
}

function pairVals(a, b) {
  const box = el("div", "pair-vals");
  for (const [cls, v] of [["ai", a], ["tools", b]]) {
    const r = el("div");
    r.appendChild(swatch(cls));
    r.appendChild(el("span", null, v));
    box.appendChild(r);
  }
  return box;
}

/* -- coverage by OWASP category and difficulty -- */
function renderCoverage(d) {
  const cs = state.compare;
  const card = el("div", "card section");
  const title = sectionTitle("Coverage", "Share of graded vulnerabilities in each bucket that each side hit.");
  const seg = el("div", "seg small-seg");
  for (const [k, lab] of [["exploitation", "Exploited (oracle)"], ["detection", "Detected"]]) {
    const b = el("button", "seg-btn" + (cs.cov === k ? " sel" : ""), lab);
    b.type = "button";
    b.onclick = () => { cs.cov = k; renderCompare(); };
    seg.appendChild(b);
  }
  title.appendChild(seg);
  card.appendChild(title);
  card.appendChild(legend());

  const exp = cs.cov === "exploitation";
  const blocks = [
    ["By OWASP Top 10 category", exp ? "by_owasp" : "detection_by_owasp", (k) => k === "(none)" ? "Uncategorized" : k.replace(/:2021/, "")],
    ["By difficulty (1 = easiest)", exp ? "by_difficulty" : "detection_by_difficulty", (k) => `Difficulty ${k}`],
  ];
  const grid = el("div", "cov-grid");
  for (const [heading, field, labelFn] of blocks) {
    const col = el("div", "cov-col");
    col.appendChild(el("div", "group-label", heading));
    const A = d.ai[field], B = d.baseline[field];
    if (!A || !B) {
      col.appendChild(el("div", "muted small", "Not in these score files. Re-score the runs (Score button) to get it."));
      grid.appendChild(col);
      continue;
    }
    const keys = [...new Set([...Object.keys(A), ...Object.keys(B)])].sort();
    for (const k of keys) {
      const a = A[k] || { hit: 0, total: 0, rate: null }, b = B[k] || { hit: 0, total: 0, rate: null };
      const total = a.total || b.total;
      const row = el("div", "cov-row");
      const lab = el("div", "cov-label");
      lab.appendChild(el("span", null, labelFn(k)));
      lab.appendChild(el("span", "muted small", `${total} graded`));
      row.appendChild(lab);
      const bars = el("div", "cov-bars");
      bars.appendChild(covBar("ai", a, `AI agent — ${labelFn(k)}`));
      bars.appendChild(covBar("tools", b, `Free tools — ${labelFn(k)}`));
      row.appendChild(bars);
      col.appendChild(row);
    }
    grid.appendChild(col);
  }
  card.appendChild(grid);
  return card;
}

function covBar(cls, cell, tip) {
  const line = el("div", "bar-line");
  const track = el("div", "bar-track");
  const fill = el("div", "bar-fill " + cls + (cell.hit ? " nonzero" : ""));
  fill.style.width = `${(cell.rate || 0) * 100}%`;
  track.appendChild(fill);
  line.appendChild(track);
  const txt = `${fmt("num", cell.hit)}/${fmt("num", cell.total)}`;
  line.appendChild(el("span", "bar-val", txt));
  line.dataset.tip = `${tip}: ${txt} (${pct(cell.rate)})`;
  return line;
}

/* -- overlap: which vulnerabilities, by name -- */
function renderOverlap(d) {
  const cs = state.compare;
  const card = el("div", "card section");
  card.appendChild(sectionTitle(cs.cov === "exploitation" ? "Overlap — oracle-confirmed exploits" : "Overlap — detections",
    "Which vulnerabilities each side reached. Switch with the Coverage toggle above."));
  const ov = (d.overlap || {})[cs.cov] || { ai_only: [], both: [], baseline_only: [] };
  const cols = el("div", "overlap-cols");
  for (const [field, label, cls] of [["ai_only", "Only the AI", "ai"], ["both", "Both", "both"], ["baseline_only", "Only the tools", "tools"]]) {
    const col = el("div", "overlap-col");
    const h = el("div", "picker-head");
    h.appendChild(swatch(cls));
    h.appendChild(el("span", null, `${label} (${ov[field].length})`));
    col.appendChild(h);
    col.appendChild(vulnChips(ov[field], d.names));
    cols.appendChild(col);
  }
  card.appendChild(cols);
  const missed = d.missed_by_both || [];
  const det = el("details", "missed");
  det.appendChild(el("summary", null, `Missed by both (${missed.length}) — what neither approach caught`));
  det.appendChild(vulnChips(missed, d.names));
  card.appendChild(det);
  return card;
}

function vulnChips(keys, names) {
  const box = el("div", "chips");
  if (!keys.length) { box.appendChild(el("span", "muted small", "none")); return box; }
  for (const k of keys) {
    const n = names[k];
    const chip = el("span", "chip vuln-chip", n ? n.name : k);
    chip.dataset.tip = n ? `${k} · ${n.owasp || "no OWASP category"} · difficulty ${n.difficulty}` : k;
    box.appendChild(chip);
  }
  return box;
}

/* -- shared bits -- */
function sectionTitle(text, sub) {
  const t = el("div", "section-title");
  const left = el("div");
  left.appendChild(el("div", "ctitle", text));
  if (sub) left.appendChild(el("div", "muted small", sub));
  t.appendChild(left);
  return t;
}

function legend() {
  const lg = el("div", "legend");
  for (const s of SIDES) {
    const item = el("span", "legend-item");
    item.appendChild(swatch(s.cls));
    item.appendChild(el("span", null, s.label));
    lg.appendChild(item);
  }
  return lg;
}

function swatch(cls) { return el("span", "swatch " + cls); }

function kindBadge(kind) {
  const b = el("span", "kind " + (kind === "baseline" ? "tools" : "ai"), kind === "baseline" ? "TOOLS" : "AI");
  b.title = kind === "baseline" ? "Free-tools baseline run" : "AI agent run";
  return b;
}

/* Score a run against the master vuln list (writes score.json). */
function scoreButton(runId, scored, small) {
  const b = el("button", small ? "small-btn" : null, scored ? "Re-score" : "Score");
  b.title = "Score this run against the master vulnerability list (needed to compare it)";
  b.onclick = async (e) => {
    e.preventDefault(); e.stopPropagation();
    b.disabled = true; b.textContent = "Scoring…";
    try {
      await api(`/api/runs/${encodeURIComponent(runId)}/score`, { method: "POST" });
      await loadRuns();
      if (state.view === "compare") await loadCompare();
      else await refreshDetail(false);
    } catch (err) {
      b.disabled = false; b.textContent = scored ? "Re-score" : "Score";
      alert("Scoring failed: " + err.message);
    }
  };
  return b;
}

/* One floating tooltip for anything with data-tip (bars, chips, tags). */
function initTooltip() {
  const tip = $("#tip");
  const show = (e) => {
    const t = e.target.closest && e.target.closest("[data-tip]");
    if (!t) { tip.classList.remove("show"); return; }
    tip.textContent = t.dataset.tip;
    tip.classList.add("show");
    const pad = 14, w = tip.offsetWidth, h = tip.offsetHeight;
    let x = e.clientX + pad, y = e.clientY + pad;
    if (x + w > window.innerWidth - 8) x = e.clientX - w - pad;
    if (y + h > window.innerHeight - 8) y = e.clientY - h - pad;
    tip.style.left = `${Math.max(8, x)}px`;
    tip.style.top = `${Math.max(8, y)}px`;
  };
  document.addEventListener("mousemove", show);
  document.addEventListener("mouseleave", () => tip.classList.remove("show"));
}

function fmt(kind, v) {
  if (v == null || Number.isNaN(v)) return "–";
  if (kind === "pct") return pct(v);
  if (kind === "usd") return "$" + v.toFixed(2);
  if (kind === "dur") {
    if (v < 90) return `${Math.round(v)}s`;
    if (v < 5400) return `${(v / 60).toFixed(1)} min`;
    return `${(v / 3600).toFixed(1)} h`;
  }
  return Number.isInteger(v) ? String(v) : v.toFixed(1);
}
function pct(v) {
  if (v == null) return "–";
  const p = v * 100;
  return `${p > 0 && p < 10 ? p.toFixed(1) : p.toFixed(0)}%`;
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
  api("/api/tools").then((t) => {
    state.tools = t.phases;
    if ($("#modal-back").classList.contains("show")) setEngine(state.engine);
  }).catch(() => {});

  // Deep link: open #<run>/<phase>/<tab> directly (handy for demos/bookmarks).
  const [hRun, hPhase, hTab] = location.hash.slice(1).split("/");
  if (hRun === "compare") {
    await openCompare(hPhase ? hPhase.split(",").filter(Boolean) : null);
    startPolling();
  } else if (hRun && state.runs.some((r) => r.run_id === hRun)) {
    await selectRun(hRun, hPhase, hTab);
  } else {
    startPolling();
  }
  window.addEventListener("hashchange", () => {
    const [r, p, t] = location.hash.slice(1).split("/");
    if (r === "compare") { if (state.view !== "compare") openCompare(p ? p.split(",").filter(Boolean) : null); }
    else if (r && (r !== state.selectedRun || state.view !== "run")) selectRun(r, p, t);
  });

  $("#btn-new").onclick = openModal;
  $("#btn-compare").onclick = () => openCompare(state.compare.picked ? [...state.compare.picked] : null);
  document.querySelectorAll("#f-engine .seg-btn").forEach((b) => { b.onclick = () => setEngine(b.dataset.engine); });
  initTooltip();
  $("#btn-cancel").onclick = closeModal;
  $("#btn-launch").onclick = launch;
  $("#modal-back").onclick = (e) => { if (e.target.id === "modal-back") closeModal(); };
  $("#f-mode").onchange = (e) => { $("#f-source-wrap").style.display = e.target.value === "white-box" ? "block" : "none"; };
  $("#f-unattended").onchange = (e) => { $("#f-warn").classList.toggle("show", e.target.checked); };
}

document.addEventListener("DOMContentLoaded", boot);

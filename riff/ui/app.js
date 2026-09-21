/* riff control surface.
   No framework, no inline script — the CSP forbids both. */

"use strict";

const MAX_ROWS = 4000;

const state = {
  flows: [],
  byId: new Map(),
  selected: null,
  filter: "",
  predicate: () => true,
  paused: false,
  missed: 0,
  lastId: 0,
  csrf: "",
  config: null,
  checked: new Set(),   // flow ids ticked for export
  lastChecked: null,    // anchor for shift-click ranges
  findings: new Map(),  // finding key -> finding row, from the passive scanner
};

const $ = (sel) => document.querySelector(sel);
const rowsEl = $("#rows");
const emptyEl = $("#empty");

/* ── tiny helpers ─────────────────────────────────────────────── */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function humanSize(bytes) {
  if (!bytes) return "\u2013";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1048576).toFixed(1) + " MB";
}

function humanMs(ms) {
  if (!ms) return "\u2013";
  if (ms < 1000) return Math.round(ms) + " ms";
  return (ms / 1000).toFixed(2) + " s";
}

function statusClass(flow) {
  if (flow.aborted || flow.error) return "s-err";
  const code = flow.status;
  if (!code) return "s-none";
  if (code < 300) return "s-2xx";
  if (code < 400) return "s-3xx";
  if (code < 500) return "s-4xx";
  return "s-5xx";
}

function toast(message, kind) {
  const node = el("div", "toast" + (kind ? " " + kind : ""), message);
  $("#toasts").append(node);
  setTimeout(() => node.remove(), kind === "bad" ? 7000 : 3200);
}

/* ── API ──────────────────────────────────────────────────────── */

async function api(path, options) {
  const opts = Object.assign({ headers: {} }, options || {});
  const method = (opts.method || "GET").toUpperCase();
  if (method !== "GET") {
    opts.headers["X-Riff-Token"] = state.csrf;
    opts.headers["Content-Type"] = "application/json";
  }
  const response = await fetch(path, opts);
  const text = await response.text();
  let payload = null;
  try { payload = text ? JSON.parse(text) : null; } catch (_) { payload = { error: text }; }
  if (!response.ok) {
    const err = new Error((payload && payload.error) || response.statusText);
    err.payload = payload;
    err.status = response.status;
    throw err;
  }
  return payload;
}

/* ── filtering ────────────────────────────────────────────────── */

function buildPredicate(query) {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return () => true;

  const tests = terms.map((raw) => {
    const negated = raw.startsWith("!");
    const term = negated ? raw.slice(1) : raw;
    const split = term.indexOf(":");
    const key = split > 0 ? term.slice(0, split) : "";
    const value = split > 0 ? term.slice(split + 1) : term;
    let test;

    switch (key) {
      case "status": {
        test = (f) => {
          const code = String(f.status || "");
          if (/^\dxx$/.test(value)) return code.startsWith(value[0]);
          return code.startsWith(value);
        };
        break;
      }
      case "method": test = (f) => f.method.toLowerCase() === value; break;
      case "host":   test = (f) => f.host.includes(value); break;
      case "path":   test = (f) => f.path.toLowerCase().includes(value); break;
      case "type":   test = (f) => (f.content_type || "").toLowerCase().includes(value); break;
      case "tag":    test = (f) => f.tags.some((t) => t.toLowerCase().includes(value)); break;
      case "id":     test = (f) => String(f.id) === value; break;
      default:
        test = (f) =>
          f.url.toLowerCase().includes(value) ||
          (f.content_type || "").toLowerCase().includes(value) ||
          f.tags.some((t) => t.toLowerCase().includes(value));
    }
    return negated ? (f) => !test(f) : test;
  });

  return (flow) => tests.every((t) => t(flow));
}

/* ── row rendering ────────────────────────────────────────────── */

function makeRow(flow) {
  const row = el("div", "row");
  row.dataset.id = String(flow.id);

  const check = el("span", "col-check");
  const box = document.createElement("input");
  box.type = "checkbox";
  box.checked = state.checked.has(flow.id);
  box.setAttribute("aria-label", "select flow " + flow.id);
  check.append(box);
  row.append(check);
  if (box.checked) row.classList.add("is-checked");

  row.append(el("span", "col-id", String(flow.id)));
  row.append(el("span", "col-method m-" + flow.method, flow.method));

  const status = el("span", "col-status " + statusClass(flow));
  status.textContent = flow.aborted ? "ABRT" : flow.error ? "ERR" : flow.status || "\u2013";
  row.append(status);

  const host = el("span", "col-host");
  if (flow.tls) {
    const lock = el("span", "lock", "\u25CF");
    lock.title = "intercepted over TLS";
    host.append(lock);
  }
  host.append(document.createTextNode(flow.host));
  row.append(host);

  const path = el("span", "col-path", flow.path);
  if (flow.intercepted) path.append(el("span", "badge-tag badge-synth", "synthetic"));
  for (const tag of flow.tags) {
    if (tag === "replay" || tag === "upgrade" || !flow.intercepted) path.append(el("span", "badge-tag", tag));
  }
  row.append(path);

  row.append(el("span", "col-type", (flow.content_type || "").replace(/^application\//, "")));
  row.append(el("span", "col-size", humanSize(flow.size)));
  row.append(el("span", "col-time", humanMs(flow.duration_ms)));
  return row;
}

function atBottom() {
  return rowsEl.scrollHeight - rowsEl.scrollTop - rowsEl.clientHeight < 40;
}

function addFlow(flow, animate) {
  if (state.byId.has(flow.id)) return;
  state.flows.push(flow);
  state.byId.set(flow.id, flow);
  state.lastId = Math.max(state.lastId, flow.id);

  while (state.flows.length > MAX_ROWS) {
    const dropped = state.flows.shift();
    state.byId.delete(dropped.id);
    state.checked.delete(dropped.id);
    const stale = rowsEl.querySelector('.row[data-id="' + dropped.id + '"]');
    if (stale) stale.remove();
  }

  if (!state.predicate(flow)) return;

  const stick = atBottom();
  const row = makeRow(flow);
  if (animate) {
    row.classList.add("is-new");
    setTimeout(() => row.classList.remove("is-new"), 600);
  }
  rowsEl.append(row);
  emptyEl.hidden = true;
  if (stick) rowsEl.scrollTop = rowsEl.scrollHeight;
}

function rerender() {
  const fragment = document.createDocumentFragment();
  let shown = 0;
  for (const flow of state.flows) {
    if (!state.predicate(flow)) continue;
    const row = makeRow(flow);
    if (state.selected === flow.id) row.classList.add("is-selected");
    fragment.append(row);
    shown++;
  }
  rowsEl.replaceChildren(emptyEl, fragment);
  emptyEl.hidden = shown > 0;
  rowsEl.scrollTop = rowsEl.scrollHeight;
  updateStats();
  updateSelectionStats();
}

function updateStats() {
  const visible = state.flows.filter(state.predicate).length;
  const total = state.flows.length;
  $("#stat-count").textContent =
    visible === total ? `${total} flows` : `${visible} of ${total} flows`;
  const bytes = state.flows.reduce((sum, f) => sum + (f.size || 0) + (f.request_size || 0), 0);
  $("#stat-bytes").textContent = humanSize(bytes);
}

/* ── selection, export, import ────────────────────────────────── */

function visibleIds() {
  return Array.from(rowsEl.querySelectorAll(".row"), (r) => Number(r.dataset.id));
}

function syncCheckUI() {
  for (const row of rowsEl.querySelectorAll(".row")) {
    const on = state.checked.has(Number(row.dataset.id));
    row.classList.toggle("is-checked", on);
    const box = row.querySelector(".col-check input");
    if (box) box.checked = on;
  }
  updateSelectionStats();
}

function updateSelectionStats() {
  const n = state.checked.size;
  const stat = $("#stat-selected");
  stat.hidden = n === 0;
  $("#stat-selected-sep").hidden = n === 0;
  stat.textContent = `${n} selected`;
  $("#btn-export").textContent = n ? `Export (${n})` : "Export";
  const shown = visibleIds();
  const shownChecked = shown.filter((id) => state.checked.has(id)).length;
  const all = $("#check-all");
  all.checked = shown.length > 0 && shownChecked === shown.length;
  all.indeterminate = shownChecked > 0 && shownChecked < shown.length;
}

function toggleCheck(id, withRange) {
  if (withRange && state.lastChecked !== null && state.lastChecked !== id) {
    const shown = visibleIds();
    const a = shown.indexOf(state.lastChecked);
    const b = shown.indexOf(id);
    if (a >= 0 && b >= 0) {
      for (const each of shown.slice(Math.min(a, b), Math.max(a, b) + 1)) state.checked.add(each);
      state.lastChecked = id;
      syncCheckUI();
      return;
    }
  }
  if (state.checked.has(id)) state.checked.delete(id); else state.checked.add(id);
  state.lastChecked = id;
  syncCheckUI();
}

function clearChecks() {
  state.checked.clear();
  state.lastChecked = null;
  syncCheckUI();
}

function showExportMenu(open) {
  const menu = $("#export-menu");
  const show = open === undefined ? menu.hidden : open;
  menu.hidden = !show;
  $("#btn-export").setAttribute("aria-expanded", String(show));
  if (show) menu.querySelector(".menu-item").focus();
}

function filenameFrom(response, fallback) {
  const header = response.headers.get("Content-Disposition") || "";
  const match = /filename="([^"]+)"/.exec(header);
  return match ? match[1] : fallback;
}

async function exportFlows(format) {
  showExportMenu(false);
  const ids = state.checked.size ? Array.from(state.checked) : visibleIds();
  if (!ids.length) { toast("Nothing to export", "bad"); return; }
  try {
    const response = await fetch(`/api/export?format=${format}&ids=${ids.join(",")}`, {
      headers: { "X-Riff-Token": state.csrf },
    });
    if (!response.ok) {
      let message = response.statusText;
      try { message = (await response.json()).error || message; } catch (_) { /* keep statusText */ }
      throw new Error(message);
    }
    const blob = await response.blob();
    const name = filenameFrom(response, format === "har" ? "riff.har" : "riff.json");
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = name;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 4000);
    const count = response.headers.get("X-Riff-Exported") || ids.length;
    toast(`Exported ${count} flow${count === "1" || count === 1 ? "" : "s"} to ${name}`, "good");
  } catch (err) {
    toast("Export failed: " + err.message, "bad");
  }
}

async function importFiles(files) {
  let total = 0;
  for (const file of files) {
    let text;
    try { text = await file.text(); } catch (err) { toast(`Could not read ${file.name}: ${err.message}`, "bad"); continue; }
    try {
      const result = await api("/api/import", { method: "POST", body: text });
      total += result.imported;
    } catch (err) {
      toast(`${file.name}: ${err.message}`, "bad");
    }
  }
  if (!total) return;
  // While paused the stream is ignored, so pull the new rows in directly.
  try {
    const data = await api("/api/flows?since=" + state.lastId);
    for (const flow of data.flows) addFlow(flow, true);
    updateStats();
    updateSelectionStats();
  } catch (_) { /* the stream will deliver them */ }
  toast(`Imported ${total} flow${total === 1 ? "" : "s"} \u2014 tagged imported`, "good");
}

/* ── detail pane ──────────────────────────────────────────────── */

function kvBlock(title, pairs) {
  const wrap = document.createDocumentFragment();
  const heading = el("div", "kv-title");
  heading.append(document.createTextNode(title));
  heading.append(el("span", "count", String(pairs.length)));
  wrap.append(heading);

  if (!pairs.length) {
    wrap.append(el("p", "body-note", "none"));
    return wrap;
  }
  const list = el("dl", "kv");
  for (const [key, value] of pairs) {
    list.append(el("dt", null, key));
    const dd = el("dd", String(value).includes("\u00ab") ? "redacted" : null, value);
    list.append(dd);
  }
  wrap.append(list);
  return wrap;
}

function highlightJson(text) {
  let parsed;
  try { parsed = JSON.parse(text); } catch (_) { return null; }
  const pretty = JSON.stringify(parsed, null, 2);
  const html = escapeHtml(pretty).replace(
    /(&quot;(?:\\.|[^&\\]|&(?!quot;))*&quot;)(\s*:)?|\b(true|false)\b|\bnull\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (match, str, colon, bool, num) => {
      if (str) return `<span class="${colon ? "j-key" : "j-str"}">${str}</span>${colon || ""}`;
      if (bool) return `<span class="j-bool">${match}</span>`;
      if (num) return `<span class="j-num">${match}</span>`;
      return `<span class="j-null">${match}</span>`;
    }
  );
  return html;
}

function bodyBlock(message) {
  const wrap = document.createDocumentFragment();
  const body = message.body || {};
  const heading = el("div", "kv-title");
  heading.append(document.createTextNode("Body"));
  heading.append(el("span", "count", humanSize(body.size || 0)));
  wrap.append(heading);

  if (body.streamed) {
    wrap.append(el("p", "body-note",
      "Streamed past riff without buffering (larger than --max-body), so no copy was kept."));
    return wrap;
  }
  if (!body.size) {
    wrap.append(el("p", "body-note", "empty"));
    return wrap;
  }
  if (body.base64 !== undefined) {
    wrap.append(el("p", "body-note", "Binary payload \u2014 " + humanSize(body.size) + ", not shown as text."));
    return wrap;
  }

  const pre = el("pre", "body-block");
  const highlighted = highlightJson(body.text || "");
  if (highlighted !== null) pre.innerHTML = highlighted;
  else pre.textContent = body.text || "";
  wrap.append(pre);

  if (body.truncated) {
    wrap.append(el("p", "body-note", "Truncated for display."));
  }
  return wrap;
}

function cookiePairs(headers, isResponse) {
  const out = [];
  for (const [name, value] of headers) {
    const lower = name.toLowerCase();
    if (isResponse && lower === "set-cookie") {
      const [pair] = value.split(";");
      const idx = pair.indexOf("=");
      if (idx > 0) out.push([pair.slice(0, idx).trim(), pair.slice(idx + 1).trim()]);
    } else if (!isResponse && lower === "cookie") {
      for (const chunk of value.split(";")) {
        const idx = chunk.indexOf("=");
        if (idx > 0) out.push([chunk.slice(0, idx).trim(), chunk.slice(idx + 1).trim()]);
      }
    }
  }
  return out;
}

function queryPairs(url) {
  const idx = url.indexOf("?");
  if (idx < 0) return [];
  const out = [];
  for (const chunk of url.slice(idx + 1).split("&")) {
    if (!chunk) continue;
    const eq = chunk.indexOf("=");
    const decode = (s) => { try { return decodeURIComponent(s.replace(/\+/g, " ")); } catch (_) { return s; } };
    out.push(eq < 0 ? [decode(chunk), ""] : [decode(chunk.slice(0, eq)), decode(chunk.slice(eq + 1))]);
  }
  return out;
}

function renderDetail(detail) {
  $("#detail-placeholder").hidden = true;
  $("#detail-body").hidden = false;

  const req = detail.request;
  const resp = detail.response;

  $("#d-method").textContent = req.method;
  $("#d-method").className = "pill m-" + req.method;
  $("#d-status").textContent = resp ? resp.status : detail.error ? "ERR" : "\u2013";
  $("#d-status").className = "pill " + statusClass({ status: resp ? resp.status : 0, error: detail.error });
  $("#d-url").textContent = req.url;
  $("#d-url").title = req.url;

  /* request */
  const reqPanel = $('[data-panel="request"]');
  reqPanel.replaceChildren();
  reqPanel.append(kvBlock("General", [
    ["Method", req.method],
    ["URL", req.url],
    ["HTTP version", req.http_version],
    ["Client", detail.client],
    ["TLS", detail.tls ? "intercepted" : "plaintext"],
    ["Flow id", detail.id],
  ]));
  const query = queryPairs(req.url);
  if (query.length) reqPanel.append(kvBlock("Query", query));
  reqPanel.append(kvBlock("Headers", req.headers));
  const reqCookies = cookiePairs(req.headers, false);
  if (reqCookies.length) reqPanel.append(kvBlock("Cookies", reqCookies));
  reqPanel.append(bodyBlock(req));

  /* response */
  const respPanel = $('[data-panel="response"]');
  respPanel.replaceChildren();
  if (!resp) {
    respPanel.append(el("p", "body-note", detail.error || "No response was received."));
  } else {
    respPanel.append(kvBlock("General", [
      ["Status", resp.status + " " + (resp.reason || "")],
      ["HTTP version", resp.http_version],
      ["Content encoding", resp.content_encoding || "identity"],
      ["Synthetic", detail.intercepted ? "yes \u2014 produced by a rule" : "no"],
    ]));
    respPanel.append(kvBlock("Headers", resp.headers));
    const respCookies = cookiePairs(resp.headers, true);
    if (respCookies.length) respPanel.append(kvBlock("Set-Cookie", respCookies));
    respPanel.append(bodyBlock(resp));
  }

  /* timing */
  const timingPanel = $('[data-panel="timing"]');
  timingPanel.replaceChildren();
  const total = detail.duration_ms || 0;
  const grid = el("div", "timing");
  const addBar = (label, value, fraction) => {
    grid.append(el("div", "timing-label", label));
    const track = el("div", "timing-track");
    const fill = el("div", "timing-fill");
    fill.style.width = Math.max(2, Math.min(100, fraction * 100)) + "%";
    track.append(fill);
    grid.append(track);
    grid.append(el("div", "timing-value", value));
  };
  addBar("Total", humanMs(total), 1);
  addBar("Request bytes", humanSize(req.body ? req.body.size : 0), 0.35);
  addBar("Response bytes", humanSize(resp && resp.body ? resp.body.size : 0), 0.6);
  timingPanel.append(grid);
  if (detail.logs && detail.logs.length) {
    timingPanel.append(kvBlock("Script log", detail.logs.map((line, i) => [String(i + 1), line])));
  }
  if (detail.tags && detail.tags.length) {
    timingPanel.append(kvBlock("Tags", detail.tags.map((t) => ["tag", t])));
  }

  /* raw */
  const rawPanel = $('[data-panel="raw"]');
  rawPanel.replaceChildren();
  rawPanel.append(el("div", "kv-title", "Request"));
  rawPanel.append(el("pre", "body-block", rawText(req, true, detail)));
  if (resp) {
    rawPanel.append(el("div", "kv-title", "Response"));
    rawPanel.append(el("pre", "body-block", rawText(resp, false, detail)));
  }
}

function rawText(message, isRequest, detail) {
  const lines = [];
  if (isRequest) {
    const path = message.url.replace(/^https?:\/\/[^/]+/, "") || "/";
    lines.push(`${message.method} ${path} ${message.http_version}`);
  } else {
    lines.push(`${message.http_version} ${message.status} ${message.reason || ""}`.trim());
  }
  for (const [key, value] of message.headers) lines.push(`${key}: ${value}`);
  lines.push("");
  const body = message.body || {};
  if (body.streamed) lines.push("<streamed, not buffered>");
  else if (body.base64 !== undefined) lines.push(`<binary, ${body.size} bytes>`);
  else if (body.text) lines.push(body.text);
  return lines.join("\n");
}

async function select(id) {
  state.selected = id;
  for (const row of rowsEl.querySelectorAll(".row.is-selected")) row.classList.remove("is-selected");
  const row = rowsEl.querySelector('.row[data-id="' + id + '"]');
  if (row) row.classList.add("is-selected");
  try {
    renderDetail(await api("/api/flow/" + id));
  } catch (err) {
    toast("Could not load flow " + id + ": " + err.message, "bad");
  }
}

/* ── curl ─────────────────────────────────────────────────────── */

function toCurl(detail) {
  const req = detail.request;
  const quote = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";
  const parts = ["curl -i -X " + req.method, quote(req.url)];
  for (const [key, value] of req.headers) {
    if (key.toLowerCase() === "content-length") continue;
    parts.push("-H " + quote(key + ": " + value));
  }
  const body = req.body || {};
  if (body.text) parts.push("--data-raw " + quote(body.text));
  return parts.join(" \\\n  ");
}

/* ── live stream ──────────────────────────────────────────────── */

let source = null;
let backoff = 500;

function setConn(status, label) {
  const node = $("#stat-conn");
  node.className = "conn " + status;
  node.replaceChildren(el("i", "dot"), document.createTextNode(label));
}

function connect() {
  if (source) source.close();
  source = new EventSource("/api/stream");

  source.onopen = () => { backoff = 500; setConn("is-live", "live"); };

  source.onmessage = (event) => {
    let message;
    try { message = JSON.parse(event.data); } catch (_) { return; }
    if (message.type === "flow") {
      if (state.paused) { state.missed++; refreshRecordLabel(); return; }
      addFlow(message.data, true);
      updateStats();
    } else if (message.type === "tunnel") {
      const d = message.data;
      $("#stat-tunnels").textContent = d.host ? `tunnel ${d.host}:${d.port}` : "0 tunnels";
    } else if (message.type === "finding") {
      ingestFinding(message.data);
    } else if (message.type === "scan") {
      if (scanJobId == null || message.data.id === scanJobId) showScanProgress(message.data);
    } else if (message.type === "findings_cleared") {
      state.findings.clear(); refreshFindingsBadge();
      if (!$("#drawer-findings").hidden) renderFindings();
    } else if (message.type === "error") {
      toast(message.data.text, "bad");
    } else if (message.type === "cleared") {
      state.flows = []; state.byId.clear(); state.selected = null;
      state.checked.clear(); state.lastChecked = null;
      state.findings.clear(); refreshFindingsBadge();
      if (!$("#drawer-findings").hidden) renderFindings();
      $("#detail-body").hidden = true; $("#detail-placeholder").hidden = false;
      rerender();
    }
  };

  source.onerror = () => {
    setConn("is-down", "reconnecting");
    source.close();
    setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, 8000);
  };
}

function refreshRecordLabel() {
  const button = $("#btn-record");
  button.classList.toggle("is-paused", state.paused);
  $("#record-label").textContent = state.paused
    ? (state.missed ? `Paused (${state.missed})` : "Paused")
    : "Recording";
}

/* ── drawers ──────────────────────────────────────────────────── */

function openDrawer(id) {
  for (const drawer of document.querySelectorAll(".drawer")) drawer.hidden = drawer.id !== id;
}
function closeDrawers() {
  for (const drawer of document.querySelectorAll(".drawer")) drawer.hidden = true;
}

/* ── findings (passive scanner) ───────────────────────────────── */

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

function ingestFinding(row) {
  state.findings.set(row.key, row);
  refreshFindingsBadge();
  if (!$("#drawer-findings").hidden) renderFindings();
}

function refreshFindingsBadge() {
  const badge = $("#findings-badge");
  let high = 0, total = 0;
  for (const f of state.findings.values()) { total++; if (f.severity === "high") high++; }
  badge.textContent = String(total);
  badge.hidden = total === 0;
  badge.classList.toggle("badge-high", high > 0);
}

function renderFindings() {
  const list = $("#findings-list");
  const rows = Array.from(state.findings.values())
    .sort((a, b) => (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]) || (b.at - a.at));
  list.replaceChildren();
  $("#findings-empty").hidden = rows.length > 0;
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of rows) counts[f.severity] = (counts[f.severity] || 0) + 1;
  $("#findings-summary").textContent = rows.length
    ? `${counts.high} high · ${counts.medium} medium · ${counts.low} low · ${counts.info} info`
    : "";
  for (const f of rows) {
    const item = el("div", "finding sev-" + f.severity);
    const head = el("div", "finding-head");
    head.append(el("span", "sev-tag", f.severity));
    head.append(el("span", "finding-title", f.title));
    if (f.confidence === "tentative") head.append(el("span", "finding-tentative", "tentative"));
    const link = el("button", "finding-flow", "#" + f.flow_id);
    link.title = "Open flow " + f.flow_id;
    link.addEventListener("click", () => { location.hash = "flow/" + f.flow_id; });
    head.append(link);
    item.append(head);
    if (f.evidence) item.append(el("div", "finding-evidence", f.evidence));
    if (f.detail) item.append(el("div", "finding-detail", f.detail));
    list.append(item);
  }
}

async function openFindings() {
  openDrawer("drawer-findings");
  try {
    const data = await api("/api/findings");
    state.findings.clear();
    for (const row of data.findings) state.findings.set(row.key, row);
    refreshFindingsBadge();
  } catch (_) { /* non-fatal: keep whatever the stream delivered */ }
  renderFindings();
  try {
    const info = await api("/api/scan");
    const list = $("#scan-host-options");
    list.replaceChildren();
    for (const host of info.hosts) {
      const opt = document.createElement("option");
      opt.value = host;
      list.append(opt);
    }
  } catch (_) { /* the datalist is a convenience only */ }
}

async function clearFindings() {
  try { await api("/api/findings/clear", { method: "POST" }); } catch (err) { toast(err.message, "bad"); return; }
  state.findings.clear();
  refreshFindingsBadge();
  renderFindings();
}

async function rescanFindings() {
  try {
    await api("/api/findings/rescan", { method: "POST" });
    const data = await api("/api/findings");
    state.findings.clear();
    for (const row of data.findings) state.findings.set(row.key, row);
    refreshFindingsBadge();
    renderFindings();
    toast(`Rescanned: ${state.findings.size} finding(s)`, "");
  } catch (err) { toast(err.message, "bad"); }
}

/* Active scan: sends attack payloads, so it is gated on an explicit host scope. */

let scanJobId = null;

function parseHosts(raw) {
  return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

async function startScan() {
  const hosts = parseHosts($("#scan-hosts").value);
  if (!hosts.length) { toast("Name at least one in-scope host before scanning.", "bad"); return; }
  const body = { hosts };
  if ($("#scan-time").checked) body.checks = ["xss-reflected", "sqli-error", "sqli-boolean", "open-redirect", "path-traversal", "ssrf", "sqli-time", "cmd-injection"];
  if ($("#scan-oob").checked) body.oob = true;
  try {
    const job = await api("/api/scan", { method: "POST", body: JSON.stringify(body) });
    scanJobId = job.id;
    showScanProgress(job);
  } catch (err) { toast(err.message, "bad"); }
}

async function cancelScan() {
  if (scanJobId == null) return;
  try { await api("/api/scan/cancel", { method: "POST", body: JSON.stringify({ id: scanJobId }) }); }
  catch (err) { toast(err.message, "bad"); }
}

function showScanProgress(job) {
  const running = job.status === "running";
  $("#scan-progress").hidden = false;
  $("#btn-scan-cancel").hidden = !running;
  $("#btn-scan-start").disabled = running;
  const pct = job.units_total ? Math.round((job.units_done / job.units_total) * 100) : (running ? 0 : 100);
  $("#scan-progress-fill").style.width = pct + "%";
  const label = running
    ? `Scanning ${job.hosts.join(", ")} — ${job.units_done}/${job.units_total} inputs, ${job.probes_sent} probes, ${job.findings_new} new`
    : `${job.status === "done" ? "Scan complete" : "Scan " + job.status}: ${job.probes_sent} probes, ${job.findings_new} new finding(s)`;
  $("#scan-progress-text").textContent = label;
  if (!running) {
    $("#btn-scan-cancel").hidden = true;
    $("#btn-scan-start").disabled = false;
    if (job.id === scanJobId) scanJobId = null;
    setTimeout(() => { if (scanJobId == null) $("#scan-progress").hidden = true; }, 6000);
  }
}

/* Deep links: #rules, #compose, #setup, #flow/12, #flow/12/response.
   Handy for bookmarking a view, and for sharing "look at flow 12" with
   someone sitting at the same capture. */
async function applyHash() {
  const hash = location.hash.replace(/^#/, "");
  if (!hash) return;
  const [head, ...rest] = hash.split("/");

  if (head === "rules") return openScript();
  if (head === "findings") return openFindings();
  if (head === "compose") return rest[0] ? openComposeAt(rest[0], rest[1]) : openCompose(null);
  if (head === "setup") {
    openDrawer("drawer-setup");
    if (state.config) renderSetup(state.config);
    return;
  }
  if (head === "flow" && rest[0]) {
    await select(Number(rest[0]));
    const wanted = rest[1];
    if (wanted) {
      const tab = document.querySelector(`.tab[data-tab="${CSS.escape(wanted)}"]`);
      if (tab) tab.click();
    }
  }
}

const CHEATSHEET = `# Which hosts get decrypted (omit both to decrypt everything)
decrypt  "*.internal.example.com"
passthru "*.bank.com"

on request where host ~ "api\\." and method == "POST" {
    set header "X-Debug" = "1"
    remove header "Accept-Encoding"
    redact header "authorization"
    log method + " " + url
}

on request where path starts with "/v1/flags" {
    respond 200 "{\\"enabled\\": true}" as json   # never reaches the network
}

on response where status >= 500 {
    tag "server-error"
    count "5xx"
    save "C:/tmp/riff-errors"
}

on response where duration > 2000 { tag "slow" }

# values     host port scheme method path url body size status reason
#            header["X"] query["p"] cookie["c"] req.* resp.* tags client
# operators  == != < <= > >=  ~ !~  contains  in  starts with  ends with
#            and or not  + - * / %
# actions    set / add / remove header|query|cookie, set body|status|method|
#            path|url|host, respond, abort, stop, delay, log, tag, count,
#            save, redact, if/else, let
# units      500ms  2s  64kb  1mb`;

async function openScript() {
  openDrawer("drawer-script");
  $("#cheatsheet").textContent = CHEATSHEET;
  try {
    const data = await api("/api/script");
    $("#script-source").value = data.source;
    $("#script-path").textContent = data.path || "(not saved to a file)";
    setScriptStatus(`${data.rules} rule(s) active`, "ok");
  } catch (err) {
    setScriptStatus(err.message, "bad");
  }
}

function setScriptStatus(text, kind) {
  const node = $("#script-status");
  node.textContent = text;
  node.className = "script-status " + (kind || "");
}

async function checkScript() {
  try {
    const result = await api("/api/script/check", {
      method: "POST",
      body: JSON.stringify({ source: $("#script-source").value }),
    });
    if (result.ok) setScriptStatus(`Parses cleanly \u2014 ${result.rules} rule(s).`, "ok");
    else setScriptStatus(`Line ${result.line}, col ${result.col}: ${result.error}`, "bad");
  } catch (err) {
    setScriptStatus(err.message, "bad");
  }
}

async function saveScript() {
  try {
    const result = await api("/api/script", {
      method: "PUT",
      body: JSON.stringify({ source: $("#script-source").value }),
    });
    setScriptStatus(`Applied \u2014 ${result.rules} rule(s)${result.saved ? ", written to disk" : ""}.`, "ok");
    $("#stat-script").textContent = `${result.rules} rule(s)`;
    toast("Rules applied", "good");
  } catch (err) {
    const p = err.payload || {};
    setScriptStatus(p.render || p.error || err.message, "bad");
    toast("Rules rejected \u2014 nothing changed", "bad");
  }
}



function renderSetup(config) {
  const body = $("#setup-body");
  body.replaceChildren();
  const proxy = `${config.proxy.host}:${config.proxy.port}`;

  const html = `
    <h3>1. Point a client at the proxy</h3>
    <p>Any HTTP client that speaks proxy will do.</p>
    <pre>curl -x http://${escapeHtml(proxy)} --cacert "${escapeHtml(config.ca.path)}" https://example.com</pre>
    <p>Windows system proxy: <em>Settings &rsaquo; Network &amp; internet &rsaquo; Proxy &rsaquo; Manual</em>,
       address <code>${escapeHtml(config.proxy.host)}</code>, port <code>${config.proxy.port}</code>.</p>

    <h3>2. Trust the riff root CA (only if you want HTTPS bodies)</h3>
    <div class="warn-box">
      <strong>Read before you run this.</strong> Trusting this CA lets anything holding
      <code>riff-ca.key</code> impersonate every HTTPS site to your user account. Install it into your
      <em>user</em> store only, never the machine store, and remove it when you are done.
    </div>
    <p>Certificate: <code>${escapeHtml(config.ca.path)}</code></p>
    <p class="fp">SHA-256 ${escapeHtml(config.ca.fingerprint)}</p>
    <p>Expires ${escapeHtml(String(config.ca.expires).slice(0, 10))}.</p>
    <pre>certutil -addstore -user Root "${escapeHtml(config.ca.path)}"</pre>
    <p>To undo:</p>
    <pre>certutil -delstore -user Root "riff Root CA"</pre>
    <p><a href="/api/ca.crt" download>Download riff-ca.crt</a></p>

    <h3>3. Decide what gets decrypted</h3>
    <p>${config.tls_rules.length
        ? "Current policy:"
        : "No <code>decrypt</code> or <code>passthru</code> directives, so <strong>every</strong> CONNECT is decrypted. Add an allowlist to keep unrelated traffic opaque."}</p>
    ${config.tls_rules.length
        ? "<pre>" + config.tls_rules.map((r) => escapeHtml(`${r.mode} "${r.pattern}"`)).join("\n") + "</pre>"
        : ""}

    <h3>Current settings</h3>
    <pre>proxy            ${escapeHtml(proxy)}
ui               ${escapeHtml(config.ui.host + ":" + config.ui.port)}
script           ${escapeHtml(config.script.path || "(none)")} \u2014 ${config.script.rules} rule(s)
verify upstream  ${config.verify_upstream ? "on" : "OFF \u2014 upstream certificates are not checked"}
max body         ${humanSize(config.max_body)}
version          riff ${escapeHtml(config.version)}</pre>`;

  body.innerHTML = html;
}

/* ── wiring ───────────────────────────────────────────────────── */

function applyTheme(theme) {
  if (theme) document.documentElement.setAttribute("data-theme", theme);
  else document.documentElement.removeAttribute("data-theme");
}

function currentTheme() {
  return (
    document.documentElement.getAttribute("data-theme") ||
    (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
  );
}

function wire() {
  $("#btn-theme").addEventListener("click", () => {
    const next = currentTheme() === "dark" ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem("riff-theme", next); } catch (_) { /* private browsing */ }
  });

  rowsEl.addEventListener("click", (event) => {
    const row = event.target.closest(".row");
    if (!row) return;
    const id = Number(row.dataset.id);
    const onBox = event.target.matches(".col-check input");
    if (onBox || event.ctrlKey || event.metaKey || event.shiftKey) {
      if (!onBox) event.preventDefault();
      toggleCheck(id, event.shiftKey);
      return;
    }
    select(id);
  });
  $("#check-all").addEventListener("change", (event) => {
    if (event.target.checked) for (const id of visibleIds()) state.checked.add(id);
    else clearChecks();
    syncCheckUI();
  });
  $("#btn-export").addEventListener("click", (event) => { event.stopPropagation(); showExportMenu(); });
  for (const item of document.querySelectorAll("#export-menu .menu-item")) {
    item.addEventListener("click", () => exportFlows(item.dataset.format));
  }
  document.addEventListener("click", (event) => {
    if (!event.target.closest(".menu-wrap")) showExportMenu(false);
  });
  $("#btn-import").addEventListener("click", () => $("#import-file").click());
  $("#import-file").addEventListener("change", async (event) => {
    const files = Array.from(event.target.files || []);
    event.target.value = "";
    if (files.length) await importFiles(files);
  });

  let filterTimer = null;
  $("#filter").addEventListener("input", (event) => {
    state.filter = event.target.value;
    clearTimeout(filterTimer);
    filterTimer = setTimeout(() => {
      state.predicate = buildPredicate(state.filter);
      rerender();
    }, 90);
  });

  $("#btn-clear").addEventListener("click", async () => {
    try { await api("/api/clear", { method: "POST" }); } catch (err) { toast(err.message, "bad"); }
  });

  $("#btn-record").addEventListener("click", async () => {
    state.paused = !state.paused;
    if (!state.paused && state.missed) {
      try {
        const data = await api("/api/flows?since=" + state.lastId);
        for (const flow of data.flows) addFlow(flow, false);
        updateStats();
      } catch (_) { /* the stream will catch up on its own */ }
      state.missed = 0;
    }
    refreshRecordLabel();
  });

  $("#btn-script").addEventListener("click", openScript);
  $("#btn-script-check").addEventListener("click", checkScript);
  $("#btn-script-save").addEventListener("click", saveScript);
  $("#btn-compose").addEventListener("click", () => openCompose(null));
  $("#btn-findings").addEventListener("click", openFindings);
  $("#btn-findings-clear").addEventListener("click", clearFindings);
  $("#btn-findings-rescan").addEventListener("click", rescanFindings);
  $("#btn-scan-start").addEventListener("click", startScan);
  $("#btn-scan-cancel").addEventListener("click", cancelScan);
  $("#btn-setup").addEventListener("click", () => {
    openDrawer("drawer-setup");
    if (state.config) renderSetup(state.config);
  });
  $("#empty-setup").addEventListener("click", () => {
    openDrawer("drawer-setup");
    if (state.config) renderSetup(state.config);
  });

  for (const button of document.querySelectorAll(".drawer-close")) {
    button.addEventListener("click", closeDrawers);
  }

  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => {
      for (const other of document.querySelectorAll(".tab")) other.classList.remove("is-active");
      tab.classList.add("is-active");
      for (const panel of document.querySelectorAll(".panel")) {
        panel.classList.toggle("is-active", panel.dataset.panel === tab.dataset.tab);
      }
    });
  }

  $("#btn-replay").addEventListener("click", async () => {
    if (!state.selected) return;
    try {
      const result = await api("/api/replay", {
        method: "POST",
        body: JSON.stringify({ id: state.selected, apply_rules: true }),
      });
      toast(result.error ? "Replay failed: " + result.error : "Replayed as flow #" + result.id,
            result.error ? "bad" : "good");
    } catch (err) { toast(err.message, "bad"); }
  });

  $("#btn-edit-replay").addEventListener("click", async () => {
    if (!state.selected) return;
    try { openCompose(await api("/api/flow/" + state.selected)); }
    catch (err) { toast(err.message, "bad"); }
  });

  $("#btn-copy-curl").addEventListener("click", async () => {
    if (!state.selected) return;
    try {
      const detail = await api("/api/flow/" + state.selected);
      await navigator.clipboard.writeText(toCurl(detail));
      toast("curl command copied", "good");
    } catch (err) { toast("Copy failed: " + err.message, "bad"); }
  });

  /* draggable splitter */
  const gutter = $("#gutter");
  const split = $("#split");
  let dragging = false;
  gutter.addEventListener("pointerdown", (event) => {
    dragging = true;
    gutter.classList.add("is-dragging");
    gutter.setPointerCapture(event.pointerId);
  });
  gutter.addEventListener("pointermove", (event) => {
    if (!dragging) return;
    const rect = split.getBoundingClientRect();
    const fromBottom = rect.bottom - event.clientY;
    const pct = Math.min(80, Math.max(12, (fromBottom / rect.height) * 100));
    split.style.gridTemplateRows = `1fr 5px ${pct}%`;
  });
  const endDrag = () => { dragging = false; gutter.classList.remove("is-dragging"); };
  gutter.addEventListener("pointerup", endDrag);
  gutter.addEventListener("pointercancel", endDrag);

  /* keyboard */
  document.addEventListener("keydown", (event) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName);
    if (event.key === "Escape") { closeDrawers(); showExportMenu(false); if (typing) event.target.blur(); return; }
    if (typing) return;

    if (event.key === "/") { event.preventDefault(); $("#filter").focus(); return; }
    if (event.key === "c") { $("#btn-clear").click(); return; }
    if (event.key === "s") { event.preventDefault(); openScript(); return; }
    if (event.key === "n") { event.preventDefault(); openCompose(null); return; }
    if (event.key === " ") { event.preventDefault(); $("#btn-record").click(); return; }
    if (event.key === "x" && state.selected !== null) { toggleCheck(state.selected, event.shiftKey); return; }
    if (event.key === "e") { event.preventDefault(); showExportMenu(); return; }
    if (event.key === "i") { event.preventDefault(); $("#import-file").click(); return; }
    if (event.key === "f") { event.preventDefault(); openFindings(); return; }

    if (event.key === "j" || event.key === "k" || event.key === "ArrowDown" || event.key === "ArrowUp") {
      const visible = Array.from(rowsEl.querySelectorAll(".row"));
      if (!visible.length) return;
      const down = event.key === "j" || event.key === "ArrowDown";
      const index = visible.findIndex((r) => Number(r.dataset.id) === state.selected);
      const next = index < 0 ? (down ? 0 : visible.length - 1)
                             : Math.min(visible.length - 1, Math.max(0, index + (down ? 1 : -1)));
      event.preventDefault();
      visible[next].scrollIntoView({ block: "nearest" });
      select(Number(visible[next].dataset.id));
    }
  });
}

/* ── boot ─────────────────────────────────────────────────────── */

async function boot() {
  try {
    const saved = localStorage.getItem("riff-theme");
    if (saved) applyTheme(saved);
  } catch (_) { /* private browsing */ }
  wire();
  setConn("", "connecting");
  try {
    state.csrf = (await api("/api/csrf")).token;
  } catch (err) {
    setConn("is-down", "unauthorised");
    toast("Not authorised. Reopen the URL printed in the terminal.", "bad");
    return;
  }
  try {
    state.config = await api("/api/config");
    $("#stat-script").textContent = `${state.config.script.rules} rule(s)`;
    document.title = `riff \u2014 :${state.config.proxy.port}`;
  } catch (_) { /* non-fatal */ }
  try {
    const data = await api("/api/flows");
    for (const flow of data.flows) addFlow(flow, false);
    rerender();
  } catch (_) { /* non-fatal */ }
  try {
    const stats = await api("/api/stats");
    $("#stat-tunnels").textContent = `${stats.tunnels} tunnels`;
  } catch (_) { /* non-fatal */ }
  try {
    const data = await api("/api/findings");
    for (const row of data.findings) state.findings.set(row.key, row);
    refreshFindingsBadge();
  } catch (_) { /* non-fatal */ }
  connect();
  await applyHash();
  window.addEventListener("hashchange", applyHash);
}

boot();

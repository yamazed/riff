/* riff composer: saved requests, environments, variables, and a response pane.
   Loaded before app.js and shares its globals ($, api, toast, select, openDrawer,
   closeDrawers, el, humanSize, humanMs, bodyBlock, kvBlock, statusClass). */

"use strict";

const composer = {
  collections: [],          // summaries from /api/collections
  docs: new Map(),          // slug -> full collection document
  environments: [],
  env: "",                  // selected environment name, "" = none
  current: { collection: null, id: null, folder: "" },
  collapsed: new Set(),     // "slug" or "slug|folder/path" the user has folded
  filter: "",               // rail filter text, lower-cased
  loaded: false,
};

const REQUEST_TABS = ["params", "headers", "body", "auth", "capture"];

/* ── key/value grid ─────────────────────────────────────────── */

function kvGrid(container, spec) {
  // spec.columns: [{ key, placeholder, options? }]; spec.enable: checkbox column
  const rows = [];

  function blank() {
    const row = { enabled: true };
    for (const col of spec.columns) row[col.key] = col.options ? col.options[0] : "";
    return row;
  }

  function isEmpty(row) {
    return spec.columns.every((col) => col.options || !String(row[col.key] || "").trim());
  }

  function render() {
    if (!rows.length || !isEmpty(rows[rows.length - 1])) rows.push(blank());
    container.replaceChildren();
    rows.forEach((row, index) => {
      const line = el("div", "kv-row" + (spec.enable ? "" : " no-enable"));
      if (spec.enable) {
        const box = document.createElement("input");
        box.type = "checkbox";
        box.checked = row.enabled !== false;
        box.title = "send this one";
        box.addEventListener("change", () => { row.enabled = box.checked; changed(); });
        line.append(box);
      }
      for (const col of spec.columns) {
        let input;
        if (col.options) {
          input = document.createElement("select");
          for (const option of col.options) {
            const node = document.createElement("option");
            node.value = option; node.textContent = option;
            input.append(node);
          }
          input.value = row[col.key] || col.options[0];
          input.addEventListener("change", () => { row[col.key] = input.value; changed(); });
        } else {
          input = document.createElement("input");
          input.type = "text";
          input.spellcheck = false;
          input.placeholder = col.placeholder || col.key;
          input.value = row[col.key] || "";
          input.addEventListener("input", () => {
            row[col.key] = input.value;
            if (index === rows.length - 1 && !isEmpty(row)) render();
            changed();
          });
        }
        input.className = "kv-" + col.key;
        line.append(input);
      }
      const del = el("button", "kv-del", "×");
      del.type = "button";
      del.title = "remove";
      del.hidden = index === rows.length - 1 && isEmpty(row);
      del.addEventListener("click", () => { rows.splice(index, 1); render(); changed(); });
      line.append(del);
      container.append(line);
    });
  }

  function changed() { if (spec.onChange) spec.onChange(); }

  return {
    set(values) {
      rows.length = 0;
      for (const value of values || []) rows.push(Object.assign(blank(), value));
      render();
    },
    read() {
      return rows.filter((row) => !isEmpty(row)).map((row) => {
        const out = {};
        for (const col of spec.columns) out[col.key] = row[col.key] || "";
        if (spec.enable) out.enabled = row.enabled !== false;
        return out;
      });
    },
  };
}

let paramsGrid, headersGrid, formGrid, captureGrid, envSharedGrid, envPersonalGrid;

/* ── request form ───────────────────────────────────────────── */

function readRequest() {
  const mode = document.querySelector('input[name="body-mode"]:checked').value;
  const authType = $("#auth-type").value;
  const auth = { type: authType };
  if (authType === "bearer") auth.token = $("#auth-token").value;
  if (authType === "basic") { auth.username = $("#auth-username").value; auth.password = $("#auth-password").value; }
  if (authType === "apikey") { auth.key = $("#auth-key").value; auth.value = $("#auth-value").value; auth.in = $("#auth-in").value; }
  return {
    id: composer.current.id || undefined,
    name: $("#req-name").value.trim(),
    folder: composer.current.folder || "",
    method: $("#compose-method").value,
    url: $("#compose-url").value.trim(),
    params: paramsGrid.read(),
    headers: headersGrid.read(),
    body: { mode, text: $("#compose-body").value, form: formGrid.read() },
    auth,
    capture: captureGrid.read().filter((c) => c.var),
  };
}

function loadRequest(req, where) {
  composer.current = Object.assign({ collection: null, id: null, folder: req.folder || "" }, where || {});
  $("#req-name").value = req.name || "";
  $("#compose-method").value = (req.method || "GET").toUpperCase();
  $("#compose-url").value = req.url || "";
  paramsGrid.set(req.params || []);
  headersGrid.set(req.headers || []);
  const body = req.body || { mode: "none" };
  setBodyMode(body.mode || "none");
  $("#compose-body").value = body.text || "";
  formGrid.set(body.form || []);
  const auth = req.auth || { type: "inherit" };
  $("#auth-type").value = auth.type || "inherit";
  $("#auth-token").value = auth.token || "";
  $("#auth-username").value = auth.username || "";
  $("#auth-password").value = auth.password || "";
  $("#auth-key").value = auth.key || "";
  $("#auth-value").value = auth.value || "";
  $("#auth-in").value = auth.in || "header";
  paintAuth();
  captureGrid.set(req.capture || []);
  paintWhere();
  showRequestTab(REQUEST_TABS.includes(location.hash.split("/")[3]) ? location.hash.split("/")[3] : "params");
  $("#resp").hidden = true;
  markTree();
}

function paintWhere() {
  const { collection, id } = composer.current;
  const doc = collection ? composer.docs.get(collection) || composer.collections.find((c) => c.slug === collection) : null;
  const folder = composer.current.folder ? " / " + composer.current.folder.split("/").join(" / ") : "";
  $("#req-where").textContent = doc ? "in " + doc.name + folder : "unsaved";
  $("#req-where").title = doc && composer.current.folder ? "folder " + composer.current.folder : "";
  $("#btn-req-delete").hidden = !(collection && id);
  $("#btn-req-save").textContent = collection ? "Save" : "Save to…";
}

function setBodyMode(mode) {
  const radio = document.querySelector(`input[name="body-mode"][value="${mode}"]`);
  if (radio) radio.checked = true;
  $("#compose-body").hidden = !(mode === "json" || mode === "text");
  $("#kv-form").hidden = mode !== "form";
  $("#body-none").hidden = mode !== "none";
}

function paintAuth() {
  const type = $("#auth-type").value;
  for (const node of document.querySelectorAll("#auth-fields [data-auth]")) {
    node.hidden = node.dataset.auth !== type;
  }
}

function showRequestTab(name) {
  for (const tab of document.querySelectorAll("#req-tabs .tab")) tab.classList.toggle("is-active", tab.dataset.tab === name);
  for (const panel of document.querySelectorAll("#req-panels > [data-panel]")) panel.hidden = panel.dataset.panel !== name;
}

function paintTabCounts() {
  const req = readRequest();
  const counts = {
    params: req.params.filter((p) => p.enabled && p.name).length,
    headers: req.headers.filter((h) => h.enabled && h.name).length,
    body: req.body.mode === "none" ? 0 : 1,
    auth: req.auth.type === "none" || req.auth.type === "inherit" ? 0 : 1,
    capture: req.capture.length,
  };
  for (const tab of document.querySelectorAll("#req-tabs .tab")) {
    const n = counts[tab.dataset.tab];
    tab.querySelector(".count").textContent = n ? String(n) : "";
  }
}

/* ── environments ───────────────────────────────────────────── */

async function loadEnvironments() {
  try {
    composer.environments = (await api("/api/environments")).environments;
  } catch (err) { toast(err.message, "bad"); composer.environments = []; }
  const sel = $("#env-select");
  const keep = composer.env;
  sel.replaceChildren();
  sel.append(new Option("No environment", ""));
  for (const env of composer.environments) sel.append(new Option(env.name, env.name));
  sel.append(new Option("Manage environments…", "__manage__"));
  if (!composer.environments.some((e) => e.name === keep)) composer.env = "";
  sel.value = composer.env;
}

function pickEnvironment(value) {
  if (value === "__manage__") {
    $("#env-select").value = composer.env;
    openEnvEditor(composer.env || (composer.environments[0] && composer.environments[0].name) || "");
    return;
  }
  composer.env = value;
  try { localStorage.setItem("riff-env", value); } catch (_) { /* fine */ }
}

async function openEnvEditor(name) {
  $("#env-editor").hidden = false;
  const sel = $("#env-edit-select");
  sel.replaceChildren();
  for (const env of composer.environments) sel.append(new Option(env.name, env.name));
  sel.append(new Option("New environment…", "__new__"));
  if (name && composer.environments.some((e) => e.name === name)) {
    sel.value = name;
    await paintEnvEditor(name);
  } else {
    sel.value = "__new__";
    await paintEnvEditor("");
  }
}

async function paintEnvEditor(name) {
  const isNew = !name;
  $("#env-new-name").hidden = !isNew;
  $("#env-new-name").value = "";
  $("#btn-env-delete").hidden = isNew;
  if (isNew) {
    envSharedGrid.set([{ name: "baseUrl", value: "https://" }]);
    envPersonalGrid.set([]);
    return;
  }
  try {
    const doc = await api("/api/environments/" + encodeURIComponent(name));
    envSharedGrid.set(Object.entries(doc.values).map(([k, v]) => ({ name: k, value: v })));
    envPersonalGrid.set(Object.entries(doc.personal).map(([k, v]) => ({ name: k, value: v })));
  } catch (err) { toast(err.message, "bad"); }
}

async function saveEnvironment() {
  let name = $("#env-edit-select").value;
  if (name === "__new__") {
    name = $("#env-new-name").value.trim().toLowerCase();
    if (!name) { toast("Give the environment a name, like dvm or prd", "bad"); return; }
  }
  const values = Object.fromEntries(envSharedGrid.read().filter((r) => r.name).map((r) => [r.name, r.value]));
  const personal = Object.fromEntries(envPersonalGrid.read().filter((r) => r.name).map((r) => [r.name, r.value]));
  try {
    await api("/api/environments/" + encodeURIComponent(name), { method: "PUT", body: JSON.stringify({ values }) });
    await api("/api/personal?environment=" + encodeURIComponent(name), { method: "PUT", body: JSON.stringify({ values: personal }) });
    composer.env = name;
    try { localStorage.setItem("riff-env", name); } catch (_) { /* fine */ }
    await loadEnvironments();
    $("#env-editor").hidden = true;
    toast(`Environment ${name} saved`, "good");
  } catch (err) { toast(err.message, "bad"); }
}

async function deleteEnvironment() {
  const name = $("#env-edit-select").value;
  if (!name || name === "__new__") return;
  if (!confirm(`Delete environment ${name}? Personal values for it stay on this machine.`)) return;
  try {
    await api("/api/environments/" + encodeURIComponent(name), { method: "DELETE" });
    if (composer.env === name) composer.env = "";
    await loadEnvironments();
    $("#env-editor").hidden = true;
    toast(`Environment ${name} deleted`, "good");
  } catch (err) { toast(err.message, "bad"); }
}

/* ── collections rail ───────────────────────────────────────── */

async function loadCollections() {
  try {
    composer.collections = (await api("/api/collections")).collections;
  } catch (err) { toast(err.message, "bad"); composer.collections = []; }
  composer.docs.clear();
  paintTree();
}

async function collectionDoc(slug) {
  if (!composer.docs.has(slug)) composer.docs.set(slug, await api("/api/collections/" + encodeURIComponent(slug)));
  return composer.docs.get(slug);
}

/* Folder paths are "a/b/c". The collection summary carries the ordered folder
   list and each request's folder, so the tree paints without loading documents. */

function loadCollapsed() {
  try { composer.collapsed = new Set(JSON.parse(localStorage.getItem("riff-folded") || "[]")); } catch (_) { composer.collapsed = new Set(); }
}

function saveCollapsed() {
  try { localStorage.setItem("riff-folded", JSON.stringify([...composer.collapsed])); } catch (_) { /* fine */ }
}

function foldKey(slug, folder) { return folder ? slug + "|" + folder : slug; }

function toggleFold(slug, folder) {
  const key = foldKey(slug, folder);
  if (composer.collapsed.has(key)) composer.collapsed.delete(key); else composer.collapsed.add(key);
  saveCollapsed();
  paintTree();
}

function unfold(slug, folder) {
  let changed = false;
  for (const path of ["", ...folderParents(folder), folder]) {
    if (composer.collapsed.delete(foldKey(slug, path))) changed = true;
  }
  if (changed) saveCollapsed();
}

function folderParents(path) {
  const parts = path ? path.split("/") : [];
  return parts.slice(0, -1).map((_, i) => parts.slice(0, i + 1).join("/"));
}

function childFolders(col, parent) {
  const depth = parent ? parent.split("/").length + 1 : 1;
  return (col.folders || []).filter((f) => f.split("/").length === depth && (!parent || f.startsWith(parent + "/")));
}

function matches(req) {
  const q = composer.filter;
  return !q || req.name.toLowerCase().includes(q) || (req.url || "").toLowerCase().includes(q);
}

function requestsIn(col, folder, deep) {
  return col.requests.filter((r) => (deep ? (r.folder === folder || (folder ? r.folder.startsWith(folder + "/") : true)) : r.folder === folder) && matches(r));
}

function highlight(text) {
  const q = composer.filter;
  const span = el("span", "req-name");
  const at = q ? text.toLowerCase().indexOf(q) : -1;
  if (at < 0) { span.textContent = text; return span; }
  span.append(text.slice(0, at), el("mark", "tree-hit", text.slice(at, at + q.length)), text.slice(at + q.length));
  return span;
}

function paintTree() {
  const tree = $("#collection-tree");
  tree.replaceChildren();
  if (!composer.collections.length) {
    tree.append(el("p", "rail-empty", "No collections yet. Save a request, or import a v2.1 collection or HAR."));
    return;
  }
  let shown = 0;
  for (const col of composer.collections) {
    col.folders = col.folders || [];
    col.requests = col.requests || [];
    const visible = requestsIn(col, "", true);
    if (composer.filter && !visible.length) continue;
    shown += 1;
    const block = el("div", "col-block");
    block.dataset.slug = col.slug;
    const folded = !composer.filter && composer.collapsed.has(foldKey(col.slug, ""));
    block.classList.toggle("is-collapsed", folded);

    const head = el("div", "col-head");
    head.append(el("span", "chev", "▾"));
    const name = el("span", "col-name", col.name);
    name.title = col.slug + ".json";
    head.append(name);
    head.append(el("span", "col-count", String(visible.length)));
    const more = el("button", "btn btn-xs btn-ghost col-more", "⋯");
    more.type = "button";
    more.title = "New request, new folder, rename, export, delete";
    more.addEventListener("click", (event) => { event.stopPropagation(); collectionMenu(col, more); });
    head.append(more);
    head.addEventListener("click", () => toggleFold(col.slug, ""));
    dropTarget(head, col.slug, "", block);
    block.append(head);
    if (col.error) block.append(el("p", "rail-empty", col.error));

    const body = el("div", "col-body");
    for (const folder of childFolders(col, "")) body.append(folderNode(col, folder, 1));
    for (const req of requestsIn(col, "", false)) body.append(requestRow(col, req, 1));
    block.append(body);
    tree.append(block);
  }
  if (!shown) tree.append(el("p", "rail-empty", `Nothing matches “${composer.filter}”.`));
  markTree();
}

function folderNode(col, path, depth) {
  const deep = requestsIn(col, path, true);
  if (composer.filter && !deep.length) return document.createDocumentFragment();
  const node = el("div", "folder");
  node.dataset.slug = col.slug;
  node.dataset.folder = path;
  const folded = !composer.filter && composer.collapsed.has(foldKey(col.slug, path));
  node.classList.toggle("is-collapsed", folded);

  const head = el("div", "folder-head");
  head.style.paddingLeft = 8 + depth * 12 + "px";
  head.append(el("span", "chev", "▾"));
  head.append(folderIcon());
  const name = el("span", "folder-name", path.split("/").pop());
  name.title = path;
  head.append(name);
  head.append(el("span", "folder-count", String(deep.length)));
  const more = el("button", "btn btn-xs btn-ghost folder-more", "⋯");
  more.type = "button";
  more.title = "New request, subfolder, rename, delete";
  more.addEventListener("click", (event) => { event.stopPropagation(); folderMenu(col, path, more); });
  head.append(more);
  head.addEventListener("click", () => toggleFold(col.slug, path));
  dropTarget(head, col.slug, path, head);
  node.append(head);

  const body = el("div", "folder-body");
  for (const child of childFolders(col, path)) body.append(folderNode(col, child, depth + 1));
  const own = requestsIn(col, path, false);
  for (const req of own) body.append(requestRow(col, req, depth + 1));
  if (!own.length && !childFolders(col, path).length && !composer.filter) {
    const empty = el("p", "folder-empty", "empty — drag a request here");
    empty.style.paddingLeft = 16 + depth * 12 + "px";
    body.append(empty);
  }
  node.append(body);
  return node;
}

function folderIcon() {
  const icon = el("span", "folder-icon");
  icon.innerHTML = '<svg width="13" height="11" viewBox="0 0 13 11" aria-hidden="true"><path d="M1 2.2a1 1 0 0 1 1-1h3l1.2 1.3H11a1 1 0 0 1 1 1V9a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1Z" fill="currentColor" opacity=".85"/></svg>';
  return icon;
}

function requestRow(col, req, depth) {
  const row = el("button", "req-row");
  row.type = "button";
  row.dataset.slug = col.slug;
  row.dataset.id = req.id;
  row.style.paddingLeft = 16 + depth * 12 + "px";
  row.append(el("span", "req-method m-" + req.method, req.method));
  row.append(highlight(req.name));
  row.title = req.url + (req.folder ? "\nin " + req.folder : "");
  row.addEventListener("click", () => openSaved(col.slug, req.id));
  row.draggable = true;
  row.addEventListener("dragstart", (event) => {
    event.dataTransfer.setData("text/plain", col.slug + "|" + req.id);
    event.dataTransfer.effectAllowed = "move";
    row.classList.add("is-dragging");
  });
  row.addEventListener("dragend", () => row.classList.remove("is-dragging"));
  return row;
}

function dropTarget(node, slug, folder, highlightNode) {
  node.addEventListener("dragover", (event) => {
    if (!event.dataTransfer.types.includes("text/plain")) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
    highlightNode.classList.add("is-drop");
  });
  node.addEventListener("dragleave", () => highlightNode.classList.remove("is-drop"));
  node.addEventListener("drop", async (event) => {
    event.preventDefault();
    highlightNode.classList.remove("is-drop");
    const [fromSlug, id] = (event.dataTransfer.getData("text/plain") || "").split("|");
    if (fromSlug && id) await moveRequest(fromSlug, id, slug, folder);
  });
}

function markTree() {
  const { collection, id } = composer.current;
  for (const row of document.querySelectorAll(".req-row")) {
    row.classList.toggle("is-active", row.dataset.slug === collection && row.dataset.id === id);
  }
}

async function openSaved(slug, id) {
  try {
    const doc = await collectionDoc(slug);
    const req = doc.requests.find((r) => r.id === id);
    if (!req) { toast("That request is no longer in the collection", "bad"); return; }
    loadRequest(req, { collection: slug, id, folder: req.folder || "" });
    history.replaceState(null, "", `#compose/${slug}/${id}`);
  } catch (err) { toast(err.message, "bad"); }
}

function placeMenu(menu, anchor) {
  menu.hidden = false;
  const rect = anchor.getBoundingClientRect();
  const drawer = $("#drawer-compose").getBoundingClientRect();
  menu.style.top = rect.bottom - drawer.top + 4 + "px";
  menu.style.left = Math.max(8, rect.left - drawer.left - 120) + "px";
}

function collectionMenu(col, anchor) {
  $("#folder-menu").hidden = true;
  const menu = $("#collection-menu");
  menu.dataset.slug = col.slug;
  placeMenu(menu, anchor);
}

function folderMenu(col, path, anchor) {
  $("#collection-menu").hidden = true;
  const menu = $("#folder-menu");
  menu.dataset.slug = col.slug;
  menu.dataset.folder = path;
  placeMenu(menu, anchor);
}

function startRequestIn(slug, folder) {
  loadRequest({ method: "GET", url: "", auth: { type: "inherit" } }, { collection: slug, id: null, folder });
  unfold(slug, folder);
  paintTree();
  history.replaceState(null, "", "#compose");
  $("#compose-url").focus();
}

async function putCollection(slug, doc) {
  await api("/api/collections/" + encodeURIComponent(slug), { method: "PUT", body: JSON.stringify(doc) });
  composer.docs.delete(slug);
}

async function collectionAction(action) {
  const slug = $("#collection-menu").dataset.slug;
  $("#collection-menu").hidden = true;
  const col = composer.collections.find((c) => c.slug === slug);
  if (!col) return;
  try {
    if (action === "new-request") {
      startRequestIn(slug, "");
    } else if (action === "new-folder") {
      await newFolder(slug, "");
    } else if (action === "rename") {
      const name = prompt("Collection name", col.name);
      if (!name || name.trim() === col.name) return;
      const doc = await collectionDoc(slug);
      doc.name = name.trim();
      await putCollection(slug, doc);
      await loadCollections();
      paintWhere();
    } else if (action === "export-v2" || action === "export-riff") {
      const format = action === "export-v2" ? "v2" : "riff";
      const response = await fetch(`/api/collections/${encodeURIComponent(slug)}/export?format=${format}`, {
        headers: { "X-Riff-Token": state.csrf },
      });
      if (!response.ok) throw new Error((await response.json()).error || response.statusText);
      const blob = await response.blob();
      const header = response.headers.get("Content-Disposition") || "";
      const match = /filename="([^"]+)"/.exec(header);
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = match ? match[1] : slug + ".json";
      document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(link.href), 4000);
      toast(`Exported ${col.name} as ${format === "v2" ? "Collection v2.1" : "riff"}`, "good");
    } else if (action === "delete") {
      if (!confirm(`Delete the collection "${col.name}" and its ${col.requests.length} request(s)?`)) return;
      await api("/api/collections/" + encodeURIComponent(slug), { method: "DELETE" });
      if (composer.current.collection === slug) composer.current = { collection: null, id: null, folder: "" };
      await loadCollections();
      paintWhere();
      toast(`Deleted ${col.name}`, "good");
    }
  } catch (err) { toast(err.message, "bad"); }
}

async function folderAction(action) {
  const menu = $("#folder-menu");
  const { slug, folder } = menu.dataset;
  menu.hidden = true;
  if (!slug || !folder) return;
  try {
    if (action === "new-request") startRequestIn(slug, folder);
    else if (action === "new-folder") await newFolder(slug, folder);
    else if (action === "rename") await renameFolder(slug, folder);
    else if (action === "delete") await deleteFolder(slug, folder);
  } catch (err) { toast(err.message, "bad"); }
}

function cleanFolderName(name) {
  return (name || "").split("/").map((p) => p.trim()).filter(Boolean).join("/");
}

async function newFolder(slug, parent) {
  const name = cleanFolderName(prompt(parent ? `New folder inside ${parent}` : "New folder name", ""));
  if (!name) return;
  const path = parent ? parent + "/" + name : name;
  const doc = await collectionDoc(slug);
  doc.folders = doc.folders || [];
  if (doc.folders.some((f) => f.path === path)) { toast(`There is already a folder called ${path}`, "bad"); return; }
  doc.folders.push({ path, description: "" });
  await putCollection(slug, doc);
  unfold(slug, path);
  await loadCollections();
  toast(`Folder ${name} added`, "good");
}

async function renameFolder(slug, path) {
  const old = path.split("/").pop();
  const name = cleanFolderName(prompt("Folder name", old));
  if (!name || name === old) return;
  const parent = folderParents(path).pop() || "";
  const target = parent ? parent + "/" + name : name;
  const doc = await collectionDoc(slug);
  const move = (p) => (p === path ? target : p.startsWith(path + "/") ? target + p.slice(path.length) : p);
  if ((doc.folders || []).some((f) => f.path === target)) { toast(`There is already a folder called ${target}`, "bad"); return; }
  doc.folders = (doc.folders || []).map((f) => Object.assign({}, f, { path: move(f.path) }));
  for (const req of doc.requests) req.folder = move(req.folder || "");
  await putCollection(slug, doc);
  if (composer.current.collection === slug) composer.current.folder = move(composer.current.folder || "");
  for (const key of [...composer.collapsed]) {
    if (key.startsWith(slug + "|")) { composer.collapsed.delete(key); composer.collapsed.add(slug + "|" + move(key.slice(slug.length + 1))); }
  }
  saveCollapsed();
  await loadCollections();
  paintWhere();
  toast(`Renamed to ${name}`, "good");
}

async function deleteFolder(slug, path) {
  const doc = await collectionDoc(slug);
  const inside = (p) => p === path || p.startsWith(path + "/");
  const gone = doc.requests.filter((r) => inside(r.folder || ""));
  const what = gone.length ? ` and the ${gone.length} request${gone.length === 1 ? "" : "s"} inside it` : "";
  if (!confirm(`Delete the folder "${path}"${what}? Drag requests out first if you want to keep them.`)) return;
  doc.folders = (doc.folders || []).filter((f) => !inside(f.path));
  doc.requests = doc.requests.filter((r) => !inside(r.folder || ""));
  await putCollection(slug, doc);
  if (composer.current.collection === slug && inside(composer.current.folder || "")) {
    composer.current = { collection: null, id: null, folder: "" };
    history.replaceState(null, "", "#compose");
  }
  await loadCollections();
  paintWhere();
  toast(`Deleted folder ${path}`, "good");
}

async function moveRequest(fromSlug, id, toSlug, folder) {
  try {
    const from = await collectionDoc(fromSlug);
    const req = from.requests.find((r) => r.id === id);
    if (!req) return;
    if (fromSlug === toSlug) {
      if ((req.folder || "") === folder) return;
      req.folder = folder;
      await putCollection(fromSlug, from);
    } else {
      const to = await collectionDoc(toSlug);
      const copy = Object.assign({}, req, { folder });
      delete copy.id;
      to.requests.push(copy);
      await putCollection(toSlug, to);
      from.requests = from.requests.filter((r) => r.id !== id);
      await putCollection(fromSlug, from);
    }
    unfold(toSlug, folder);
    await loadCollections();
    if (composer.current.collection === fromSlug && composer.current.id === id) {
      if (fromSlug === toSlug) composer.current.folder = folder;
      else {
        const saved = await collectionDoc(toSlug);
        const mine = saved.requests[saved.requests.length - 1];
        composer.current = { collection: toSlug, id: mine.id, folder };
        history.replaceState(null, "", `#compose/${toSlug}/${mine.id}`);
        markTree();
      }
      paintWhere();
    }
    const target = composer.collections.find((c) => c.slug === toSlug);
    toast(`Moved ${req.name} to ${target ? target.name : toSlug}${folder ? " / " + folder : ""}`, "good");
  } catch (err) { toast(err.message, "bad"); }
}

async function newCollection() {
  const name = prompt("New collection name", "");
  if (!name || !name.trim()) return;
  try {
    const result = await api("/api/collections", { method: "POST", body: JSON.stringify({ name: name.trim() }) });
    await loadCollections();
    toast(`Created ${result.name}`, "good");
    return result.slug;
  } catch (err) { toast(err.message, "bad"); return null; }
}

async function importCollections(files) {
  for (const file of files) {
    try {
      const text = await file.text();
      // Strip the collection suffix other tools use, riff's own export suffix,
      // and a plain .json, so a re-import is named the same as the export.
      const name = file.name.replace(/\.([a-z]+_collection|riff-collection|collection-v2)?\.?json$|\.har$/i, "");
      const result = await api("/api/collections/import?name=" + encodeURIComponent(name), { method: "POST", body: text });
      toast(`Imported ${result.name}: ${result.requests} request${result.requests === 1 ? "" : "s"}`, "good");
    } catch (err) { toast(`${file.name}: ${err.message}`, "bad"); }
  }
  await loadCollections();
}

/* ── saving ─────────────────────────────────────────────────── */

async function saveRequest() {
  const req = readRequest();
  if (!req.url) { toast("Give the request a URL first", "bad"); return; }
  if (composer.current.collection) {
    await saveInto(composer.current.collection, req);
    return;
  }
  openSaveDialog(req);
}

function openSaveDialog(req) {
  const dialog = $("#save-dialog");
  const sel = $("#save-collection");
  sel.replaceChildren();
  for (const col of composer.collections) sel.append(new Option(col.name, col.slug));
  sel.append(new Option("New collection…", "__new__"));
  if (!composer.collections.length) sel.value = "__new__";
  else if (composer.current.collection) sel.value = composer.current.collection;
  $("#save-new-name").hidden = sel.value !== "__new__";
  paintSaveFolders(sel.value, composer.current.collection === sel.value ? composer.current.folder : "");
  $("#save-request-name").value = req.name || suggestName(req);
  dialog.hidden = false;
  $("#save-request-name").focus();
}

function paintSaveFolders(slug, current) {
  const sel = $("#save-folder");
  sel.replaceChildren();
  sel.append(new Option("top level", ""));
  const col = composer.collections.find((c) => c.slug === slug);
  for (const path of (col && col.folders) || []) sel.append(new Option(path.split("/").join(" / "), path));
  sel.append(new Option("New folder…", "__new__"));
  sel.value = current && (col && col.folders || []).includes(current) ? current : "";
  $("#save-new-folder").hidden = sel.value !== "__new__";
}

function suggestName(req) {
  try {
    const url = new URL(req.url.replace(/\{\{[^}]+\}\}/g, "x"));
    return `${req.method} ${url.pathname}`;
  } catch (_) { return `${req.method} ${req.url}`.slice(0, 60); }
}

async function confirmSave() {
  const req = readRequest();
  req.name = $("#save-request-name").value.trim() || suggestName(req);
  let slug = $("#save-collection").value;
  if (slug === "__new__") {
    const name = $("#save-new-name").value.trim();
    if (!name) { toast("Name the new collection", "bad"); return; }
    try {
      slug = (await api("/api/collections", { method: "POST", body: JSON.stringify({ name }) })).slug;
    } catch (err) { toast(err.message, "bad"); return; }
  }
  let folder = $("#save-folder").value;
  if (folder === "__new__") {
    folder = cleanFolderName($("#save-new-folder").value);
    if (!folder) { toast("Name the new folder", "bad"); return; }
  }
  req.folder = folder;
  composer.current.folder = folder;
  $("#save-dialog").hidden = true;
  $("#req-name").value = req.name;
  await saveInto(slug, req);
}

async function saveInto(slug, req) {
  try {
    composer.docs.delete(slug);
    const doc = await collectionDoc(slug);
    const index = doc.requests.findIndex((r) => r.id === req.id);
    if (index >= 0) doc.requests[index] = Object.assign({}, doc.requests[index], req);
    else { delete req.id; doc.requests.push(req); }
    await api("/api/collections/" + encodeURIComponent(slug), { method: "PUT", body: JSON.stringify(doc) });
    composer.docs.delete(slug);
    const saved = await collectionDoc(slug);
    const mine = index >= 0 ? saved.requests[index] : saved.requests[saved.requests.length - 1];
    composer.current = { collection: slug, id: mine.id, folder: mine.folder || "" };
    unfold(slug, mine.folder || "");
    await loadCollections();
    paintWhere();
    markTree();
    history.replaceState(null, "", `#compose/${slug}/${mine.id}`);
    toast(`Saved to ${saved.name}`, "good");
  } catch (err) { toast(err.message, "bad"); }
}

async function deleteRequest() {
  const { collection, id } = composer.current;
  if (!collection || !id) return;
  try {
    const doc = await collectionDoc(collection);
    const req = doc.requests.find((r) => r.id === id);
    if (!confirm(`Delete "${req ? req.name : "this request"}" from ${doc.name}?`)) return;
    doc.requests = doc.requests.filter((r) => r.id !== id);
    await api("/api/collections/" + encodeURIComponent(collection), { method: "PUT", body: JSON.stringify(doc) });
    composer.docs.delete(collection);
    composer.current = { collection: null, id: null, folder: "" };
    await loadCollections();
    paintWhere();
    history.replaceState(null, "", "#compose");
    toast("Request deleted", "good");
  } catch (err) { toast(err.message, "bad"); }
}

/* ── sending ────────────────────────────────────────────────── */

async function sendComposed() {
  const req = readRequest();
  if (!req.url) { toast("The request needs a URL", "bad"); return; }
  if (req.body.mode === "json" && req.body.text.trim()) {
    try { JSON.parse(req.body.text.replace(/\{\{[^}]+\}\}/g, "0")); }
    catch (err) { setSendStatus("Body is not valid JSON: " + err.message, "bad"); return; }
  }
  setSendStatus("Sending…", "");
  $("#btn-compose-send").disabled = true;
  try {
    const result = await api("/api/send", {
      method: "POST",
      body: JSON.stringify({
        request: req,
        environment: composer.env,
        collection: composer.current.collection || "",
        apply_rules: $("#compose-rules").checked,
      }),
    });
    renderResponse(result);
  } catch (err) {
    const missing = err.payload && err.payload.missing;
    setSendStatus(err.message + (missing && missing.length ? "" : ""), "bad");
    if (missing && missing.length) hintVariables(missing);
  } finally {
    $("#btn-compose-send").disabled = false;
  }
}

function setSendStatus(text, kind) {
  const node = $("#compose-status");
  node.textContent = text;
  node.className = "script-status" + (kind ? " " + kind : "");
}

function hintVariables(missing) {
  const where = composer.env ? `environment ${composer.env}` : "an environment";
  toast(`No value for ${missing.map((m) => "{{" + m + "}}").join(", ")} — add it to ${where} or your personal values`, "bad");
}

function renderResponse(result) {
  const resp = $("#resp");
  resp.hidden = false;
  const detail = result.detail || {};
  const response = detail.response;
  const pill = $("#resp-status");
  pill.className = "resp-status " + statusClass({ status: result.status, error: result.error });
  pill.textContent = result.error ? "ERR" : String(result.status || "–");
  $("#resp-reason").textContent = result.error ? result.error : (response && response.reason) || "";
  $("#resp-time").textContent = humanMs(result.duration_ms || 0);
  $("#resp-size").textContent = response ? humanSize((response.body && response.body.size) || 0) : "";
  $("#resp-open").textContent = "flow #" + result.id;
  $("#resp-open").dataset.id = String(result.id);

  const bodyPane = $("#resp-body");
  const headersPane = $("#resp-headers");
  bodyPane.replaceChildren();
  headersPane.replaceChildren();
  if (response) {
    bodyPane.append(bodyBlock(response));
    headersPane.append(kvBlock("Headers", response.headers));
  } else {
    bodyPane.append(el("p", "body-note", result.error || "no response"));
  }
  showResponseTab("body");

  const notes = [];
  if (result.missing && result.missing.length) notes.push("unresolved: " + result.missing.map((m) => "{{" + m + "}}").join(", "));
  const captured = Object.entries(result.captured || {}).filter(([k]) => k !== "_error");
  if (captured.length) {
    notes.push("captured " + captured.map(([k]) => k).join(", ") + (composer.env ? ` into ${composer.env}` : " into personal values"));
  }
  if (result.captured && result.captured._error) notes.push(result.captured._error);
  setSendStatus(notes.join(" · "), result.error ? "bad" : notes.length ? "ok" : "");
  if (result.missing && result.missing.length) hintVariables(result.missing);
}

function showResponseTab(name) {
  for (const tab of document.querySelectorAll("#resp-tabs .tab")) tab.classList.toggle("is-active", tab.dataset.tab === name);
  $("#resp-body").hidden = name !== "body";
  $("#resp-headers").hidden = name !== "headers";
}

/* ── opening ────────────────────────────────────────────────── */

async function ensureComposerLoaded() {
  if (composer.loaded) return;
  composer.loaded = true;
  try { composer.env = localStorage.getItem("riff-env") || ""; } catch (_) { /* fine */ }
  loadCollapsed();
  await Promise.all([loadCollections(), loadEnvironments()]);
}

async function openCompose(fromDetail) {
  openDrawer("drawer-compose");
  await ensureComposerLoaded();
  setSendStatus("", "");
  if (fromDetail) {
    const req = fromDetail.request;
    const headers = req.headers
      .filter(([k]) => !["content-length", "host"].includes(k.toLowerCase()))
      .map(([k, v]) => ({ name: k, value: v, enabled: true }));
    const text = (req.body && req.body.text) || "";
    const type = (req.headers.find(([k]) => k.toLowerCase() === "content-type") || [])[1] || "";
    const mode = !text ? "none" : /json/i.test(type) ? "json" : "text";
    loadRequest(
      { name: "", method: req.method, url: req.url, headers, body: { mode, text }, auth: { type: "none" } },
      { collection: null, id: null, folder: "" }
    );
    $("#req-name").value = suggestName({ method: req.method, url: req.url });
    history.replaceState(null, "", "#compose");
  } else if (!composer.current.collection && !$("#compose-url").value) {
    loadRequest({ method: "GET", url: "", auth: { type: "inherit" } }, { collection: null, id: null, folder: "" });
  }
  $("#compose-url").focus();
}

async function openComposeAt(slug, id) {
  openDrawer("drawer-compose");
  await ensureComposerLoaded();
  if (slug && id) await openSaved(slug, id);
}

/* ── wiring ─────────────────────────────────────────────────── */

function wireComposer() {
  const onChange = () => paintTabCounts();
  paramsGrid = kvGrid($("#kv-params"), { enable: true, columns: [{ key: "name", placeholder: "parameter" }, { key: "value", placeholder: "value" }], onChange });
  headersGrid = kvGrid($("#kv-headers"), { enable: true, columns: [{ key: "name", placeholder: "Header-Name" }, { key: "value", placeholder: "value" }], onChange });
  formGrid = kvGrid($("#kv-form"), { enable: true, columns: [{ key: "name", placeholder: "field" }, { key: "value", placeholder: "value" }], onChange });
  captureGrid = kvGrid($("#kv-capture"), {
    columns: [
      { key: "var", placeholder: "variable" },
      { key: "from", options: ["json", "header", "status"] },
      { key: "path", placeholder: "json path, e.g. data.token" },
    ],
    onChange,
  });
  envSharedGrid = kvGrid($("#env-shared"), { columns: [{ key: "name", placeholder: "name, e.g. baseUrl" }, { key: "value", placeholder: "value" }] });
  envPersonalGrid = kvGrid($("#env-personal"), { columns: [{ key: "name", placeholder: "name, e.g. token" }, { key: "value", placeholder: "value, kept on this machine" }] });

  for (const tab of document.querySelectorAll("#req-tabs .tab")) tab.addEventListener("click", () => showRequestTab(tab.dataset.tab));
  for (const tab of document.querySelectorAll("#resp-tabs .tab")) tab.addEventListener("click", () => showResponseTab(tab.dataset.tab));
  for (const radio of document.querySelectorAll('input[name="body-mode"]')) radio.addEventListener("change", () => { setBodyMode(radio.value); paintTabCounts(); });
  $("#auth-type").addEventListener("change", () => { paintAuth(); paintTabCounts(); });
  $("#compose-body").addEventListener("input", paintTabCounts);

  $("#btn-compose-send").addEventListener("click", sendComposed);
  $("#drawer-compose").addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") { event.preventDefault(); sendComposed(); }
    if (event.key === "Escape") {
      // Escape closes the innermost thing first: a menu, the save dialog, a filter. Only then the drawer (app.js).
      const popups = ["#collection-menu", "#folder-menu", "#save-dialog"].filter((id) => !$(id).hidden);
      const filtering = event.target === $("#rail-filter") && event.target.value;
      if (popups.length || filtering) {
        event.stopPropagation();
        for (const id of popups) $(id).hidden = true;
        if (filtering) { event.target.value = ""; composer.filter = ""; paintTree(); }
      }
    }
  });
  $("#btn-req-save").addEventListener("click", saveRequest);
  $("#btn-req-saveas").addEventListener("click", () => openSaveDialog(readRequest()));
  $("#btn-req-delete").addEventListener("click", deleteRequest);
  $("#btn-req-new").addEventListener("click", () => {
    loadRequest({ method: "GET", url: "", auth: { type: "inherit" } }, { collection: null, id: null, folder: "" });
    history.replaceState(null, "", "#compose");
    $("#compose-url").focus();
  });
  $("#save-collection").addEventListener("change", (event) => {
    $("#save-new-name").hidden = event.target.value !== "__new__";
    paintSaveFolders(event.target.value, "");
  });
  $("#save-folder").addEventListener("change", (event) => { $("#save-new-folder").hidden = event.target.value !== "__new__"; });
  $("#save-new-folder").addEventListener("keydown", (event) => { if (event.key === "Enter") confirmSave(); });
  $("#btn-save-confirm").addEventListener("click", confirmSave);
  $("#btn-save-cancel").addEventListener("click", () => { $("#save-dialog").hidden = true; });
  $("#save-request-name").addEventListener("keydown", (event) => { if (event.key === "Enter") confirmSave(); });

  $("#btn-collection-new").addEventListener("click", newCollection);
  $("#btn-collection-import").addEventListener("click", () => $("#collection-file").click());
  $("#collection-file").addEventListener("change", async (event) => {
    const files = Array.from(event.target.files || []);
    event.target.value = "";
    if (files.length) await importCollections(files);
  });
  for (const item of document.querySelectorAll("#collection-menu .menu-item")) {
    item.addEventListener("click", () => collectionAction(item.dataset.action));
  }
  for (const item of document.querySelectorAll("#folder-menu .menu-item")) {
    item.addEventListener("click", () => folderAction(item.dataset.action));
  }
  document.addEventListener("click", (event) => {
    if (!event.target.closest("#collection-menu") && !event.target.closest(".col-more")) $("#collection-menu").hidden = true;
    if (!event.target.closest("#folder-menu") && !event.target.closest(".folder-more")) $("#folder-menu").hidden = true;
  });
  $("#rail-filter").addEventListener("input", (event) => {
    composer.filter = event.target.value.trim().toLowerCase();
    paintTree();
  });


  $("#env-select").addEventListener("change", (event) => pickEnvironment(event.target.value));
  $("#btn-env-edit").addEventListener("click", () => openEnvEditor(composer.env));
  $("#env-edit-select").addEventListener("change", (event) => paintEnvEditor(event.target.value === "__new__" ? "" : event.target.value));
  $("#btn-env-save").addEventListener("click", saveEnvironment);
  $("#btn-env-delete").addEventListener("click", deleteEnvironment);
  $("#btn-env-close").addEventListener("click", () => { $("#env-editor").hidden = true; });

  $("#resp-open").addEventListener("click", () => {
    const id = Number($("#resp-open").dataset.id);
    if (id) { closeDrawers(); select(id); }
  });
}

// app.js defines the shared helpers after this file runs; wire once both are loaded.
document.addEventListener("DOMContentLoaded", wireComposer);

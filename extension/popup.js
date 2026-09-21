"use strict";

const DEFAULTS = {
  enabled: false,
  host: "127.0.0.1",
  port: 8888,
  uiPort: 8899,
  captureLocalhost: true,
  bypass: "",
};

const FIELDS = ["enabled", "host", "port", "uiPort", "captureLocalhost", "bypass"];
const $ = (id) => document.getElementById(id);

function read() {
  return {
    enabled: $("enabled").checked,
    host: $("host").value.trim() || DEFAULTS.host,
    port: Number($("port").value) || DEFAULTS.port,
    uiPort: Number($("uiPort").value) || DEFAULTS.uiPort,
    captureLocalhost: $("captureLocalhost").checked,
    bypass: $("bypass").value.trim(),
  };
}

function paint(config) {
  for (const key of FIELDS) {
    const node = $(key);
    if (node.type === "checkbox") node.checked = Boolean(config[key]);
    else node.value = config[key];
  }
  const state = $("state");
  state.textContent = config.enabled
    ? `Chrome is going through ${config.host}:${config.port}.`
    : "Chrome is using its normal connection.";
  state.className = "state" + (config.enabled ? " on" : "");
}

async function persist() {
  const config = read();
  await chrome.storage.local.set(config);
  const result = await chrome.runtime.sendMessage({ type: "apply" });
  paint(config);
  if (result && result.error) {
    show(`Could not change the proxy: ${result.error}`);
  } else if (config.enabled) {
    await probe(config);
  } else {
    $("warn").hidden = true;
  }
}

function show(message) {
  $("warn").textContent = message;
  $("warn").hidden = false;
}

async function probe(config) {
  // A 401 from the UI root is a healthy riff: it is up and asking for a token.
  try {
    const response = await fetch(`http://${config.host}:${config.uiPort}/`, { cache: "no-store" });
    if (response.status === 401 || response.ok) {
      $("warn").hidden = true;
      return;
    }
    show(`riff answered with ${response.status} on the UI port.`);
  } catch (_) {
    show(`Nothing is listening on ${config.host}:${config.uiPort}. Start riff, or Chrome will fail to load pages.`);
  }
}

// The UI's access token lives in a cookie scoped to one hostname, so
// 127.0.0.1 and localhost are signed in separately. Open whichever one already
// has the cookie; if neither does, the page itself explains `riff ui --open`.
async function uiUrl(config) {
  const candidates = [`http://${config.host}:${config.uiPort}`, `http://localhost:${config.uiPort}`];
  for (const origin of candidates) {
    try {
      const response = await fetch(`${origin}/api/stats`, { credentials: "include", cache: "no-store" });
      if (response.ok) return `${origin}/`;
    } catch (_) {
      // not listening on this name; try the next
    }
  }
  return `${candidates[0]}/`;
}

async function boot() {
  const stored = Object.assign({}, DEFAULTS, await chrome.storage.local.get(DEFAULTS));
  paint(stored);

  for (const key of FIELDS) {
    $(key).addEventListener("change", persist);
  }

  $("open-ui").addEventListener("click", async () => {
    const config = read();
    chrome.tabs.create({ url: await uiUrl(config) });
  });

  const status = await chrome.runtime.sendMessage({ type: "status" });
  if (status && status.levelOfControl && status.levelOfControl.startsWith("controlled_by_other")) {
    show("Another extension or a policy controls Chrome's proxy, so this switch will not take effect.");
  }
  $("hint").textContent = stored.enabled ? "" : "toggle to route traffic";
}

boot();

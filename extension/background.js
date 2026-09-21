/* Applies and clears Chrome's proxy setting.
 *
 * This extension deliberately does NOT use chrome.debugger. That API can read
 * response bodies, but it pins a "being debugged" banner to the window and only
 * ever sees this browser. riff already sees bodies as a proxy, from every
 * client on the machine, so all the extension has to do is point Chrome at it.
 */

const DEFAULTS = {
  enabled: false,
  host: "127.0.0.1",
  port: 8888,
  uiPort: 8899,
  captureLocalhost: true,
  bypass: "",
};

async function settings() {
  return Object.assign({}, DEFAULTS, await chrome.storage.local.get(DEFAULTS));
}

function buildConfig(config) {
  const bypassList = [];

  // Never route the riff UI through riff itself.
  bypassList.push(`${config.host}:${config.uiPort}`, `localhost:${config.uiPort}`);

  if (config.captureLocalhost) {
    // Chrome bypasses loopback by default; this token switches that off so
    // local dev servers show up in the capture too.
    bypassList.push("<-loopback>");
  } else {
    bypassList.push("<local>");
  }

  for (const entry of String(config.bypass || "").split(",")) {
    const trimmed = entry.trim();
    if (trimmed) bypassList.push(trimmed);
  }

  return {
    mode: "fixed_servers",
    rules: {
      singleProxy: { scheme: "http", host: config.host, port: Number(config.port) },
      bypassList,
    },
  };
}

async function apply() {
  const config = await settings();
  if (!config.enabled) {
    await chrome.proxy.settings.clear({ scope: "regular" });
    await chrome.action.setBadgeText({ text: "" });
    return { active: false };
  }
  await chrome.proxy.settings.set({ value: buildConfig(config), scope: "regular" });
  await chrome.action.setBadgeText({ text: "on" });
  await chrome.action.setBadgeBackgroundColor({ color: "#8b6cff" });
  return { active: true };
}

chrome.runtime.onInstalled.addListener(apply);
chrome.runtime.onStartup.addListener(apply);

chrome.runtime.onMessage.addListener((message, _sender, respond) => {
  if (message.type === "apply") {
    apply().then(respond, (error) => respond({ error: String(error) }));
    return true; // keep the channel open for the async reply
  }
  if (message.type === "status") {
    chrome.proxy.settings.get({}, (details) => {
      respond({ levelOfControl: details.levelOfControl, value: details.value });
    });
    return true;
  }
  return false;
});

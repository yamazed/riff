# riff proxy switch (Chrome extension)

A one-toggle switch that points Chrome at a running riff proxy, so you do not
have to change Windows' system proxy every time you want to capture something.

## What it does, and what it deliberately does not

It sets `chrome.proxy.settings`. That is all. Bodies, rules and the UI all come
from riff itself, which sees traffic from **every** client on the machine, not
just this browser.

It does **not** use `chrome.debugger`. That API can read and rewrite response
bodies from inside the browser, which sounds attractive until you notice:

| | `chrome.debugger` extension | riff as a proxy |
|---|---|---|
| Reads request/response bodies | yes | yes |
| Rewrites bodies | yes | yes |
| Persistent *"being debugged"* banner | **yes** | no |
| Sees non-browser clients (curl, .NET, API clients, mobile) | no | yes |
| Survives browser restart | no | yes |
| Scriptable rules | you write JS | `.riff` rules |

`declarativeNetRequest` — the other MV3 option — cannot read bodies at all, so
it is not a candidate.

## Install

1. Start riff: `riff run -s rules.riff`
2. Open `chrome://extensions`, turn on **Developer mode** (top right).

   ![Developer mode on](../docs/screenshots/ext-developer-mode.png)

3. **Load unpacked** → pick this `extension/` folder. The card appears.

   ![The loaded card](../docs/screenshots/ext-loaded.png)

4. Click the riff icon, set the ports if you changed them, flip the switch.

   ![The popup](../docs/screenshots/ext-popup.png)

A one-minute recording of the same steps is in
[`../docs/riff-extension-install.webm`](../docs/riff-extension-install.webm).
Edge takes the same folder through `edge://extensions`.

Why this and not the Windows proxy: endpoint agents such as Zscaler Client
Connector watch the Windows proxy setting and revert any change within a
second while they are enabled. Chrome's own proxy setting, which is what this
extension changes, is not under their control.

Chrome does not allow unpacked extensions to persist without developer mode; to
avoid the warning bar, pack it (`chrome://extensions` → *Pack extension*) and
install the resulting `.crx` through your normal enterprise deployment.

## Notes

- **Capture localhost traffic too** adds Chrome's `<-loopback>` bypass token,
  which stops Chrome from skipping the proxy for local dev servers. Turn it off
  if you only care about external APIs.
- The riff UI port is always bypassed, so the UI never routes through riff.
- **Open riff UI** opens whichever of `localhost` and `127.0.0.1` already holds
  the UI's token cookie (they are separate). If neither does, the page tells
  you to run `riff ui --open` once.
- If a corporate policy or another extension owns the proxy setting, the popup
  says so and the toggle will not take effect — policy always wins.
- Turning the switch off restores whatever Chrome was doing before.
- Without the riff root CA trusted, HTTPS pages will fail to load while the
  switch is on. Either trust it (`riff ca install`) or add a `passthru` rule.

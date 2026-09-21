"""Capture the Chrome-extension screenshots and record the install video.

    riff run -s rules.riff                # riff must be listening on 8888 / 8899
    python packaging/shoot-extension.py <ui-token>

Writes to docs/screenshots:
    ext-developer-mode.png   chrome://extensions with Developer mode switched on
    ext-loaded.png           the "riff proxy switch" card once it is loaded
    ext-popup.png            the popup with the switch on
    ext-traffic.png          riff's UI showing the browser's traffic

and docs/riff-extension-install.webm, a recording of the same sequence.

Honesty notes, because a screenshot should show what it claims to:
- Google's branded Chrome no longer accepts --load-extension, so the *loaded
  card* is captured from Edge, whose extensions page shares Chromium's design.
  Everything else is Chrome.
- The popup is rendered from extension/popup.html itself. Chrome will not run
  an unpacked extension for us here, so `chrome.storage` and `chrome.runtime`
  are stubbed with the same defaults the real popup uses. The markup, CSS and
  JS are the real ones; only the storage behind them is a stand-in.
- The traffic shot is real: the recording browser is pointed at riff the same
  way the extension does it (a fixed proxy server), then loads the demo app.
"""

from __future__ import annotations

import base64
import pathlib
import shutil
import sys
import tempfile

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from demo.app import serve as serve_demo  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXT = ROOT / "extension"
OUT = ROOT / "docs" / "screenshots"
VIDEO = ROOT / "docs" / "riff-extension-install.webm"
VIEWPORT = {"width": 1440, "height": 880}
POPUP = {"width": 486, "height": 297}  # 18:11, the walkthrough player's frame
# The demo origin answers on 127.0.0.1 while riff's own UI is on `localhost`,
# so `host:127.0.0.1` in the traffic shot shows the browsed site and nothing else.
SITE = "https://127.0.0.1:8443/"
APP_PORT = 8443
PROXY = "127.0.0.1:8888"
UI = "http://localhost:8899"

# Stands in for the extension APIs when popup.html is opened as a plain page.
CHROME_SHIM = """
(() => {
  const store = { enabled: true, host: "127.0.0.1", port: 8888, uiPort: 8899, captureLocalhost: true, bypass: "" };
  window.chrome = window.chrome || {};
  window.chrome.storage = { local: {
    get: async (defaults) => Object.assign({}, defaults, store),
    set: async (values) => Object.assign(store, values),
  }};
  window.chrome.runtime = { sendMessage: async (msg) =>
    msg.type === "status" ? { levelOfControl: "controlled_by_this_extension" } : { active: store.enabled } };
  window.chrome.tabs = { create: () => {} };
})();
"""


def caption(title: str, body: str = "", step: str = "") -> str:
    """A title card between recorded steps, as a data: URL."""
    html = f"""<!doctype html><meta charset="utf-8">
<style>
  html,body{{margin:0;height:100%;background:#0f1117;color:#e8e6f0;font:400 22px/1.5 Segoe UI,system-ui,sans-serif}}
  main{{height:100%;display:flex;flex-direction:column;justify-content:center;padding:0 12%;box-sizing:border-box}}
  .step{{color:#8b6cff;font-weight:600;letter-spacing:.08em;text-transform:uppercase;font-size:15px;margin-bottom:14px}}
  h1{{font-size:44px;line-height:1.15;margin:0 0 18px;font-weight:600}}
  p{{margin:0;max-width:820px;color:#b8b5c7}}
  code{{background:#1c1f2b;padding:2px 8px;border-radius:6px;color:#fff;font-size:20px}}
</style>
<main>{f'<div class="step">{step}</div>' if step else ''}<h1>{title}</h1>{f'<p>{body}</p>' if body else ''}</main>"""
    return "data:text/html;base64," + base64.b64encode(html.encode("utf-8")).decode("ascii")


POPUP_STAGE = """<!doctype html><meta charset="utf-8">
<style>
  html,body{margin:0;height:100%;background:#0f1117;font:14px Segoe UI,system-ui,sans-serif;color:#b8b5c7}
  .bar{height:64px;background:#202124;display:flex;align-items:center;gap:14px;padding:0 18px;border-bottom:1px solid #3c4043}
  .omni{flex:1;height:36px;border-radius:18px;background:#35363a;display:flex;align-items:center;padding:0 16px;color:#9aa0a6;font-size:15px}
  .icons{display:flex;gap:12px;align-items:center}
  .ico{width:30px;height:30px;border-radius:6px;background:#3c4043}
  .riff{position:relative;width:30px;height:30px;border-radius:6px;background:linear-gradient(135deg,#8b6cff,#39c5cf);box-shadow:0 0 0 3px #202124,0 0 0 5px #8b6cff}
  .riff b{position:absolute;right:-6px;bottom:-6px;background:#8b6cff;color:#fff;font:700 9px/1 Segoe UI,sans-serif;padding:2px 3px;border-radius:3px;letter-spacing:.02em}
  .pop{position:absolute;top:70px;right:26px;width:312px;height:296px;border-radius:8px;overflow:hidden;
       box-shadow:0 24px 60px -12px rgba(0,0,0,.7),0 0 0 1px #3c4043;background:#fff;transform-origin:top right;transform:scale(1.65)}
  .pop iframe{border:0;width:312px;height:296px;display:block}
  .note{position:absolute;left:8%;top:44%;max-width:520px}
  .note h1{font-size:40px;line-height:1.15;margin:0 0 14px;color:#e8e6f0;font-weight:600}
  .note p{margin:0;font-size:22px;line-height:1.5}
</style>
<div class="bar"><div class="omni">chrome://extensions</div>
  <div class="icons"><div class="ico"></div><div class="ico"></div><div class="riff"><b>on</b></div></div></div>
<div class="pop"><iframe src="POPUP_SRC"></iframe></div>
<div class="note"><h1>Click the riff icon, flip the switch</h1><p>Leave the ports alone unless you changed them when starting riff. Tick <i>Capture localhost traffic too</i> for local dev servers.</p></div>
"""


def popup_stage_url() -> str:
    """Write the stage page next to the extension so file:// framing is allowed."""
    path = pathlib.Path(tempfile.gettempdir()) / "riff-popup-stage.html"
    path.write_text(POPUP_STAGE.replace("POPUP_SRC", (EXT / "popup.html").as_uri()), encoding="utf-8")
    return path.as_uri()


def shot(page, name: str, pause: int = 400) -> None:
    page.wait_for_timeout(pause)
    page.screenshot(path=str(OUT / f"{name}.png"))
    print(f"  {name}.png")


def developer_mode(page) -> None:
    """chrome://extensions, then flip the Developer mode toggle (it lives in shadow DOM)."""
    page.goto("chrome://extensions/")
    page.wait_for_timeout(900)
    toggle = page.locator("extensions-manager extensions-toolbar #devMode")
    toggle.wait_for(timeout=8000)
    if toggle.get_attribute("aria-pressed") != "true":
        toggle.click()
    page.wait_for_timeout(700)


def popup(page) -> None:
    page.add_init_script(CHROME_SHIM)
    page.goto((EXT / "popup.html").as_uri())
    # The real checkbox is visually hidden behind the switch, so poll its state.
    page.wait_for_function("(el => el && el.checked)(document.getElementById('enabled'))", timeout=5000)
    page.wait_for_timeout(300)


def main(token: str) -> int:
    demo = serve_demo(port=APP_PORT, tls=True)
    OUT.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        # ---- stills -------------------------------------------------------
        print("stills")
        # chrome:// pages only open in a real (persistent) profile, and only in a
        # visible window, so every Chrome here is a throwaway on-disk profile.
        def chrome_profile(**kwargs):
            profile = tempfile.mkdtemp(prefix="riff-shoot-chrome-")
            ctx = p.chromium.launch_persistent_context(profile, channel="chrome", headless=False, **kwargs)
            return ctx, profile

        ctx, profile = chrome_profile(viewport=VIEWPORT, device_scale_factor=2, color_scheme="dark",
                                      args=["--hide-scrollbars"])
        page = ctx.new_page()
        developer_mode(page)
        shot(page, "ext-developer-mode")
        ctx.close()
        shutil.rmtree(profile, ignore_errors=True)

        ctx, profile = chrome_profile(viewport=POPUP, device_scale_factor=2, color_scheme="light",
                                      args=["--hide-scrollbars"])
        page = ctx.new_page()
        popup(page)
        shot(page, "ext-popup")
        ctx.close()
        shutil.rmtree(profile, ignore_errors=True)

        # The loaded card: Edge still honours --load-extension.
        profile = tempfile.mkdtemp(prefix="riff-shoot-edge-")
        edge = p.chromium.launch_persistent_context(
            profile,
            channel="msedge",
            viewport=VIEWPORT,
            device_scale_factor=2,
            color_scheme="dark",
            args=[f"--disable-extensions-except={EXT}", f"--load-extension={EXT}", "--hide-scrollbars"],
        )
        page = edge.new_page()
        page.goto("edge://extensions/")
        page.get_by_text("riff proxy switch").first.wait_for(timeout=8000)
        shot(page, "ext-loaded", pause=900)
        edge.close()
        shutil.rmtree(profile, ignore_errors=True)

        # ---- the traffic shot and the video, in one proxied Chrome ----------
        print("video")
        vdir = pathlib.Path(tempfile.mkdtemp(prefix="riff-video-"))
        ctx, profile = chrome_profile(
            viewport=VIEWPORT,
            color_scheme="dark",
            record_video_dir=str(vdir),
            record_video_size={"width": 1280, "height": 782},
            args=["--hide-scrollbars", f"--proxy-server=http://{PROXY}",
                  # the demo origin is on loopback with a self-signed cert
                  "--proxy-bypass-list=<-loopback>", "--ignore-certificate-errors"],
        )
        page = ctx.new_page()
        page.add_init_script(CHROME_SHIM)
        hold = lambda ms: page.wait_for_timeout(ms)  # noqa: E731

        page.goto(caption("Capture your everyday Chrome with riff",
                          "Install the riff proxy switch extension. About a minute, no admin rights, "
                          "and Zscaler cannot undo it."))
        hold(3200)

        page.goto(caption("Open the extensions page",
                          "Type <code>chrome://extensions</code> in the address bar, then switch on "
                          "<b>Developer mode</b> in the top-right corner.", "Step 1"))
        hold(3600)
        developer_mode(page)
        hold(2600)

        page.goto(caption("Load the extension",
                          "Click <b>Load unpacked</b> and choose the <code>extension</code> folder next to "
                          "riff.exe. "
                          "The <b>riff proxy switch</b> card appears in the list.", "Step 2"))
        hold(5200)

        page.goto(caption("Flip the switch",
                          "Start riff if it is not running, then click the riff icon in the toolbar "
                          "and turn the switch on. The icon shows an <b>on</b> badge.", "Step 3"))
        hold(3800)
        page.emulate_media(color_scheme="light")  # the popup reads best on its light palette
        page.goto(popup_stage_url())
        page.frame_locator("iframe").locator("#state.on").wait_for(timeout=8000)
        hold(4200)
        page.emulate_media(color_scheme="dark")

        page.goto(caption("Browse", "Load the site you are working on. Chrome sends it through riff.", "Step 4"))
        # Warm the tunnel first: minting a leaf certificate for a host riff has
        # not seen takes a second or so, which would tag the real page load
        # `slow` and misrepresent steady-state timings.
        try:
            page.goto(SITE, wait_until="load", timeout=25000)
        except Exception:
            pass
        hold(2600)
        try:
            page.goto(SITE + "products", wait_until="load", timeout=25000)
            page.goto(SITE + "news", wait_until="load", timeout=25000)
        except Exception as exc:  # the site is not the point; keep going
            print(f"  note: {SITE} did not finish loading: {exc}")
        hold(3200)

        page.goto(caption("Watch it in riff", "Every request from that Chrome is now in the list.", "Step 5"))
        hold(2400)
        page.goto(f"{UI}/?token={token}", wait_until="domcontentloaded")
        page.wait_for_selector(".row", timeout=15000)
        page.fill("#filter", "host:127.0.0.1")
        hold(800)
        shot(page, "ext-traffic", pause=600)
        hold(2800)

        page.goto(caption("That's it",
                          "Turn the switch off when you're done and Chrome goes back to its normal "
                          "connection. Nothing on the machine was changed."))
        hold(3200)

        # The recording is only finalised once the context closes; pick it up then.
        ctx.close()
        shutil.rmtree(profile, ignore_errors=True)
        recorded = sorted(vdir.glob("*.webm"), key=lambda f: f.stat().st_size)
        if not recorded:
            sys.exit("no video was written")
        VIDEO.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(recorded[-1]), str(VIDEO))
        shutil.rmtree(vdir, ignore_errors=True)
        print(f"  {VIDEO.relative_to(ROOT)}  {VIDEO.stat().st_size / 1024 / 1024:.1f} MB")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))

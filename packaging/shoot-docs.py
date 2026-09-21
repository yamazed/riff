"""Capture the README screenshots, start to finish.

    python packaging/shoot-docs.py

Self-contained: it starts the demo app, starts its own riff against it, drives
a fixed run of traffic through the proxy, then photographs the traffic table,
the detail tabs, the rule editor and the setup drawer.

Uses the Chrome already installed on the machine (channel="chrome"), so there
is no browser download.

Writes traffic, filter, detail-request, detail-response, detail-timing,
detail-raw, detail-mocked, rules, rules-error, setup and traffic-light
into docs/screenshots.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import time

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from demo.app import serve as serve_demo      # noqa: E402
from demo.traffic import run as run_traffic   # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "screenshots"
RIFF_HOME = pathlib.Path(os.environ.get("USERPROFILE", "")) / ".riff"
PROXY_PORT, UI_PORT, APP_PORT = 8890, 8891, 8123
VIEWPORT = {"width": 1440, "height": 880}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    demo = serve_demo(port=APP_PORT)  # plain HTTP: these shots are of the API, not TLS
    home = pathlib.Path(tempfile.mkdtemp(prefix="riff-shoot-home-"))
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "riff", "run", "-p", str(PROXY_PORT), "--ui-port", str(UI_PORT),
            "--no-proxy-watch", "--ca-home", str(home),
            "-s", str(ROOT / "examples" / "demo.riff"), "--quiet",
        ],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        url_file = home / "ui-url.txt"
        for _ in range(100):
            if url_file.exists() and "token=" in url_file.read_text(encoding="utf-8"):
                break
            time.sleep(0.1)
        else:
            print("riff never wrote its UI address", file=sys.stderr)
            return 1
        base_url = url_file.read_text(encoding="utf-8").strip()
        token = base_url.partition("token=")[2]

        print("driving demo traffic...")
        run_traffic(f"127.0.0.1:{PROXY_PORT}", f"127.0.0.1:{APP_PORT}", quiet=True)
        time.sleep(1.0)

        return shoot(token, f"http://localhost:{UI_PORT}")
    finally:
        demo.shutdown()
        proc.terminate()


def shoot(token: str, base: str) -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", args=["--hide-scrollbars"])
        context = browser.new_context(
            viewport=VIEWPORT, device_scale_factor=2, color_scheme="dark", reduced_motion="reduce"
        )
        page = context.new_page()

        page.goto(f"{base}/?token={token}", wait_until="domcontentloaded")
        page.wait_for_selector(".row", timeout=15000)
        page.wait_for_timeout(600)

        def shot(name: str) -> None:
            page.wait_for_timeout(350)
            page.screenshot(path=str(OUT / f"{name}.png"))
            print(f"  {name}.png")

        # 1 — the live traffic table
        shot("traffic")

        # 2 — filtering
        page.fill("#filter", "status:5xx")
        page.wait_for_timeout(400)
        shot("filter")
        page.fill("#filter", "")
        page.wait_for_timeout(300)

        # 3..6 — the detail tabs, each on a flow that shows it off.
        # Give the detail pane most of the window so bodies are actually visible.
        def detail(name: str, row_text: str, tab: str, scroll: int = 0) -> None:
            page.click(f".row:has-text('{row_text}')")
            page.wait_for_selector("#detail-body:not([hidden])", timeout=8000)
            page.click(f".tab[data-tab='{tab}']")
            page.evaluate("document.getElementById('split').style.gridTemplateRows = '1fr 5px 66%'")
            if scroll:
                page.evaluate(
                    "y => document.querySelector('.panel.is-active').scrollTop = y", scroll
                )
            shot(name)
            page.evaluate("document.getElementById('split').style.gridTemplateRows = ''")

        detail("detail-request", "/v1/session", "request", scroll=260)
        detail("detail-response", "/v1/users", "response", scroll=300)
        detail("detail-timing", "/v1/search", "timing")
        detail("detail-raw", "/v1/orders", "raw")

        # 7 — synthetic response produced by a rule
        detail("detail-mocked", "/v1/flags", "response", scroll=250)

        # 8 — the rule editor
        page.click("#btn-script")
        page.wait_for_selector("#drawer-script:not([hidden])")
        page.wait_for_timeout(500)
        shot("rules")

        # 9 — a rejected script, showing the caret
        page.fill("#script-source", 'on request where host == {\n    tag "nope"\n}\n')
        page.click("#btn-script-check")
        page.wait_for_timeout(700)
        shot("rules-error")
        page.click("#drawer-script .drawer-close")

        # 10 — setup / certificate guidance
        page.click("#btn-setup")
        page.wait_for_selector("#drawer-setup:not([hidden])")
        page.wait_for_timeout(400)
        shot("setup")
        page.click("#drawer-setup .drawer-close")

        # 11 — light theme, same table
        page.click("#btn-theme")
        page.wait_for_timeout(400)
        shot("traffic-light")

        browser.close()
    print(f"\nwrote screenshots to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Capture the export/import screenshots for the README and the walkthrough.

    python packaging/shoot-export.py

Starts its own riff on ports 8890/8891 (using your trusted CA from
%USERPROFILE%\\.riff, but a scratch home so the running riff's UI address is
untouched), drives a proxied Chrome through a few demo-app pages for real
traffic, then works the UI: tick rows, open Export, download a HAR, import it.

Writes docs/screenshots/export.png and docs/screenshots/import.png.
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
from demo.app import serve as serve_demo  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "screenshots"
RIFF_HOME = pathlib.Path(os.environ.get("USERPROFILE", "")) / ".riff"
PROXY_PORT, UI_PORT = 8890, 8891
UI = f"http://localhost:{UI_PORT}"
PAGES = ["https://localhost:8443/", "https://localhost:8443/news", "https://localhost:8443/products"]
APP_PORT = 8443
VIEWPORT = {"width": 1440, "height": 880}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    demo = serve_demo(port=APP_PORT, tls=True)  # the origin riff will intercept
    home = pathlib.Path(tempfile.mkdtemp(prefix="riff-shoot-home-"))
    downloads = pathlib.Path(tempfile.mkdtemp(prefix="riff-shoot-dl-"))
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "riff", "run", "-p", str(PROXY_PORT), "--ui-port", str(UI_PORT),
            "--no-proxy-watch", "--ca-home", str(home),
            "--ca-cert", str(RIFF_HOME / "riff-ca.crt"), "--ca-key", str(RIFF_HOME / "riff-ca.key"),
            "-s", str(ROOT / "examples" / "demo.riff"), "--insecure", "--quiet",
        ],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        url_file = home / "ui-url.txt"
        for _ in range(100):
            if url_file.exists() and "token=" in url_file.read_text():
                break
            time.sleep(0.1)
        token = url_file.read_text().strip().split("token=")[1]

        with sync_playwright() as p:
            # ---- real traffic through the proxy -------------------------------
            # <-loopback> stops Chrome skipping the proxy for localhost, which
            # is where the demo app lives.
            surfer = p.chromium.launch(channel="chrome", args=[
                f"--proxy-server=http://127.0.0.1:{PROXY_PORT}",
                "--proxy-bypass-list=<-loopback>",
                "--ignore-certificate-errors",
            ])
            tab = surfer.new_page()
            for url in PAGES:
                try:
                    tab.goto(url, wait_until="load", timeout=30000)
                except Exception as exc:  # a slow page is not the point
                    print(f"  note: {url}: {exc}")
                tab.wait_for_timeout(800)
            surfer.close()

            # ---- the UI -----------------------------------------------------------
            browser = p.chromium.launch(channel="chrome", args=["--hide-scrollbars"])
            ctx = browser.new_context(viewport=VIEWPORT, device_scale_factor=2, color_scheme="dark",
                                      accept_downloads=True, reduced_motion="reduce")
            page = ctx.new_page()
            page.goto(f"{UI}/?token={token}", wait_until="domcontentloaded")
            page.wait_for_selector(".row", timeout=15000)
            page.fill("#filter", "!tag:static")
            page.wait_for_timeout(500)
            rows = page.locator(".row")
            count = rows.count()
            print(f"  {count} non-static rows")
            if count < 6:
                page.fill("#filter", "")
                page.wait_for_timeout(400)
                rows = page.locator(".row")

            # tick a range of four, then open the export menu
            rows.nth(1).locator(".col-check input").click()
            rows.nth(4).locator(".col-check input").click(modifiers=["Shift"])
            rows.nth(2).click()  # a selected row for the detail pane
            page.wait_for_selector("#detail-body:not([hidden])")
            page.click("#btn-export")
            page.wait_for_timeout(500)
            page.screenshot(path=str(OUT / "export.png"))
            print("  export.png")

            with page.expect_download() as dl:
                page.click("#export-menu .menu-item[data-format='har']")
            har = downloads / dl.value.suggested_filename
            dl.value.save_as(str(har))
            page.wait_for_timeout(300)

            # import it back and show only the imported rows
            page.set_input_files("#import-file", [str(har)])
            page.locator(".toast", has_text="Imported").wait_for(timeout=10000)
            page.fill("#filter", "tag:imported")
            page.wait_for_timeout(400)
            page.locator(".row").first.click()
            page.wait_for_selector("#detail-body:not([hidden])")
            page.click(".tab[data-tab='response']")
            page.wait_for_timeout(500)
            page.screenshot(path=str(OUT / "import.png"))
            print("  import.png")
            browser.close()
        return 0
    finally:
        demo.shutdown()
        proc.terminate()
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())

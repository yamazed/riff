"""Capture the composer screenshots for the README and the walkthrough.

    python packaging/shoot-compose.py

Starts its own riff on ports 8890/8891 with a scratch workspace, seeds a
realistic demo collection and a `dev` environment through the API, sends one
request for real, and photographs the composer and the environment editor.

Writes docs/screenshots/compose.png and docs/screenshots/compose-env.png.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.request

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from demo.app import serve as serve_demo  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "screenshots"
RIFF_HOME = pathlib.Path(os.environ.get("USERPROFILE", "")) / ".riff"
PROXY_PORT, UI_PORT, APP_PORT = 8890, 8891, 8443
UI = f"http://localhost:{UI_PORT}"
VIEWPORT = {"width": 1440, "height": 880}

COLLECTION = {
    "name": "DemoShop API",
    "description": "The demo app's pages and JSON API, for demos.",
    "auth": {"type": "bearer", "token": "{{token}}"},
    "variables": {"query": "widget"},
    "folders": ["Pages", "Search", "Users"],
    "requests": [
        {"name": "Home page", "method": "GET", "url": "{{baseUrl}}/", "auth": {"type": "none"}, "folder": "Pages",
         "headers": [{"name": "Accept", "value": "text/html"}]},
        {"name": "News", "method": "GET", "url": "{{baseUrl}}/news", "folder": "Pages",
         "params": [{"name": "_rsc", "value": "1"}], "auth": {"type": "none"}},
        {"name": "Search the catalogue", "method": "GET", "url": "{{baseUrl}}/v1/search", "folder": "Search",
         "params": [{"name": "q", "value": "{{query}}"}],
         "headers": [{"name": "Accept", "value": "application/json"}, {"name": "X-Correlation-Id", "value": "{{correlationId}}"}],
         "auth": {"type": "inherit"},
         "capture": [{"var": "lastRequestId", "from": "header", "path": "x-request-id"}]},
        {"name": "Create a user", "method": "POST", "url": "{{baseUrl}}/v1/users", "folder": "Users",
         "body": {"mode": "json", "text": '{\n  "name": "Edsger Dijkstra",\n  "email": "{{email}}",\n  "role": "engineer"\n}'},
         "auth": {"type": "inherit"}},
    ],
}
ENVIRONMENTS = {
    "dev": {"baseUrl": "https://localhost:8443", "email": "ada@example.com", "correlationId": "riff-demo-dev"},
    "prod": {"baseUrl": "https://localhost:8443", "email": "grace@example.com", "correlationId": "riff-demo-prod"},
}
PERSONAL = {"dev": {"token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.dev-token"}}


def api(token: str, method: str, path: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(UI + path, method=method, data=data,
                                 headers={"X-Riff-Token": token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    demo = serve_demo(port=APP_PORT, tls=True)  # the origin riff will intercept
    home = pathlib.Path(tempfile.mkdtemp(prefix="riff-shoot-home-"))
    work = pathlib.Path(tempfile.mkdtemp(prefix="riff-shoot-work-"))
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "riff", "run", "-p", str(PROXY_PORT), "--ui-port", str(UI_PORT),
            "--no-proxy-watch", "--ca-home", str(home), "--workspace", str(work),
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

        # seed
        slug = api(token, "POST", "/api/collections", {"name": COLLECTION["name"]})["slug"]
        api(token, "PUT", f"/api/collections/{slug}", COLLECTION)
        for name, values in ENVIRONMENTS.items():
            api(token, "PUT", f"/api/environments/{name}", {"values": values})
        for name, values in PERSONAL.items():
            api(token, "PUT", f"/api/personal?environment={name}", {"values": values})
        doc = api(token, "GET", f"/api/collections/{slug}")
        search = next(r for r in doc["requests"] if r["name"] == "Search the catalogue")
        print(f"  seeded {slug} with {len(doc['requests'])} requests")

        with sync_playwright() as p:
            browser = p.chromium.launch(channel="chrome", args=["--hide-scrollbars"])
            ctx = browser.new_context(viewport=VIEWPORT, device_scale_factor=2, color_scheme="dark", reduced_motion="reduce")
            page = ctx.new_page()
            page.add_init_script("try { localStorage.setItem('riff-env', 'dev'); } catch (e) {}")
            page.goto(f"{UI}/?token={token}", wait_until="domcontentloaded")
            page.wait_for_selector("#btn-compose")
            page.goto(f"{UI}/#compose/{slug}/{search['id']}", wait_until="domcontentloaded")
            page.wait_for_selector("#drawer-compose:not([hidden])")
            page.locator(".req-row.is-active").wait_for(timeout=10000)
            page.click("#req-tabs .tab[data-tab='headers']")
            page.click("#btn-compose-send")
            page.locator("#resp:not([hidden])").wait_for(timeout=30000)
            page.locator("#resp-status").wait_for()
            page.wait_for_timeout(600)
            page.screenshot(path=str(OUT / "compose.png"))
            print("  compose.png")

            page.click("#btn-env-edit")
            page.wait_for_selector("#env-editor:not([hidden])")
            page.wait_for_timeout(500)
            page.screenshot(path=str(OUT / "compose-env.png"))
            print("  compose-env.png")
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

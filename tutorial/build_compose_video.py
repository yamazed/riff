"""Render a narrated tour of Compose, the API client inside riff: tutorial/riff-compose-tour.mp4.

    python tutorial/build_compose_video.py              # everything
    python tutorial/build_compose_video.py --scenes build,save --no-concat   # iterate on scenes

Set RIFF_PYTHON to the interpreter that has riff's dependencies (the project venv) when the video
tooling (edge-tts, imageio-ffmpeg, playwright) lives in a different one.

Self-contained: it starts its own riff on ports 8894/8895 with a scratch workspace and
`tutorial/compose-demo.riff`, whose rules answer every request to demo-api.riff.local, so the
recording is deterministic and needs no network. Each scene is a live Playwright recording of the
real UI, with a drawn cursor so viewers can follow the clicks, and each action is cued to the
sentence of narration that describes it. Same voice and tooling as the walkthrough (Edge neural
TTS, Chrome via Playwright, ffmpeg from imageio-ffmpeg).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections import deque
from pathlib import Path

import edge_tts
import imageio_ffmpeg
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
from theme import BG, CSS, H, W  # noqa: E402
from build_video import RATE, VOICE, audio_duration, run  # noqa: E402
VOICE = "en-US-AvaNeural"  # the tour videos use a female US voice, independent of build_video

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
WORK = HERE / "video-build" / "compose"
OUTPUT = HERE / "riff-compose-tour.mp4"
RULES = HERE / "compose-demo.riff"
RIFF_HOME = Path(os.environ.get("USERPROFILE", str(Path.home()))) / ".riff"
PROXY_PORT, UI_PORT = 8894, 8895
# The interpreter that runs riff itself (needs `cryptography`); the video tooling may live in a different one.
RIFF_PYTHON = os.environ.get("RIFF_PYTHON") or sys.executable
UI = f"http://localhost:{UI_PORT}"
VIEW = {"width": W, "height": H}
ZOOM = 1.25   # the riff UI is zoomed so its 12px type reads at 1080p; cards are not
API_HOST = "https://demo-api.riff.local"

# A Collection v2.1 file to import on camera: the shape of a real SCIM test suite.
COLLECTION_SAMPLE = {
    "info": {"name": "SCIM Tests", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
    "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}", "type": "string"}]},
    "variable": [{"key": "Server", "value": "scim.demo.example.com"}, {"key": "Api", "value": "scim/v2"}],
    "item": [
        {"name": "Get Token", "item": [{"name": "Get Token", "request": {"method": "GET", "url": "https://{{Server}}/{{Api}}/Token"}}]},
        {"name": "Endpoint tests", "item": [
            {"name": "Get empty Users", "request": {"method": "GET", "url": "https://{{Server}}/{{Api}}/Users"}},
            {"name": "Get ResourceTypes", "request": {"method": "GET", "url": "https://{{Server}}/{{Api}}/ResourceTypes"}},
            {"name": "Get Schemas", "request": {"method": "GET", "url": "https://{{Server}}/{{Api}}/Schemas"}},
        ]},
        {"name": "User tests", "item": [
            {"name": "Post User", "request": {"method": "POST", "url": "https://{{Server}}/{{Api}}/Users",
                                               "body": {"mode": "raw", "raw": '{"userName": "user1@example.com"}', "options": {"raw": {"language": "json"}}}}},
            {"name": "Get user1", "request": {"method": "GET", "url": "https://{{Server}}/{{Api}}/Users/1"}},
            {"name": "patch user1", "request": {"method": "PATCH", "url": "https://{{Server}}/{{Api}}/Users/1"}},
            {"name": "Garbage", "item": [{"name": "Post user with garbage", "request": {"method": "POST", "url": "https://{{Server}}/{{Api}}/Users"}}]},
        ]},
        {"name": "Group tests", "item": [
            {"name": "Post Group", "request": {"method": "POST", "url": "https://{{Server}}/{{Api}}/Groups"}},
            {"name": "Get group1", "request": {"method": "GET", "url": "https://{{Server}}/{{Api}}/Groups/1"}},
        ]},
        {"name": "Teardown", "item": [{"name": "Delete user1", "request": {"method": "DELETE", "url": "https://{{Server}}/{{Api}}/Users/1"}}]},
        {"name": "Get all users", "request": {"method": "GET", "url": "https://{{Server}}/{{Api}}/Users?count=100"}},
    ],
}

# A drawn cursor: Playwright's recordings have none, and a tutorial needs one.
CURSOR_JS = """
(() => {
  const cur = document.createElement('div');
  cur.id = 'riff-cursor';
  cur.style.cssText = 'position:fixed;left:0;top:0;width:22px;height:30px;z-index:2147483647;pointer-events:none;transform:translate(-3px,-2px);transition:opacity .2s;opacity:0';
  cur.innerHTML = '<svg width="22" height="30" viewBox="0 0 22 30"><path d="M3 2 L3 24 L8.5 18.5 L12.5 27.5 L16 26 L12 17 L20 17 Z" fill="#fff" stroke="#111" stroke-width="1.6" stroke-linejoin="round"/></svg>';
  const ring = document.createElement('div');
  ring.style.cssText = 'position:fixed;width:34px;height:34px;border-radius:50%;border:3px solid #8b7cf6;z-index:2147483646;pointer-events:none;transform:translate(-50%,-50%) scale(.3);opacity:0';
  document.addEventListener('DOMContentLoaded', () => { document.documentElement.append(cur, ring); });
  let x = 0, y = 0;
  const move = (e) => { x = e.clientX; y = e.clientY; cur.style.left = x + 'px'; cur.style.top = y + 'px'; cur.style.opacity = '1'; };
  document.addEventListener('mousemove', move, true);
  document.addEventListener('dragover', move, true);
  document.addEventListener('mousedown', (e) => {
    ring.style.left = e.clientX + 'px'; ring.style.top = e.clientY + 'px';
    ring.style.transition = 'none'; ring.style.opacity = '.9'; ring.style.transform = 'translate(-50%,-50%) scale(.3)';
    requestAnimationFrame(() => { ring.style.transition = 'transform .45s ease-out, opacity .45s ease-out'; ring.style.opacity = '0'; ring.style.transform = 'translate(-50%,-50%) scale(1.4)'; });
  }, true);
})();
"""


ZOOM_JS = "document.addEventListener('DOMContentLoaded', () => { document.body.style.zoom = '%s'; });" % ZOOM


# ── narration + recording plumbing ───────────────────────────────────────────

def centre(title: str, text: str) -> str:
    import html

    return (f'<!doctype html><html><head><meta charset="utf-8"><style>{CSS}</style></head><body><div class="stage">'
            f'<div class="center"><div class="kicker">riff · Compose</div><h1>{html.escape(title)}</h1>'
            f'<p>{html.escape(text)}</p></div></div></body></html>')


async def narrate(name: str, text: str) -> Path:
    path = WORK / f"{name}.mp3"
    if not path.exists():
        import ssl

        import edge_tts.communicate as communicate_module

        try:  # Zscaler re-signs the TTS endpoint
            import truststore

            communicate_module._SSL_CTX = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except ImportError:
            pass
        print(f"voice  {name}", flush=True)
        for attempt in range(4):  # Edge TTS sometimes returns no audio through Zscaler; retry
            try:
                await edge_tts.Communicate(text, VOICE, rate=RATE).save(str(path))
                break
            except Exception:
                if attempt == 3:
                    raise
                await asyncio.sleep(2)
    return path


def record(name: str, drive, zoom: bool = True) -> Path:
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", args=["--hide-scrollbars"])
        context = browser.new_context(viewport=VIEW, device_scale_factor=1, color_scheme="dark", reduced_motion="reduce",
                                      record_video_dir=str(WORK / "raw"), record_video_size={"width": W, "height": H})
        context.add_init_script(CURSOR_JS)
        if zoom:
            context.add_init_script(ZOOM_JS)
        page = context.new_page()
        page.set_default_timeout(20000)
        started = time.time()
        print(f"scene  {name} started", flush=True)
        drive(page, started)
        print(f"scene  {name} actions done after {time.time() - started:.0f}s", flush=True)
        video = page.video
        context.close()
        browser.close()
        raw = Path(video.path())
    dest = WORK / f"{name}.webm"
    if dest.exists():
        dest.unlink()
    raw.rename(dest)
    print(f"record {name}  {dest.stat().st_size / 1024 / 1024:.1f} MB", flush=True)
    return dest


def compose(ffmpeg: str, name: str, video: Path, audio: Path, seconds: float) -> Path:
    out = WORK / f"{name}.mp4"
    run([ffmpeg, "-y", "-i", str(video), "-i", str(audio), "-filter_complex",
         f"[0:v]scale={W}:{H}:force_original_aspect_ratio=decrease,pad={W}:{H}:(ow-iw)/2:(oh-ih)/2:color={BG},fps=30,format=yuv420p[v];"
         f"[1:a]adelay=600|600,apad=whole_dur={seconds:.2f}[a]",
         "-map", "[v]", "-map", "[a]", "-t", f"{seconds:.2f}", "-c:v", "libx264", "-preset", "medium", "-crf", "20",
         "-c:a", "aac", "-b:a", "160k", "-movflags", "+faststart", str(out)])
    print(f"clip   {name}  {seconds:.1f}s", flush=True)
    return out


# ── the riff under test ──────────────────────────────────────────────────────

class Riff:
    def __init__(self):
        self.home = Path(tempfile.mkdtemp(prefix="riff-tour-home-"))
        self.work = Path(tempfile.mkdtemp(prefix="riff-tour-work-"))
        self.proc = None
        self.token = ""

    def start(self):
        self.proc = subprocess.Popen(
            [RIFF_PYTHON, "-m", "riff", "run", "-p", str(PROXY_PORT), "--ui-port", str(UI_PORT), "--no-proxy-watch",
             "--ca-home", str(self.home), "--workspace", str(self.work),
             "--ca-cert", str(RIFF_HOME / "riff-ca.crt"), "--ca-key", str(RIFF_HOME / "riff-ca.key"),
             "-s", str(RULES), "--quiet"],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        url_file = self.home / "ui-url.txt"
        for _ in range(150):
            if url_file.exists() and "token=" in url_file.read_text():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("riff did not start")
        self.token = url_file.read_text().strip().split("token=")[1]

    def api(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(UI + path, method=method, data=data,
                                     headers={"X-Riff-Token": self.token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# ── page helpers: everything moves the drawn cursor ──────────────────────────

def glide(page, selector, steps=22):
    box = page.locator(selector).first.bounding_box()
    if not box:
        page.locator(selector).first.scroll_into_view_if_needed()
        box = page.locator(selector).first.bounding_box()
    page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2, steps=steps)
    return box


def click(page, selector, pause=250):
    glide(page, selector)
    page.wait_for_timeout(120)
    page.mouse.down()
    page.mouse.up()
    page.wait_for_timeout(pause)


def hover(page, selector, pause=400):
    glide(page, selector)
    page.wait_for_timeout(pause)


def type_in(page, selector, text, delay=28):
    """Type like a person. The key/value grids rebuild their rows on the first keystroke into a blank
    row, which drops focus; re-focus whenever that happens so no key falls through to riff's shortcuts."""
    click(page, selector, pause=80)
    field = page.locator(selector).first
    field.fill("")
    for ch in text:
        if not field.evaluate("el => el === document.activeElement"):
            field.focus()
            page.keyboard.press("End")
        page.keyboard.type(ch)
        page.wait_for_timeout(delay)


def choose(page, selector, value):
    click(page, selector, pause=150)
    page.select_option(selector, value)
    page.wait_for_timeout(200)


def drag(page, source, target):
    a = glide(page, source)
    page.mouse.down()
    page.mouse.move(a["x"] + a["width"] / 2 + 8, a["y"] + a["height"] / 2 + 4, steps=4)
    b = page.locator(target).first.bounding_box()
    page.mouse.move(b["x"] + b["width"] / 2, b["y"] + b["height"] / 2, steps=28)
    page.wait_for_timeout(250)
    page.mouse.up()
    page.wait_for_timeout(400)


def wait_response(page):
    page.locator("#resp:not([hidden])").wait_for(timeout=15000)
    page.locator("#resp-status").wait_for()
    page.wait_for_timeout(300)


def open_ui(page, riff: Riff, hash_: str = "", env: str = ""):
    if env:  # each scene is a fresh browser profile; carry the environment picked in an earlier scene
        page.add_init_script("try { localStorage.setItem('riff-env', '%s'); } catch (e) {}" % env)
    page.goto(f"{UI}/?token={riff.token}", wait_until="domcontentloaded")
    page.wait_for_selector("#btn-compose")
    if hash_:
        page.goto(f"{UI}/{hash_}", wait_until="domcontentloaded")
        page.wait_for_selector("#drawer-compose:not([hidden])")
        page.wait_for_timeout(400)
    page.mouse.move(VIEW["width"] * 0.55, VIEW["height"] * 0.5)


def row_selector(name: str) -> str:
    return f".req-row:has(.req-name:text-is('{name}'))"


def folder_selector(name: str) -> str:
    return f".folder-head:has(.folder-name:text-is('{name}'))"


# ── beats: (sentence, action) pairs; each action fires when its sentence starts ──

def play_beats(page, started: float, duration: float, beats):
    total = sum(len(s.split()) for s, _ in beats)
    spoken = 0
    for sentence, action in beats:
        at = started + 0.6 + duration * spoken / total
        while time.time() < at:
            page.wait_for_timeout(40)
        late = time.time() - at
        if late > 1.5:
            print(f"  late by {late:.1f}s: {sentence[:60]}", flush=True)
        if action:
            action(page)
        spoken += len(sentence.split())
    while time.time() - started < duration + 1.2:
        page.wait_for_timeout(100)


INTRO = (
    "Compose is the request tool built into riff: a full API client. If you have never used one, here is the whole idea. "
    "You write down an H T T P request, send it, read the answer, and keep the request so you can send it again tomorrow. "
    "Everything you send goes through riff, so it also shows up in the traffic list with everything else. "
    "This tour covers all of it: building a request, saving it into collections and folders, environments and variables, "
    "logging in once and capturing the token for every other request, and moving collections in and out."
)

OUTRO = (
    "That is Compose. Build a request and send it. Save it into a collection, in folders, as plain files the team can share. "
    "Environments for the servers, personal values for the secrets, capture for the token, and collection import and export "
    "when you need them. Press n to open it, and the Compose section of the read me has the details."
)


def build_beats(riff: Riff):
    return [
        ("Open Compose from the button at the top of riff, or just press n.",
         lambda p: (click(p, "#btn-compose"), p.wait_for_selector("#drawer-compose:not([hidden])"), p.wait_for_timeout(300))),
        ("The top line is the request itself: a method, and an address.",
         lambda p: hover(p, "#compose-method")),
        ("Type the U R L of the endpoint you want to call.",
         lambda p: type_in(p, "#compose-url", f"{API_HOST}/api/users")),
        ("Params holds query string values as a grid. Untick a row and it stays out of the request.",
         lambda p: (type_in(p, "#kv-params .kv-row:nth-child(1) .kv-name", "count"),
                    type_in(p, "#kv-params .kv-row:nth-child(1) .kv-value", "25"))),
        ("Headers works the same way.",
         lambda p: (click(p, "#req-tabs .tab[data-tab='headers']"),
                    type_in(p, "#kv-headers .kv-row:nth-child(1) .kv-name", "Accept"),
                    type_in(p, "#kv-headers .kv-row:nth-child(1) .kv-value", "application/json"))),
        ("Now Send, or press Control Enter.",
         lambda p: (click(p, "#btn-compose-send"), wait_response(p))),
        ("The response appears underneath: the status, how long it took, the size, and the body, pretty printed.",
         lambda p: hover(p, "#resp-status")),
        ("The second tab has the response headers.",
         lambda p: (click(p, "#resp-tabs .tab[data-tab='headers']"), p.wait_for_timeout(1200), click(p, "#resp-tabs .tab[data-tab='body']"))),
        ("This one came back four oh one: the A P I wants a bearer token. We will fix that in a minute.",
         lambda p: hover(p, "#resp-body")),
        ("Every send is also an ordinary row in the traffic list. The flow link opens it there,",
         lambda p: (click(p, "#resp-open"), p.wait_for_timeout(900))),
        ("with the full request and response, timing, and the raw bytes, like any other capture.",
         lambda p: hover(p, "#btn-edit-replay")),
        ("And it works the other way round: open any captured row and click Edit and send to reopen it in Compose with its real headers and body.",
         lambda p: (click(p, "#btn-edit-replay"), p.wait_for_selector("#drawer-compose:not([hidden])"), p.wait_for_timeout(500))),
        ("Replay re-sends a row exactly as it was, and Copy curl puts it on your clipboard as a command line.",
         lambda p: hover(p, "#compose-url")),
    ]


def save_beats(riff: Riff, answers: deque):
    return [
        ("A request worth keeping goes into a collection. Click Save to.",
         lambda p: (click(p, "#btn-req-save"), p.wait_for_selector("#save-dialog:not([hidden])"))),
        ("A collection is a named group of requests, one JSON file each. Name a new one: Demo A P I.",
         lambda p: type_in(p, "#save-new-name", "Demo API")),
        ("Folders group the requests inside it. Start a folder called Users.",
         lambda p: (choose(p, "#save-folder", "__new__"), type_in(p, "#save-new-folder", "Users"))),
        ("Give the request a name, and save.",
         lambda p: (type_in(p, "#save-request-name", "List users"), click(p, "#btn-save-confirm"),
                    p.wait_for_selector(".req-row.is-active"), p.wait_for_timeout(300))),
        ("It appears in the rail on the left, inside its folder, and the title line shows where it lives.",
         lambda p: (hover(p, row_selector("List users")), p.wait_for_timeout(500), hover(p, "#req-where"))),
        ("The dots menu on a collection adds a request or a folder, renames, exports, or deletes it.",
         lambda p: (hover(p, ".col-head"), click(p, ".col-head .col-more"), p.wait_for_selector("#collection-menu:not([hidden])"),
                    hover(p, "#collection-menu [data-action='new-folder']", 1200), p.keyboard.press("Escape"))),
        ("Folders have one too, for subfolders and for starting a request right there.",
         lambda p: (hover(p, folder_selector("Users")), click(p, folder_selector("Users") + " .folder-more"),
                    p.wait_for_selector("#folder-menu:not([hidden])"), hover(p, "#folder-menu [data-action='new-request']", 1000),
                    p.keyboard.press("Escape"))),
        ("Let us add a second request: plus New, the single user endpoint, Save to, and this time a new folder called Auth, so we have somewhere to put the login later.",
         lambda p: (click(p, "#btn-req-new"), type_in(p, "#compose-url", f"{API_HOST}/api/users/1001"),
                    click(p, "#btn-req-save"), p.wait_for_selector("#save-dialog:not([hidden])"),
                    choose(p, "#save-folder", "__new__"), type_in(p, "#save-new-folder", "Auth"),
                    type_in(p, "#save-request-name", "Get one user"), click(p, "#btn-save-confirm"),
                    p.wait_for_selector(row_selector("Get one user")), p.wait_for_timeout(300))),
        ("Put a request in the wrong place? Drag it onto a folder, or onto the collection name, to move it.",
         lambda p: drag(p, row_selector("Get one user"), folder_selector("Users"))),
        ("Click a folder to fold it away, and click again to open it.",
         lambda p: (click(p, folder_selector("Auth")), p.wait_for_timeout(700), click(p, folder_selector("Users")),
                    p.wait_for_timeout(900), click(p, folder_selector("Users")), p.wait_for_timeout(300), click(p, folder_selector("Auth")))),
        ("With a big collection, the filter box narrows the tree to requests whose name or U R L match.",
         lambda p: (type_in(p, "#rail-filter", "one user"), p.wait_for_timeout(1400), page_clear_filter(p))),
        ("On disk this is a collections folder next to your rules file. Check it into the repo and the whole team works from the same requests.",
         lambda p: hover(p, ".col-head")),
    ]


def page_clear_filter(p):
    p.keyboard.press("Escape")   # Escape in the filter clears it (a second Escape would close the drawer)
    p.wait_for_timeout(300)


def env_beats(riff: Riff):
    return [
        ("The same request usually has to go to more than one server: dev, test, production. Environments handle that.",
         lambda p: hover(p, "#env-select")),
        ("Click Environments and create one called d v m.",
         lambda p: (click(p, "#btn-env-edit"), p.wait_for_selector("#env-editor:not([hidden])"), type_in(p, "#env-new-name", "dev"))),
        ("Shared values, on the left, are saved next to the collections and are safe to share. Here that is base U R L, the server this environment points at.",
         lambda p: (type_in(p, "#env-shared .kv-row:nth-child(1) .kv-name", "baseUrl"),
                    type_in(p, "#env-shared .kv-row:nth-child(1) .kv-value", API_HOST))),
        ("Personal values, on the right, live only on this machine and override the shared ones. That is where secrets go. Add the client secret the login will need.",
         lambda p: (type_in(p, "#env-personal .kv-row:nth-child(1) .kv-name", "clientSecret"),
                    type_in(p, "#env-personal .kv-row:nth-child(1) .kv-value", "s3cret-from-the-vault"))),
        ("Save, and d v m is selected at the top of the drawer.",
         lambda p: (click(p, "#btn-env-save"), p.wait_for_selector("#env-editor", state="hidden"), hover(p, "#env-select"))),
        ("Now open List users and replace the host with double curly braces base U R L.",
         lambda p: (click(p, row_selector("List users")), p.wait_for_selector(".req-row.is-active"),
                    type_in(p, "#compose-url", "{{baseUrl}}/api/users"))),
        ("When you send, riff fills the variable in from the selected environment. Pick a different environment and the very same request goes to a different server.",
         lambda p: (click(p, "#btn-compose-send"), wait_response(p), hover(p, "#resp-open"))),
        ("Variables work anywhere: the U R L, params, headers, the body, and the auth fields. If one has no value, riff tells you before anything is sent.",
         lambda p: (click(p, "#btn-req-save"), p.wait_for_timeout(600))),
    ]


def auth_beats(riff: Riff):
    return [
        ("Time to log in. Start a new request with plus New.",
         lambda p: (click(p, "#btn-req-new"), p.wait_for_timeout(200))),
        ("The token endpoint is a POST to connect slash token, on the same base U R L.",
         lambda p: (choose(p, "#compose-method", "POST"), type_in(p, "#compose-url", "{{baseUrl}}/connect/token"))),
        ("Its body is a form: grant type, client id, client secret, username and password. The secret comes from your personal value, so it never lands in the shared file.",
         lambda p: (click(p, "#req-tabs .tab[data-tab='body']"), click(p, "input[name='body-mode'][value='form']"),
                    type_in(p, "#kv-form .kv-row:nth-child(1) .kv-name", "grant_type", 20),
                    type_in(p, "#kv-form .kv-row:nth-child(1) .kv-value", "password", 20),
                    type_in(p, "#kv-form .kv-row:nth-child(2) .kv-name", "client_id", 20),
                    type_in(p, "#kv-form .kv-row:nth-child(2) .kv-value", "riff-demo", 20),
                    type_in(p, "#kv-form .kv-row:nth-child(3) .kv-name", "client_secret", 20),
                    type_in(p, "#kv-form .kv-row:nth-child(3) .kv-value", "{{clientSecret}}", 20),
                    type_in(p, "#kv-form .kv-row:nth-child(4) .kv-name", "username", 20),
                    type_in(p, "#kv-form .kv-row:nth-child(4) .kv-value", "ada@example.com", 20),
                    type_in(p, "#kv-form .kv-row:nth-child(5) .kv-name", "password", 20),
                    type_in(p, "#kv-form .kv-row:nth-child(5) .kv-value", "password12", 20))),
        ("Capture is what makes the login reusable. After a successful send, take access token out of the JSON body and store it as the variable token, in your personal values for d v m.",
         lambda p: (click(p, "#req-tabs .tab[data-tab='capture']"),
                    type_in(p, "#kv-capture .kv-row:nth-child(1) .kv-var", "token"),
                    choose(p, "#kv-capture .kv-row:nth-child(1) .kv-from", "json"),
                    type_in(p, "#kv-capture .kv-row:nth-child(1) .kv-path", "access_token"))),
        ("Send.",
         lambda p: (click(p, "#btn-compose-send"), wait_response(p))),
        ("Two hundred, and the status line confirms the token was captured into dev. In most API clients this takes a script; here it is one row.",
         lambda p: hover(p, "#compose-status", 900)),
        ("Save it as Get token, in the Auth folder.",
         lambda p: (click(p, "#btn-req-save"), p.wait_for_selector("#save-dialog:not([hidden])"),
                    choose(p, "#save-folder", "Auth"), type_in(p, "#save-request-name", "Get token"),
                    click(p, "#btn-save-confirm"), p.wait_for_selector(row_selector("Get token")), p.wait_for_timeout(300))),
        ("Back to List users. On the Auth tab pick bearer token and write double curly braces token: the variable the login just filled.",
         lambda p: (click(p, row_selector("List users")), p.wait_for_selector(".req-row.is-active"),
                    click(p, "#req-tabs .tab[data-tab='auth']"), choose(p, "#auth-type", "bearer"),
                    type_in(p, "#auth-token", "{{token}}"))),
        ("Send again.",
         lambda p: (click(p, "#btn-compose-send"), wait_response(p))),
        ("Two hundred, and the users come back. Save, and every request in this collection can use the same token. When it expires, send Get token once more.",
         lambda p: (hover(p, "#resp-body", 800), click(p, "#btn-req-save"), p.wait_for_timeout(500))),
        ("Basic auth and A P I keys work the same way, and an explicit Authorization header always wins if you set one.",
         lambda p: hover(p, "#auth-type")),
    ]


def interchange_beats(riff: Riff, sample: Path):
    return [
        ("Already have collections elsewhere? Import takes a Collection v2.1 file, a riff collection, or a HAR file.",
         lambda p: (hover(p, "#btn-collection-import", 600), p.set_input_files("#collection-file", str(sample)),
                    p.wait_for_selector(".col-name:text-is('SCIM Tests')"), p.wait_for_timeout(400))),
        ("The folder tree comes across as it was, and so do the collection's auth and variables.",
         lambda p: (hover(p, ".col-block[data-slug='scim-tests'] " + folder_selector("User tests")), p.wait_for_timeout(600),
                    hover(p, ".col-block[data-slug='scim-tests'] " + folder_selector("Garbage")))),
        ("Test scripts do not: riff has the Auth and Capture tabs instead, which cover what most of those scripts did.",
         lambda p: hover(p, ".col-block[data-slug='scim-tests'] " + row_selector("Get Token"))),
        ("Export goes the other way, folders included, so a collection can move on when it grows into a full test suite.",
         lambda p: (hover(p, ".col-block[data-slug='demo-api'] .col-head"), click(p, ".col-block[data-slug='demo-api'] .col-more"),
                    p.wait_for_selector("#collection-menu:not([hidden])"), hover(p, "#collection-menu [data-action='export-v2']", 700),
                    export_collection_v2(p))),
        ("One last thing. Requests sent from here obey your rules file exactly like captured traffic. In this tour every demo endpoint is answered by a respond rule, which is why it runs offline. Untick apply rules to bypass them.",
         lambda p: hover(p, "#compose-rules", 800)),
    ]


def export_collection_v2(p):
    with p.expect_download() as info:
        click(p, "#collection-menu [data-action='export-v2']")
    info.value.save_as(str(WORK / "exported.collection-v2.json"))
    p.wait_for_timeout(800)


# ── main ─────────────────────────────────────────────────────────────────────

ORDER = ("intro", "build", "save", "env", "auth", "interchange", "outro")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenes", default="", help="comma-separated subset to re-record (others reuse cached clips)")
    parser.add_argument("--no-concat", action="store_true")
    args = parser.parse_args()
    only = {s.strip() for s in args.scenes.split(",") if s.strip()}

    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "raw").mkdir(exist_ok=True)
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    sample = WORK / "SCIM Tests.collection-v2.json"
    sample.write_text(json.dumps(COLLECTION_SAMPLE, indent=2), encoding="utf-8")

    riff = Riff()
    riff.start()
    answers: deque = deque()
    try:
        beats = {
            "build": build_beats(riff),
            "save": save_beats(riff, answers),
            "env": env_beats(riff),
            "auth": auth_beats(riff),
            "interchange": interchange_beats(riff, sample),
        }
        texts = {"intro": INTRO, "outro": OUTRO}
        texts.update({name: " ".join(s for s, _ in b) for name, b in beats.items()})
        voices = {name: asyncio.run(narrate(name, texts[name])) for name in ORDER}
        lengths = {name: audio_duration(ffmpeg, path) for name, path in voices.items()}
        print("narration seconds:", {k: round(v, 1) for k, v in lengths.items()}, "total", round(sum(lengths.values())), flush=True)

        def on_dialog(d):
            d.accept(answers.popleft() if answers else "") if d.type == "prompt" else d.accept()

        def drive_card(html_text, seconds):
            def drive(page, started):
                page.set_content(html_text)
                while time.time() - started < seconds + 1.5:
                    page.wait_for_timeout(100)
            return drive

        def first_request(name):
            for col in riff.api("GET", "/api/collections")["collections"]:
                for req in col["requests"]:
                    if req["name"] == name:
                        return f"#compose/{col['slug']}/{req['id']}"
            return "#compose"

        def drive_live(name, hash_for, env=""):
            def drive(page, started):
                page.on("dialog", on_dialog)
                open_ui(page, riff, hash_for(), env)
                play_beats(page, started, lengths[name], beats[name])
            return drive

        def drive_save(page, started):
            # This scene continues from the request built in the previous scene: rebuild it in the drawer first.
            page.on("dialog", on_dialog)
            open_ui(page, riff, "#compose")
            page.fill("#compose-url", f"{API_HOST}/api/users")
            page.locator("#kv-params .kv-row:nth-child(1) .kv-name").fill("count")
            page.locator("#kv-params .kv-row:nth-child(1) .kv-value").fill("25")
            page.click("#req-tabs .tab[data-tab='headers']")
            page.locator("#kv-headers .kv-row:nth-child(1) .kv-name").fill("Accept")
            page.locator("#kv-headers .kv-row:nth-child(1) .kv-value").fill("application/json")
            page.click("#req-tabs .tab[data-tab='params']")
            page.mouse.move(VIEW["width"] * 0.55, VIEW["height"] * 0.5)
            play_beats(page, started, lengths["save"], beats["save"])

        drivers = {
            "intro": drive_card(centre("Compose", "An API client inside riff: build a request, send it, keep it, share it."), lengths["intro"]),
            "build": drive_live("build", lambda: ""),
            "save": drive_save,
            "env": drive_live("env", lambda: first_request("List users")),
            "auth": drive_live("auth", lambda: first_request("List users"), env="dev"),
            "interchange": drive_live("interchange", lambda: first_request("List users"), env="dev"),
            "outro": drive_card(centre("That is Compose", "n opens it · collections/ sits next to your rules file · personal values stay on "
                                       "your machine · README → Compose for the details"), lengths["outro"]),
        }

        def prime_for(name):
            """When re-recording a later scene alone, seed what the earlier scenes would have created."""
            if name in ("env", "auth", "interchange") and not riff.api("GET", "/api/collections")["collections"]:
                slug = riff.api("POST", "/api/collections", {"name": "Demo API"})["slug"]
                riff.api("PUT", f"/api/collections/{slug}", {
                    "name": "Demo API", "folders": ["Users", "Auth"],
                    "requests": [
                        {"name": "List users", "method": "GET", "url": f"{API_HOST}/api/users", "folder": "Users",
                         "params": [{"name": "count", "value": "25"}], "headers": [{"name": "Accept", "value": "application/json"}]},
                        {"name": "Get one user", "method": "GET", "url": f"{API_HOST}/api/users/1001", "folder": "Users"},
                    ]})
            if name in ("auth", "interchange") and not riff.api("GET", "/api/environments")["environments"]:
                riff.api("PUT", "/api/environments/dev", {"values": {"baseUrl": API_HOST}})
                riff.api("PUT", "/api/personal?environment=dev", {"values": {"clientSecret": "s3cret-from-the-vault"}})
            if name == "auth":
                for col in riff.api("GET", "/api/collections")["collections"]:
                    if col["slug"] == "demo-api":
                        doc = riff.api("GET", "/api/collections/demo-api")
                        for req in doc["requests"]:
                            if req["name"] == "List users":
                                req["url"] = "{{baseUrl}}/api/users"
                        riff.api("PUT", "/api/collections/demo-api", doc)

        clips = []
        for name in ORDER:
            clip = WORK / f"{name}.mp4"
            if only and name not in only and clip.exists():
                clips.append(clip)
                continue
            prime_for(name)
            webm = record(name, drivers[name], zoom=name not in ("intro", "outro"))
            clips.append(compose(ffmpeg, name, webm, voices[name], lengths[name] + (1.5 if name in ("intro", "outro") else 1.2)))
            if name == "save":
                where = {r["name"]: r["folder"] for c in riff.api("GET", "/api/collections")["collections"] for r in c["requests"]}
                print("after save scene:", where, flush=True)
    finally:
        riff.stop()

    if args.no_concat:
        print("clips:", [c.name for c in clips])
        return 0
    listing = WORK / "concat.txt"
    listing.write_text("".join(f"file '{c.as_posix()}'\n" for c in clips), encoding="utf-8")
    run([ffmpeg, "-y", "-f", "concat", "-safe", "0", "-i", str(listing), "-c", "copy", "-movflags", "+faststart", str(OUTPUT)])
    print(f"wrote {OUTPUT} ({OUTPUT.stat().st_size / 1024 / 1024:.1f} MB, {audio_duration(ffmpeg, OUTPUT):.0f} s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Render a narrated tour of riff's security scanner: tutorial/riff-scanner-tour.mp4.

    python tutorial/build_scanner_video.py                 # everything
    python tutorial/build_scanner_video.py --scenes active --no-concat   # iterate on one scene

Set RIFF_PYTHON to the interpreter that has riff's dependencies (the project venv) when the
video tooling (edge-tts, imageio-ffmpeg, playwright) lives in a different one.

Self-contained: it starts a tiny, deliberately vulnerable web app on loopback, runs its own riff
on ports 8896/8897 pointed at it, seeds a few captured requests, then films the real UI — the
passive findings that appear as traffic is captured, and an active scan that injects payloads and
turns up reflected XSS, SQL injection, and an open redirect. Same voice and tooling as the rest of
the walkthrough (Edge neural TTS, Chrome via Playwright, ffmpeg from imageio-ffmpeg). Nothing but
loopback is touched.
"""

from __future__ import annotations

import argparse
import asyncio
import http.server
import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

import edge_tts
import imageio_ffmpeg
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
# Reuse the page-driving helpers and the drawn cursor from the Compose tour; copy only the
# WORK-bound plumbing so this script writes into its own build directory.
from build_compose_video import CURSOR_JS, ZOOM_JS, ZOOM, VIEW, click, glide, hover, play_beats, type_in  # noqa: E402
from theme import BG, CSS, H, W  # noqa: E402

sys.path.insert(0, str(HERE.parent))
from demo.app import serve as serve_demo  # noqa: E402
from build_video import RATE, VOICE, audio_duration, run  # noqa: E402
VOICE = "en-US-AvaNeural"  # the tour videos use a female US voice, independent of build_video

ROOT = HERE.parent
WORK = HERE / "video-build" / "scanner"
OUTPUT = HERE / "riff-scanner-tour.mp4"
RULES = HERE / "scanner-demo.riff"
RIFF_PYTHON = os.environ.get("RIFF_PYTHON") or sys.executable
PROXY_PORT, UI_PORT, APP_PORT = 8896, 8897, 8898
UI = f"http://localhost:{UI_PORT}"
ORDER = ("intro", "passive", "active", "outro")


# ── the deliberately vulnerable demo app ─────────────────────────
# One copy, shared with the shoot scripts and anyone trying riff by hand:
# see demo/app.py. Its /shop, /item and /go routes are insecure on purpose.


def start_app() -> "socketserver.TCPServer":
    return serve_demo(port=APP_PORT)


# ── narration + recording plumbing (own WORK) ────────────────────────────────

def centre(title: str, text: str) -> str:
    import html

    return (f'<!doctype html><html><head><meta charset="utf-8"><style>{CSS}</style></head><body><div class="stage">'
            f'<div class="center"><div class="kicker">riff · Scanner</div><h1>{html.escape(title)}</h1>'
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
        self.home = Path(tempfile.mkdtemp(prefix="riff-scan-home-"))
        self.work = Path(tempfile.mkdtemp(prefix="riff-scan-work-"))
        self.proc = None
        self.token = ""

    def start(self):
        self.proc = subprocess.Popen(
            [RIFF_PYTHON, "-m", "riff", "run", "-p", str(PROXY_PORT), "--ui-port", str(UI_PORT), "--no-proxy-watch",
             "--ca-home", str(self.home), "--workspace", str(self.work),
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
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())

    def seed(self):
        """Browse the vulnerable app through riff so the traffic list has rows to scan."""
        for url in (f"http://127.0.0.1:{APP_PORT}/shop?q=widgets",
                    f"http://127.0.0.1:{APP_PORT}/item?id=42",
                    f"http://127.0.0.1:{APP_PORT}/go?next=/account"):
            try:
                self.api("POST", "/api/replay", {"url": url, "method": "GET", "headers": [], "apply_rules": True})
            except Exception as exc:
                print("seed failed:", exc, flush=True)

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def open_ui(page, riff: Riff):
    page.goto(f"{UI}/?token={riff.token}", wait_until="domcontentloaded")
    page.wait_for_selector("#btn-findings")
    page.wait_for_timeout(400)
    page.mouse.move(VIEW["width"] * 0.55, VIEW["height"] * 0.5)


# ── scenes ───────────────────────────────────────────────────────────────────

SCAN_HOST = "127.0.0.1"


def passive_beats(riff: Riff):
    return [
        ("As traffic goes past, riff reads what it already captured and checks it for security problems. Open the Findings panel.",
         lambda p: (click(p, "#btn-findings"), p.wait_for_selector("#drawer-findings:not([hidden])"), p.wait_for_timeout(500))),
        ("These are the passive checks. They send nothing of their own; they only read the responses riff already has, so there is no scanning traffic and nothing to authorise.",
         lambda p: hover(p, ".findings-note")),
        ("Each finding has a severity and points at the flow it came from. This response set a session cookie with no Secure, HttpOnly, or SameSite flag,",
         lambda p: hover(p, ".finding.sev-medium")),
        ("it is missing the browser hardening headers a page like this should send,",
         lambda p: hover(p, ".findings-list")),
        ("and its Server header gives away a version number. Click the flow number on any finding to jump straight to the request and response behind it.",
         lambda p: (click(p, ".finding .finding-flow"), p.wait_for_timeout(1400))),
    ]


def active_beats(riff: Riff):
    return [
        ("Passive checks can only see what the response already shows. The active scan goes further: it sends attack payloads and watches how the server answers. Open Findings again.",
         lambda p: (click(p, "#btn-findings"), p.wait_for_selector("#drawer-findings:not([hidden])"), p.wait_for_timeout(500))),
        ("Because it sends attack traffic, it is gated on scope. You name the hosts you are authorised to test, and riff will only ever probe those.",
         lambda p: type_in(p, "#scan-hosts", SCAN_HOST)),
        ("Then start the scan.",
         lambda p: (click(p, "#btn-scan-start"), p.wait_for_timeout(300))),
        ("riff injects payloads into every query parameter and body field it captured, sends them, and judges the responses. The bar tracks the probes as they go out.",
         lambda p: (p.locator(".finding.sev-high").first.wait_for(timeout=20000), p.wait_for_timeout(400))),
        ("And there they are. A search box that reflects input straight back is a reflected cross-site scripting hole.",
         lambda p: hover(p, ".finding.sev-high")),
        ("A parameter that throws a database error on a single quote is SQL injection.",
         lambda p: (glide(p, ".findings-list"), p.wait_for_timeout(800))),
        ("And a redirect the caller controls is an open redirect. Every finding still links to the exact flow, so you can see the payload that proved it.",
         lambda p: (click(p, ".finding.sev-high .finding-flow"), p.wait_for_timeout(1600))),
    ]


INTRO_TITLE = ("riff's built-in security scanner has two halves. The passive half runs on its own and sends nothing. "
               "The active half injects real attack payloads, so it only ever runs against hosts you put in scope. "
               "Here is both, against a small demo shop that is deliberately full of holes.")

OUTRO_TITLE = ("That is the scanner. Passive findings appear on their own as you browse; the active scan adds reflected "
               "cross-site scripting, SQL injection, open redirects, path traversal, and server-side request forgery, "
               "always inside the scope you set. The same thing runs headless with riff scan for a saved capture, and "
               "writes a report. Only ever scan what you are authorised to test.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenes", default="", help="comma-separated subset to re-record (others reuse cached clips)")
    parser.add_argument("--no-concat", action="store_true")
    args = parser.parse_args()
    only = {s.strip() for s in args.scenes.split(",") if s.strip()}

    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "raw").mkdir(exist_ok=True)
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()

    app = start_app()
    riff = Riff()
    riff.start()
    riff.seed()
    time.sleep(0.6)
    try:
        beats = {"passive": passive_beats(riff), "active": active_beats(riff)}
        texts = {"intro": INTRO_TITLE, "outro": OUTRO_TITLE}
        texts.update({name: " ".join(s for s, _ in b) for name, b in beats.items()})
        voices = {name: asyncio.run(narrate(name, texts[name])) for name in ORDER}
        lengths = {name: audio_duration(ffmpeg, path) for name, path in voices.items()}
        print("narration seconds:", {k: round(v, 1) for k, v in lengths.items()}, "total", round(sum(lengths.values())), flush=True)

        def drive_card(html_text, seconds):
            def drive(page, started):
                page.set_content(html_text)
                while time.time() - started < seconds + 1.5:
                    page.wait_for_timeout(100)
            return drive

        def drive_live(name):
            def drive(page, started):
                open_ui(page, riff)
                play_beats(page, started, lengths[name], beats[name])
            return drive

        drivers = {
            "intro": drive_card(centre("The security scanner", "Passive findings that send nothing, plus an active scan that stays in scope."), lengths["intro"]),
            "passive": drive_live("passive"),
            "active": drive_live("active"),
            "outro": drive_card(centre("That is the scanner", "Passive by default · active scan stays in scope · riff scan for CI · only test what you are authorised to"), lengths["outro"]),
        }

        clips = []
        for name in ORDER:
            clip = WORK / f"{name}.mp4"
            if only and name not in only and clip.exists():
                clips.append(clip)
                continue
            if name in ("passive", "active"):  # findings live in the riff process; seed before the first scene that shows them
                riff.seed()
            webm = record(name, drivers[name], zoom=name not in ("intro", "outro"))
            clips.append(compose(ffmpeg, name, webm, voices[name], lengths[name] + (1.5 if name in ("intro", "outro") else 1.2)))
    finally:
        riff.stop()
        app.shutdown()

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

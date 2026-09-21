"""Render the riff commercial: tutorial/riff-promo.mp4.

A ~4-minute brand film for developers, QA, DevOps and SecOps. Animated title cards and
Ken-Burns moves over the real UI, an American-female voiceover (Edge neural Ava), and a
self-synthesised cinematic bed (gusting wind, distant storm, a soft evolving pad) that ducks
under the narration. Nothing is licensed and nothing but the TTS endpoint is fetched.

    python tutorial/build_promo_video.py
    python tutorial/build_promo_video.py --scenes secure,close --no-concat   # iterate on scenes

Set RIFF_PYTHON if riff's deps live in another interpreter (not needed here — no riff is run).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import html as _html
import sys
import time
from pathlib import Path

import edge_tts
import imageio_ffmpeg
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from build_video import audio_duration, run  # noqa: E402
from promo_audio import make_score  # noqa: E402

ROOT = HERE.parent
SHOTS = ROOT / "docs" / "screenshots"
WORK = HERE / "video-build" / "promo"
OUTPUT = HERE / "riff-promo.mp4"
W, H = 1920, 1080
VIEW = {"width": W, "height": H}
VOICE = "en-US-AvaMultilingualNeural"   # warm American female
RATE = "-3%"
BG = "#05060b"
TAIL = 3.2  # seconds of held frame + music after each line
FADE = 0.5  # dip-to-black between scenes


# ── the look ─────────────────────────────────────────────────────────────────

FONT = "'Segoe UI Variable Display','Segoe UI',Inter,system-ui,sans-serif"
GRAIN = ("data:image/svg+xml;base64," + base64.b64encode(
    b"<svg xmlns='http://www.w3.org/2000/svg' width='160' height='160'>"
    b"<filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2'/>"
    b"<feColorMatrix type='saturate' values='0'/></filter>"
    b"<rect width='100%' height='100%' filter='url(#n)' opacity='0.5'/></svg>").decode())

BASE_CSS = f"""
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
html, body {{ width: {W}px; height: {H}px; overflow: hidden; background: {BG}; font-family: {FONT}; color: #eef1fb; }}
body {{ color: #eef1fb; }}
.stage {{ position: absolute; inset: 0; overflow: hidden; }}
/* animated gradient mesh */
.mesh {{ position: absolute; inset: -20%; filter: blur(60px); opacity: .9; }}
.blob {{ position: absolute; border-radius: 50%; mix-blend-mode: screen; }}
.b1 {{ width: 900px; height: 900px; left: -6%; top: -18%; background: radial-gradient(circle at 40% 40%, #6b4bff, transparent 60%); animation: drift1 26s ease-in-out infinite; }}
.b2 {{ width: 820px; height: 820px; right: -8%; top: 4%; background: radial-gradient(circle at 50% 50%, #b455ff, transparent 62%); animation: drift2 32s ease-in-out infinite; }}
.b3 {{ width: 760px; height: 760px; left: 24%; bottom: -22%; background: radial-gradient(circle at 50% 50%, #2f7bff, transparent 60%); animation: drift3 30s ease-in-out infinite; }}
@keyframes drift1 {{ 0%,100% {{ transform: translate(0,0) scale(1); }} 50% {{ transform: translate(120px,60px) scale(1.15); }} }}
@keyframes drift2 {{ 0%,100% {{ transform: translate(0,0) scale(1.05); }} 50% {{ transform: translate(-90px,80px) scale(1.2); }} }}
@keyframes drift3 {{ 0%,100% {{ transform: translate(0,0) scale(1); }} 50% {{ transform: translate(60px,-70px) scale(1.12); }} }}
/* wind streaks */
.wind {{ position: absolute; inset: 0; overflow: hidden; opacity: .5; }}
.streak {{ position: absolute; height: 1px; width: 46%; left: -50%;
  background: linear-gradient(90deg, transparent, rgba(190,200,255,.55), transparent);
  transform: rotate(-14deg); animation: blow linear infinite; }}
@keyframes blow {{ from {{ transform: translateX(0) rotate(-14deg); }} to {{ transform: translateX(320%) rotate(-14deg); }} }}
/* grain + vignette */
.grain {{ position: absolute; inset: 0; background-image: url('{GRAIN}'); background-size: 320px; opacity: .05; mix-blend-mode: overlay; animation: flick .7s steps(2) infinite; }}
@keyframes flick {{ 0% {{ transform: translate(0,0); }} 100% {{ transform: translate(-8px,6px); }} }}
.vign {{ position: absolute; inset: 0; background: radial-gradient(120% 120% at 50% 45%, transparent 55%, rgba(0,0,0,.72)); }}
.fadein {{ animation: fadein .9s ease both; }}
@keyframes fadein {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
/* kinetic text */
.center {{ position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; padding: 0 8%; }}
.kicker {{ letter-spacing: .5em; text-transform: uppercase; font-size: 22px; color: #9aa6d8; margin-bottom: 26px; opacity: 0; animation: rise .9s ease .15s forwards; }}
h1 {{ font-size: 96px; font-weight: 800; line-height: 1.02; letter-spacing: -.02em; }}
h1 .l {{ display: block; opacity: 0; transform: translateY(26px); filter: blur(10px); animation: rise 1s cubic-bezier(.2,.7,.2,1) forwards; }}
.sub {{ margin-top: 30px; font-size: 34px; color: #c7cdf0; font-weight: 500; opacity: 0; animation: rise 1s ease forwards; }}
.grad {{ background: linear-gradient(92deg,#a78bff,#6bb8ff 60%,#e08bff); -webkit-background-clip: text; background-clip: text; color: transparent; }}
@keyframes rise {{ to {{ opacity: 1; transform: none; filter: blur(0); }} }}
/* the wordmark */
.mark {{ font-size: 220px; font-weight: 800; letter-spacing: -.04em; position: relative; }}
.mark .dot {{ color: #8b6cff; }}
.mark::after {{ content: ''; position: absolute; left: 8%; right: 8%; bottom: 6%; height: 3px;
  background: linear-gradient(90deg, transparent, #8b6cff, transparent); transform: scaleX(0);
  animation: line 1.4s ease .5s forwards; }}
@keyframes line {{ to {{ transform: scaleX(1); }} }}
/* audience chips */
.chips {{ display: flex; gap: 16px; margin-top: 40px; flex-wrap: wrap; justify-content: center; }}
.chip {{ padding: 12px 26px; border: 1px solid rgba(150,160,220,.35); border-radius: 999px; font-size: 26px; color: #d6dbf6;
  background: rgba(120,130,220,.08); opacity: 0; transform: translateY(14px); animation: rise .7s ease forwards; }}
.chip.on {{ border-color: #8b6cff; color: #fff; box-shadow: 0 0 28px rgba(139,108,255,.45); background: rgba(139,108,255,.16); }}
/* device frame for screenshots */
.device {{ position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; }}
.frame {{ width: 74%; aspect-ratio: 16/10; border-radius: 18px; overflow: hidden; position: relative;
  box-shadow: 0 40px 120px rgba(0,0,0,.6), 0 0 0 1px rgba(150,160,230,.18), 0 0 90px rgba(120,90,255,.28);
  background: #0b0e16; opacity: 0; animation: pop 1.1s cubic-bezier(.2,.7,.2,1) forwards; }}
@keyframes pop {{ from {{ opacity: 0; transform: translateY(30px) scale(.97); }} to {{ opacity: 1; transform: none; }} }}
.frame img {{ position: absolute; inset: 0; width: 100%; height: 100%; object-fit: cover; object-position: left top;
  transform: scale(1.06); animation: ken 20s ease-out forwards; }}
@keyframes ken {{ from {{ transform: scale(1.06) translate(0,0); }} to {{ transform: scale(1.16) translate(-2.5%,-2.5%); }} }}
.caption {{ position: absolute; left: 0; right: 0; bottom: 0; padding: 60px 60px 44px;
  background: linear-gradient(0deg, rgba(4,5,11,.96) 30%, rgba(4,5,11,.75) 65%, transparent); }}
.caption .t {{ font-size: 50px; font-weight: 700; letter-spacing: -.01em; max-width: 78%; opacity: 0; animation: rise .8s ease .3s forwards; }}
.caption .d {{ font-size: 27px; line-height: 1.35; color: #c2c9ee; margin-top: 12px; max-width: 62%; opacity: 0; animation: rise .8s ease .5s forwards; }}
.tag {{ position: absolute; top: 34px; right: 40px; padding: 10px 22px; border-radius: 999px; font-size: 24px; font-weight: 600;
  color: #fff; background: rgba(139,108,255,.22); border: 1px solid #8b6cff; box-shadow: 0 0 26px rgba(139,108,255,.4);
  opacity: 0; animation: rise .7s ease .6s forwards; }}
"""


def _scaffold(inner: str, extra_css: str = "") -> str:
    return (f"<!doctype html><html><head><meta charset='utf-8'><style>{BASE_CSS}{extra_css}</style></head>"
            f"<body><div class='stage'><div class='mesh'><div class='blob b1'></div><div class='blob b2'></div>"
            f"<div class='blob b3'></div></div><div class='wind'>{_streaks()}</div>{inner}"
            f"<div class='grain'></div><div class='vign'></div></div></body></html>")


def _streaks() -> str:
    out = []
    for i in range(9):
        top = 8 + i * 10
        dur = 7 + (i % 4) * 2.5
        delay = -(i * 1.7)
        out.append(f"<div class='streak' style='top:{top}%;animation-duration:{dur}s;animation-delay:{delay}s'></div>")
    return "".join(out)


def _lines(text_lines: list[str], base_delay: float = 0.2, step: float = 0.5) -> str:
    spans = []
    for i, ln in enumerate(text_lines):
        spans.append(f"<span class='l' style='animation-delay:{base_delay + i * step:.2f}s'>{ln}</span>")
    return "".join(spans)


def card_hook(lines: list[str], kicker: str = "") -> str:
    k = f"<div class='kicker'>{_html.escape(kicker)}</div>" if kicker else ""
    inner = f"<div class='center'>{k}<h1>{_lines(lines)}</h1></div>"
    return _scaffold(inner)


def card_brand(sub: str) -> str:
    inner = (f"<div class='center'><div class='mark fadein'>ri<span class='dot'>f</span>f</div>"
             f"<div class='sub' style='animation-delay:1.1s'>{_html.escape(sub)}</div></div>")
    return _scaffold(inner)


def card_audiences(title: str, chips: list[str]) -> str:
    ch = "".join(
        f"<div class='chip on' style='animation-delay:{0.5 + i * 0.18:.2f}s'>{_html.escape(c)}</div>"
        for i, c in enumerate(chips))
    inner = (f"<div class='center'><h1 style='font-size:72px'>{_lines([title])}</h1>"
             f"<div class='chips'>{ch}</div></div>")
    return _scaffold(inner)


def card_close(sub: str, cta: str) -> str:
    inner = (f"<div class='center'><div class='mark fadein'>ri<span class='dot'>f</span>f</div>"
             f"<div class='sub' style='animation-delay:1.0s'>{_html.escape(sub)}</div>"
             f"<div class='sub' style='font-size:26px;color:#9aa6d8;margin-top:16px;animation-delay:1.6s'>{_html.escape(cta)}</div></div>")
    return _scaffold(inner)


def shot(img_name: str, title: str, desc: str, tag: str) -> str:
    data = base64.b64encode((SHOTS / f"{img_name}.png").read_bytes()).decode()
    inner = (f"<div class='device'><div class='frame'>"
             f"<img src='data:image/png;base64,{data}'>"
             f"<div class='tag'>{_html.escape(tag)}</div>"
             f"<div class='caption'><div class='t'>{_html.escape(title)}</div>"
             f"<div class='d'>{_html.escape(desc)}</div></div></div></div>")
    return _scaffold(inner)


# ── scenes ───────────────────────────────────────────────────────────────────

SCENES = [
    ("intro", card_hook(["Every app is a conversation.", "<span class='grad'>Most teams never see it.</span>"]),
     "Every app is a conversation. Requests, responses, tokens, errors. Thousands of them, every minute. And most teams never really get to see them."),

    ("brand", card_brand("See it. Shape it. Secure it."),
     "This is riff. One small tool that lets your whole team see, shape, and secure the traffic your applications make."),

    ("problem", card_hook(["A 500 in production.", "A test that fails at random.", "A header nobody can explain."]),
     "A five hundred in production. A test that fails only sometimes. An endpoint that got slow overnight. A header nobody can explain. Whatever you are chasing, the answer is in the traffic."),

    ("see", shot("traffic", "See every request, live", "Method, status, timing, the full decrypted body. Filter by host, status, method or tag.", "Dev · QA"),
     "Point any client at riff, and every request appears the moment it happens. The method, the status, the timing, the full body, decrypted. Filter it by host, by status, by method, by your own tags. It is the whole conversation, live."),

    ("inspect", shot("detail-response", "Read it in full", "Headers, cookies, a pretty-printed body, and the exact bytes on the wire. Nothing hidden.", "Dev · QA"),
     "Click any request and read it in full. The headers, the cookies, a pretty-printed body, and when framing is the problem, the exact bytes that crossed the wire. Nothing is hidden from you."),

    ("shape", shot("rules", "Rewrite, mock, redact — live", "A tiny, safe rule language. Changes take effect on the very next request. No restart.", "Dev"),
     "Then shape it. A small, safe rule language rewrites a header, mocks a response before the backend even exists, redacts a secret, tags the slow ones. And it takes effect on the very next request. Nothing restarts."),

    ("mock", shot("detail-mocked", "Mock what isn't built yet", "Answer a request from a rule, before the backend exists — so the front end never waits.", "Dev · QA"),
     "The backend not ready? Answer the request from a rule, and the front end stops waiting. Build and test against a response that behaves exactly how you need it to, long before the real thing ships."),

    ("compose", shot("compose", "An API client, built in", "Build a request, send it, save it into collections your whole team shares. Import and export the portable v2.1 format.", "QA"),
     "Need to send a request by hand? Compose is a full API client built right in. Build it, send it, and save it into collections your whole team shares as plain files. Import and export the portable collection format, so nobody has to leave their tools."),

    ("secure", shot("findings", "A security scanner, built in", "Passive checks flag misconfigurations for free, sending nothing of their own.", "SecOps"),
     "And riff secures it. A full scanner is built in. While you simply browse, passive checks read the responses riff already captured and flag missing security headers, weak cookies, cleartext credentials, version banners and secrets in a body. It sends nothing of its own. The findings are just there, waiting, by the time you go looking."),

    ("scan", shot("findings", "Then go looking, on purpose", "Reflected XSS, SQL injection, path traversal, open redirects and blind SSRF \u2014 every probe re-checked against your scope.", "SecOps"),
     "When you want to go further, the active scan does. It injects into every parameter it captured and finds reflected cross-site scripting, SQL injection, path traversal, open redirects and blind server-side request forgery, out of band. And it is safe by construction: you name the hosts you are authorised to test, and every single probe re-checks its target against that list before the socket opens. Every finding links straight to the request that proved it, and the same scan runs headless and writes a report."),

    ("share", shot("ext-traffic", "Runs anywhere. Shares everything.", "One file, no install. Capture your own Chrome. Export to HAR or a portable collection in a click.", "DevOps"),
     "And it goes everywhere your team goes. It is a single file with no install, it captures the Chrome you already use, and it exports to HAR or a portable collection in a single click. One small tool, on every machine."),

    ("audiences", card_audiences("Built for the whole request.", ["Developers", "QA", "DevOps", "SecOps"]),
     "For the developers who build it. For the QA engineers who test it. For the DevOps and SRE teams who ship it. And for the security teams who protect it."),

    ("close", card_close("See it. Shape it. Secure it.", "riff · github.com/yamazed/riff"),
     "One tool for the whole request. riff. See it. Shape it. Secure it."),
]


# ── plumbing ─────────────────────────────────────────────────────────────────

async def narrate(name: str, text: str) -> Path:
    path = WORK / f"{name}.mp3"
    if not path.exists():
        import ssl

        import edge_tts.communicate as cm

        try:
            import truststore

            cm._SSL_CTX = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except ImportError:
            pass
        print(f"voice  {name}", flush=True)
        await edge_tts.Communicate(text, VOICE, rate=RATE).save(str(path))
    return path


def record(name: str, html_text: str, seconds: float) -> Path:
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", args=["--hide-scrollbars", "--force-color-profile=srgb"])
        context = browser.new_context(viewport=VIEW, device_scale_factor=1, color_scheme="dark",
                                      record_video_dir=str(WORK / "raw"), record_video_size={"width": W, "height": H})
        page = context.new_page()
        page.set_content(html_text, wait_until="load")
        started = time.time()
        while time.time() - started < seconds:
            page.wait_for_timeout(80)
        video = page.video
        context.close()
        browser.close()
        raw = Path(video.path())
    dest = WORK / f"{name}.webm"
    if dest.exists():
        dest.unlink()
    raw.rename(dest)
    return dest


def clip(ffmpeg: str, name: str, webm: Path, mp3: Path, seconds: float) -> Path:
    out = WORK / f"{name}.mp4"
    fo = max(0.0, seconds - FADE)
    run([ffmpeg, "-y", "-i", str(webm), "-i", str(mp3), "-filter_complex",
         f"[0:v]scale={W}:{H}:force_original_aspect_ratio=decrease,pad={W}:{H}:(ow-iw)/2:(oh-ih)/2:color={BG},"
         f"fps=30,format=yuv420p,fade=t=in:st=0:d={FADE},fade=t=out:st={fo:.2f}:d={FADE}[v];"
         f"[1:a]adelay=650|650,apad=whole_dur={seconds:.2f}[a]",
         "-map", "[v]", "-map", "[a]", "-t", f"{seconds:.2f}", "-c:v", "libx264", "-preset", "medium", "-crf", "19",
         "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart", str(out)])
    print(f"clip   {name}  {seconds:.1f}s", flush=True)
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenes", default="")
    parser.add_argument("--no-concat", action="store_true")
    args = parser.parse_args()
    only = {s.strip() for s in args.scenes.split(",") if s.strip()}

    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "raw").mkdir(exist_ok=True)
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()

    voices = {name: asyncio.run(narrate(name, vo)) for name, _html, vo in SCENES}
    lengths = {name: audio_duration(ffmpeg, path) for name, path in voices.items()}
    durations = {name: round(lengths[name] + TAIL, 2) for name, _h, _v in SCENES}
    print("scene seconds:", durations, "total", round(sum(durations.values())), flush=True)

    clips = []
    starts = {}
    running = 0.0
    for name, html_text, _vo in SCENES:
        starts[name] = running
        running += durations[name]
        out = WORK / f"{name}.mp4"
        if only and name not in only and out.exists():
            clips.append(out)
            continue
        webm = record(name, html_text, durations[name])
        clips.append(clip(ffmpeg, name, webm, voices[name], durations[name]))

    if args.no_concat:
        print("clips:", [c.name for c in clips])
        return 0

    # Concatenate the narration clips.
    listing = WORK / "concat.txt"
    listing.write_text("".join(f"file '{c.as_posix()}'\n" for c in clips), encoding="utf-8")
    silent = WORK / "promo-narrated.mp4"
    run([ffmpeg, "-y", "-f", "concat", "-safe", "0", "-i", str(listing), "-c", "copy", "-movflags", "+faststart", str(silent)])
    total = audio_duration(ffmpeg, silent)

    # A cinematic score: a title sting up front, a warm resolve at the end, the body left clear.
    marks = {
        "reveal": starts["brand"] + 1.5,          # logo reveal / first impact
        "intro_fade": starts["problem"] + 1.0,    # intro music gone once the film gets to work
        "outro_start": starts["audiences"],       # swell back in for the close
        "close": starts["close"] + 0.6,           # final resolve / impact
    }
    score = WORK / "score.wav"
    make_score(total, str(score), marks)

    # Mix: score ducks under the voiceover (sidechain). Everything is resampled to stereo
    # 44.1 kHz so the master is not stuck at the TTS's mono 24 kHz.
    run([ffmpeg, "-y", "-i", str(silent), "-i", str(score), "-filter_complex",
         "[0:a]aresample=44100,aformat=channel_layouts=stereo[nar];"
         "[1:a]aresample=44100,aformat=channel_layouts=stereo,volume=0.85[sc];"
         "[sc][nar]sidechaincompress=threshold=0.03:ratio=8:attack=8:release=400[scd];"
         "[nar][scd]amix=inputs=2:duration=first:normalize=0,alimiter=limit=0.95[a]",
         "-map", "0:v", "-map", "[a]", "-c:v", "copy", "-c:a", "aac", "-b:a", "224k",
         "-ar", "44100", "-ac", "2", "-movflags", "+faststart", str(OUTPUT)])
    print(f"wrote {OUTPUT} ({OUTPUT.stat().st_size / 1024 / 1024:.1f} MB, {audio_duration(ffmpeg, OUTPUT):.0f} s)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

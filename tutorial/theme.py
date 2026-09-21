"""Shared look for the narrated tour videos.

The palette, the frame size and the slide CSS that `build_compose_video.py`
and `build_scanner_video.py` both render their title cards and terminals with.
Kept here so the two tours stay visually identical.
"""

BG = "#070a10"
W, H = 1920, 1080

CSS = """
  :root { --bg: #070a10; --ink: #e6ebf4; --dim: #7b879c; --cmd: #c9d4ff; --accent: #8b7cf6; --ok: #3fc27a; --warn: #e0a83a; }
  html, body { margin: 0; height: 100%; background: var(--bg); color: var(--ink);
    font-family: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif; }
  .stage { position: absolute; inset: 0; display: grid; place-items: center; }
  .term { width: 1560px; height: 820px; box-sizing: border-box; padding: 34px 40px; border-radius: 14px;
    background: radial-gradient(120% 90% at 50% 0%, #131a26 0%, #0b0f17 60%); color: var(--ink);
    font-family: "IBM Plex Mono", Consolas, monospace; font-size: 26px; line-height: 1.6; overflow: hidden;
    box-shadow: 0 30px 80px rgba(0,0,0,.6); }
  .bar { display: flex; gap: 10px; align-items: center; color: var(--dim); font-size: 20px; margin-bottom: 22px; }
  .dot { width: 14px; height: 14px; border-radius: 50%; background: #2a3444; }
  .title { margin-left: 10px; }
  .p { color: var(--dim); user-select: none; }
  .c { color: var(--cmd); font-weight: 500; }
  .o { color: var(--ink); white-space: pre-wrap; }
  .ok { color: var(--ok); } .warn { color: var(--warn); }
  .cursor { display: inline-block; width: 14px; height: 30px; background: var(--cmd); vertical-align: -6px;
    animation: blink 1s steps(1) infinite; }
  @keyframes blink { 50% { opacity: 0; } }
  .card { width: 1560px; padding: 60px 70px; box-sizing: border-box; border-radius: 16px; background: #0f1520;
    box-shadow: 0 30px 80px rgba(0,0,0,.6); }
  .kicker { color: var(--accent); font-weight: 700; letter-spacing: .12em; font-size: 22px; text-transform: uppercase; }
  h1 { font-size: 64px; margin: 10px 0 24px; line-height: 1.1; }
  ol { font-size: 32px; line-height: 1.5; color: var(--ink); padding-left: 40px; margin: 0; }
  ol li { margin: 12px 0; }
  ol b { color: #fff; }
  .shots { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 22px; margin-top: 30px; }
  .shots img { width: 100%; border-radius: 10px; border: 1px solid #263042; }
  .center { text-align: center; }
  .center h1 { font-size: 78px; }
  .center p { font-size: 34px; color: var(--dim); max-width: 1200px; margin: 0 auto; line-height: 1.5; }
"""

"""Rebuild tutorial/riff-walkthrough.html from its template and media.

    python tutorial/build.py                 # linked: a small page next to its media (default)
    python tutorial/build.py --standalone    # also write riff-walkthrough-standalone.html with everything inlined
    python tutorial/build.py --video-base URL   # resolve the tour videos to URL/<name>.mp4

The linked page references the screenshots, narration and videos by relative path, so it opens from
the repo by double-clicking (file:// allows media subresources) and stays under a
megabyte; the media sits next to it in the repo. The standalone variant
inlines everything as data URIs for the one case where the HTML travels on its own, e.g. by email.

The tour videos are tens of megabytes and are published as release assets rather than committed, so
`--video-base` points the page at them instead of at a local file. That is how the GitHub Pages copy
is built:

    python tutorial/build.py --video-base https://github.com/yamazed/riff/releases/latest/download
"""
import base64, json, pathlib, re, sys

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import lipsync  # noqa: E402
shots = here.parent / "docs" / "screenshots"
narration = here / "narration" / "ryan"
tpl = (here / "walkthrough.template.html").read_text(encoding="utf-8")
argv = sys.argv[1:]
standalone = "--standalone" in argv
video_base = ""
if "--video-base" in argv:
    video_base = argv[argv.index("--video-base") + 1].rstrip("/")

MIME = {".png": "image/png", ".mp4": "video/mp4", ".mp3": "audio/mpeg"}


def data_uri(path: pathlib.Path) -> str:
    return f"data:{MIME[path.suffix]};base64," + base64.b64encode(path.read_bytes()).decode()


def _ffmpeg() -> str | None:
    try:
        import imageio_ffmpeg

        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:
        return None


def render(inline: bool) -> str:
    missing = []

    def img(m):
        p = shots / f"{m.group(1)}.png"
        if not p.exists():
            missing.append(p.name)
            return ""
        return data_uri(p) if inline else f"../docs/screenshots/{p.name}"

    def video(m):
        p = here / f"{m.group(1)}.mp4"
        # With a base URL the video is fetched from there (a release asset), so the
        # local file only has to exist when we are inlining or linking to it.
        if video_base and not inline:
            return f"{video_base}/{p.name}"
        if not p.exists():
            missing.append(f"{p.name} (build it with tutorial/build_compose_video.py or build_scanner_video.py)")
            return ""
        return data_uri(p) if inline else p.name

    out = re.sub(r"\{\{IMG:([a-z-]+)\}\}", img, tpl)
    out = re.sub(r"\{\{VIDEO:([a-z-]+)\}\}", video, out)
    if missing:
        sys.exit("missing media: " + ", ".join(missing))
    tracks = sorted(narration.glob("*.mp3"))
    audio = [data_uri(p) if inline else f"narration/ryan/{p.name}" for p in tracks]
    out = out.replace("{{RYAN_AUDIO}}", json.dumps(audio, separators=(",", ":")))
    ffmpeg = _ffmpeg()
    mouth = [lipsync.voiced_ranges(p, ffmpeg) for p in tracks] if ffmpeg else []
    out = out.replace("{{MOUTH}}", json.dumps(mouth, separators=(",", ":")))
    return out, len(tracks)


def write(name: str, inline: bool) -> None:
    out, tracks = render(inline)
    dest = here / name
    dest.write_text(out, encoding="utf-8")
    how = "inlined" if inline else "linked"
    shots_n, videos_n = len(re.findall(r"\{\{IMG:", tpl)), len(re.findall(r"\{\{VIDEO:", tpl))
    print(f"wrote {dest.name}  {dest.stat().st_size / 1024 / 1024:.2f} MB, "
          f"{shots_n} screenshots, {videos_n} video(s) and {tracks} narration tracks {how}")


write("riff-walkthrough.html", inline=False)
if standalone:
    write("riff-walkthrough-standalone.html", inline=True)

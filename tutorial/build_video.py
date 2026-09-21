"""Render the interactive riff walkthrough as a narrated MP4.

    python tutorial/build_video.py

The build uses Chrome for deterministic scene captures, Edge neural TTS for
narration, and the FFmpeg binary bundled by imageio-ffmpeg for composition.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import shutil
import ssl
import subprocess
import sys
from pathlib import Path

import edge_tts
import imageio_ffmpeg
import truststore
from playwright.sync_api import sync_playwright


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lipsync  # noqa: E402

HTML = HERE / "riff-walkthrough.html"
WORK = HERE / "video-build"
NARRATION = HERE / "narration" / "ryan"
DEFAULT_OUTPUT = HERE / "riff-walkthrough-ryan.mp4"
VOICE = "en-US-AndrewNeural"
RATE = "-4%"


def run(command: list[str]) -> None:
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())


def audio_duration(ffmpeg: str, path: Path) -> float:
    result = subprocess.run([ffmpeg, "-i", str(path)], text=True, capture_output=True)
    match = re.search(r"Duration: (\d+):(\d+):(\d+(?:\.\d+)?)", result.stderr)
    if not match:
        raise RuntimeError(f"could not read duration of {path.name}")
    hours, minutes, seconds = match.groups()
    return int(hours) * 3600 + int(minutes) * 60 + float(seconds)


def mouth_expression(ffmpeg: str, path: Path) -> str:
    # The interactive page and the MP4 flap the jaw from the same syllable-level ranges (tutorial/lipsync.py),
    # so the presenter's mouth matches the words the same way in both.
    return lipsync.between_expr(lipsync.voiced_ranges(path, ffmpeg))


async def render_voiceovers(steps: list[dict[str, str]], audio_dir: Path, force: bool) -> None:
    import edge_tts.communicate as communicate_module

    communicate_module._SSL_CTX = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    for index, step in enumerate(steps, 1):
        destination = audio_dir / f"{index:02}.mp3"
        if destination.exists() and destination.stat().st_size and not force:
            continue
        print(f"voice {index:02}/{len(steps)}  {step['title']}")
        for attempt in range(4):  # the Edge TTS endpoint occasionally returns no audio through Zscaler; retry
            try:
                await edge_tts.Communicate(step["voiceover"], VOICE, rate=RATE).save(str(destination))
                break
            except Exception:
                if attempt == 3:
                    raise
                await asyncio.sleep(2)


def capture_scenes(steps: list[dict[str, str]], frame_dir: Path, force: bool) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", args=["--hide-scrollbars"])
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            color_scheme="dark",
            reduced_motion="reduce",
            device_scale_factor=1,
        )
        page = context.new_page()
        page.goto(HTML.as_uri(), wait_until="load")
        page.evaluate("document.fonts.ready")
        page.add_style_tag(
            content="""
                body { background: #070a10; }
                /* In the MP4 a video step is a still poster (an 18:11 screenshot), so keep the box 18:11
                   here even though the live page switches it to the video's 16:9. */
                .screen.is-video { aspect-ratio: 18 / 11 !important; }
                .wrap { max-width: 1720px; padding: 0; }
                .mast, .chapters, section.sec, footer { display: none !important; }
                .player { grid-template-columns: minmax(0, 1fr) 500px; border-radius: 8px; }
                                .narr { padding: 34px; position: relative; }
                                .narr .part, .narr h2 { max-width: 300px; }
                                .narr h2 { font-size: 2rem; }
                .narr .say { font-size: 1.15rem; }
                .term { font-size: 15px; }
                .voice .sel { display: none; }
                #voiceBtn { pointer-events: none; }
                                .presenter-portrait {
                                    width: 88px; height: 88px; margin: 0 auto 5px; overflow: hidden;
                                }
            """
        )
        page.evaluate(
            """
            () => {
                document.getElementById('playBtn').setAttribute('aria-pressed', 'true');
                document.getElementById('iconPlay').hidden = true;
                document.getElementById('iconPause').hidden = false;
                document.getElementById('playLbl').textContent = 'Playing';
                document.getElementById('voiceLbl').textContent = 'Andrew voice';
            }
            """
        )
        for index, step in enumerate(steps, 1):
            destination = frame_dir / f"{index:02}.png"
            speaking_destination = frame_dir / f"{index:02}-speaking.png"
            if (
                destination.exists()
                and destination.stat().st_size
                and speaking_destination.exists()
                and speaking_destination.stat().st_size
                and not force
            ):
                continue
            print(f"frame {index:02}/{len(steps)}  {step['title']}")
            page.evaluate("step => window.__riffTour.showStep(step)", index - 1)
            page.wait_for_timeout(350)
            page.locator(".presenter").evaluate("element => element.classList.remove('is-speaking')")
            page.locator("#player").screenshot(path=str(destination))
            page.locator(".presenter").evaluate("element => element.classList.add('is-speaking')")
            page.locator("#player").screenshot(path=str(speaking_destination))
        context.close()
        browser.close()


def compose_video(
    ffmpeg: str,
    steps: list[dict[str, str]],
    frame_dir: Path,
    audio_dir: Path,
    segment_dir: Path,
    output: Path,
    force: bool,
) -> None:
    segment_paths: list[Path] = []
    for index, step in enumerate(steps, 1):
        frame = frame_dir / f"{index:02}.png"
        speaking_frame = frame_dir / f"{index:02}-speaking.png"
        audio = audio_dir / f"{index:02}.mp3"
        segment = segment_dir / f"{index:02}.mp4"
        segment_paths.append(segment)
        newest_input = max(frame.stat().st_mtime, speaking_frame.stat().st_mtime, audio.stat().st_mtime)
        if segment.exists() and segment.stat().st_size and segment.stat().st_mtime >= newest_input and not force:
            continue

        duration = audio_duration(ffmpeg, audio) + 0.65
        fade_out = max(0, duration - 0.25)
        mouth_open = mouth_expression(ffmpeg, audio)
        video_filter = (
            f"[0:v][1:v]overlay=enable='gt({mouth_open},0)',"
            "scale=1920:1080:force_original_aspect_ratio=decrease,"
            "pad=1920:1080:(ow-iw)/2:(oh-ih)/2:color=#070a10,"
            "zoompan=z='min(zoom+0.00006,1.025)':d=1:s=1920x1080:fps=30,"
            f"fade=t=in:st=0:d=0.25,fade=t=out:st={fade_out:.3f}:d=0.25[v]"
        )
        print(f"clip  {index:02}/{len(steps)}  {step['title']}")
        run(
            [
                ffmpeg,
                "-y",
                "-loop",
                "1",
                "-framerate",
                "30",
                "-i",
                str(frame),
                "-loop",
                "1",
                "-framerate",
                "30",
                "-i",
                str(speaking_frame),
                "-i",
                str(audio),
                "-filter_complex",
                video_filter,
                "-map",
                "[v]",
                "-map",
                "2:a:0",
                "-af",
                "apad=pad_dur=0.65",
                "-t",
                f"{duration:.3f}",
                "-c:v",
                "libx264",
                "-preset",
                "medium",
                "-crf",
                "20",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                "-b:a",
                "192k",
                str(segment),
            ]
        )

    concat_file = segment_dir / "concat.txt"
    concat_file.write_text(
        "".join(f"file '{path.resolve().as_posix()}'\n" for path in segment_paths),
        encoding="utf-8",
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            ffmpeg,
            "-y",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            str(concat_file),
            "-c",
            "copy",
            "-movflags",
            "+faststart",
            str(output),
        ]
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, help="render only the first N scenes")
    parser.add_argument("--force", action="store_true", help="rebuild cached assets")
    parser.add_argument("--clean", action="store_true", help="remove cached assets first")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.clean and WORK.exists():
        shutil.rmtree(WORK)
    audio_dir = NARRATION
    frame_dir = WORK / "frames"
    segment_dir = WORK / "segments"
    for directory in (audio_dir, frame_dir, segment_dir):
        directory.mkdir(parents=True, exist_ok=True)

    run([sys.executable, str(HERE / "build.py")])
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome")
        page = browser.new_page()
        page.goto(HTML.as_uri(), wait_until="load")
        steps = page.evaluate("window.__riffTour.steps")
        browser.close()
    if args.limit:
        steps = steps[: args.limit]
    if not steps:
        raise RuntimeError("the walkthrough contains no scenes")

    asyncio.run(render_voiceovers(steps, audio_dir, args.force))
    run([sys.executable, str(HERE / "build.py")])
    capture_scenes(steps, frame_dir, args.force)
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    compose_video(
        ffmpeg,
        steps,
        frame_dir,
        audio_dir,
        segment_dir,
        args.output.resolve(),
        args.force,
    )
    size_mb = args.output.resolve().stat().st_size / 1024 / 1024
    print(f"wrote {args.output.resolve()} ({size_mb:.1f} MB, {len(steps)} scenes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
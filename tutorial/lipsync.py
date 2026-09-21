"""Shared lip-sync: turn a narration track into open-mouth time ranges.

Both the interactive page (build.py, embedded as MOUTH) and the MP4 (build_video.py) drive the
presenter's jaw from these ranges, so the mouth flaps the same way in both. The mouth is two states,
open or shut, so to read as speech it must flap on syllables: the amplitude envelope is thresholded
against its own local average, which opens the jaw on each above-average pulse (roughly a syllable)
and shuts it in the troughs between, regardless of how loud the passage is overall. An absolute floor
keeps it shut through silence. The old code merged voiced spans into long opens, so the jaw hung open
for whole phrases and looked out of sync; this does not.
"""

from __future__ import annotations

import array
import math
import subprocess
from pathlib import Path

SAMPLE_RATE = 8000
WINDOW = 0.040          # seconds per amplitude window: a fast syllable is ~5-6 of these
_BASELINE_RADIUS = 3    # windows each side for the local average (~0.3 s span)
_OPEN_FACTOR = 1.0      # open when the window is at/above its local average
_FLOOR_FRAC = 0.05      # ... and above this fraction of the track's peak (kills silence)
_FLOOR_ABS = 220.0


def _levels(path: Path, ffmpeg: str) -> list[float]:
    result = subprocess.run(
        [ffmpeg, "-v", "error", "-i", str(path), "-f", "s16le", "-ac", "1", "-ar", str(SAMPLE_RATE), "-"],
        capture_output=True,
    )
    if result.returncode:
        return []
    samples = array.array("h")
    samples.frombytes(result.stdout)
    win = round(SAMPLE_RATE * WINDOW)
    levels: list[float] = []
    for start in range(0, len(samples), win):
        chunk = samples[start : start + win]
        if chunk:
            levels.append(math.sqrt(sum(s * s for s in chunk) / len(chunk)))
    return levels


def voiced_ranges(path: Path, ffmpeg: str) -> list[float]:
    """Open-mouth ranges as a flat [s0, e0, s1, e1, ...] list of seconds, flapping per syllable."""
    levels = _levels(Path(path), ffmpeg)
    if not levels:
        return []
    peak = max(levels)
    floor = max(_FLOOR_ABS, peak * _FLOOR_FRAC)
    prefix = [0.0]
    for level in levels:
        prefix.append(prefix[-1] + level)

    def baseline(i: int) -> float:
        a, b = max(0, i - _BASELINE_RADIUS), min(len(levels), i + _BASELINE_RADIUS + 1)
        return (prefix[b] - prefix[a]) / (b - a)

    is_open = [levels[i] > floor and levels[i] >= baseline(i) * _OPEN_FACTOR for i in range(len(levels))]
    # Bridge single-window dips inside speech so the jaw does not chatter frame-to-frame, but keep the
    # real inter-syllable closes that make it read as talking.
    for i in range(1, len(is_open) - 1):
        if not is_open[i] and is_open[i - 1] and is_open[i + 1]:
            is_open[i] = True

    hang = WINDOW * 0.5
    spans: list[list[float]] = []
    for i, on in enumerate(is_open):
        if not on:
            continue
        start_t, end_t = i * WINDOW, (i + 1) * WINDOW + hang
        if spans and start_t - spans[-1][1] <= WINDOW * 0.5:
            spans[-1][1] = end_t
        else:
            spans.append([start_t, end_t])

    flat: list[float] = []
    for start_t, end_t in spans:
        flat.append(round(start_t, 2))
        flat.append(round(end_t, 2))
    return flat


def between_expr(ranges: list[float]) -> str:
    """The ffmpeg timeline expression that is > 0 exactly inside the open ranges."""
    if not ranges:
        return "0"
    return "+".join(f"between(t,{ranges[i]:.2f},{ranges[i + 1]:.2f})" for i in range(0, len(ranges), 2))

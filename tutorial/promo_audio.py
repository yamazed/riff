"""Synthesize a royalty-free cinematic score for the promo: a title sting up front and a
resolving outro at the end, with the middle left clean for the voiceover.

`make_score(total, path, marks)` writes a stereo 44.1 kHz WAV of length `total`. It builds a
rising intro that lands on a deep impact and a bright major-9 chord at the logo reveal, holds and
fades as the film gets to work, stays essentially silent through the body, then swells back for a
warm resolve and a final soft impact at the close. Everything is generated from sine tones and
noise with numpy, so nothing is licensed and nothing is fetched.
"""

from __future__ import annotations

import wave
from pathlib import Path

import numpy as np

SR = 44100
# A bright, hopeful D major-9: D3 F#3 A3 C#4 E4, plus a low D2 for weight on the resolve.
CHORD = [146.83, 185.00, 220.00, 277.18, 329.63]
LOW_D = 73.42
RNG = np.random.default_rng(11)


def _norm(x, peak=0.9):
    m = np.max(np.abs(x)) or 1.0
    return x / m * peak


def _lowpass(x, cutoff_hz):
    win = max(1, int(SR / max(cutoff_hz, 1.0)))
    if win <= 1:
        return x.astype(float)
    c = np.cumsum(np.insert(x.astype(float), 0, 0.0))
    y = (c[win:] - c[:-win]) / win
    if y.size < x.size:
        y = np.concatenate([y, np.full(x.size - y.size, y[-1] if y.size else 0.0)])
    return y


def _swell(n, attack, release):
    env = np.ones(n)
    a = min(int(attack * SR), n)
    r = min(int(release * SR), n - a)
    if a:
        env[:a] = np.sin(np.linspace(0, np.pi / 2, a)) ** 2   # ease-in
    if r:
        env[n - r:] = np.cos(np.linspace(0, np.pi / 2, r)) ** 2  # ease-out
    return env


def _pad(dur, freqs, attack, release, shimmer=0.25):
    n = int(dur * SR)
    t = np.arange(n) / SR
    tone = np.zeros(n)
    for i, f in enumerate(freqs):
        detune = 1 + 0.0012 * np.sin(2 * np.pi * (0.08 + 0.011 * i) * t)
        weight = 0.85 ** i
        tone += np.sin(2 * np.pi * f * detune * t) * weight
        if shimmer:
            tone += shimmer * np.sin(2 * np.pi * 2 * f * detune * t) * weight
    return _norm(tone) * _swell(n, attack, release)


def _impact(dur=2.2):
    n = int(dur * SR)
    t = np.arange(n) / SR
    freq = 40 + 55 * np.exp(-5 * t)            # sub with a fast downward pitch drop
    phase = 2 * np.pi * np.cumsum(freq) / SR
    boom = np.sin(phase) * np.exp(-t * 4.0)
    thump = np.sin(2 * np.pi * 95 * t) * np.exp(-t * 9) * 0.5
    click = _lowpass(RNG.standard_normal(n), 5000) * np.exp(-t * 32) * 0.35
    return _norm(boom + thump + click)


def _riser(dur=4.0):
    n = int(dur * SR)
    t = np.arange(n) / SR
    x = t / dur
    air = _lowpass(RNG.standard_normal(n), 3200) * 0.6
    freq = 180 + 620 * x                        # rising glissando
    sweep = np.sin(2 * np.pi * np.cumsum(freq) / SR) * 0.4
    return _norm(air + sweep) * (x ** 2)        # crescendo into the impact


def _place(master, clip, at_s, gain=1.0):
    start = int(at_s * SR)
    end = min(start + clip.size, master.size)
    if start >= master.size or end <= start:
        return
    master[start:end] += clip[: end - start] * gain


def make_score(total, path, marks=None):
    marks = marks or {}
    reveal = float(marks.get("reveal", 15.5))       # logo reveal / first impact
    intro_fade = float(marks.get("intro_fade", 26.0))  # intro music gone by here
    outro_start = float(marks.get("outro_start", max(0.0, total - 24.0)))
    close = float(marks.get("close", max(0.0, total - 9.0)))  # final resolve / impact

    n = int((total + 1.0) * SR)
    master = np.zeros(n)

    # ── intro: a low bed rising, a riser into a deep impact and a bright chord ──
    _place(master, _pad(intro_fade, [LOW_D, CHORD[0]], attack=2.5, release=6.0, shimmer=0.0) * 0.35, 0.0)
    _place(master, _riser(4.0), max(0.0, reveal - 4.0), gain=0.7)
    _place(master, _impact(2.4), reveal, gain=1.0)
    _place(master, _pad(1.2, CHORD, attack=0.02, release=1.1) * 0.9, reveal)            # bright hit
    hold = max(3.0, intro_fade - reveal - 0.5)
    _place(master, _pad(hold, CHORD, attack=0.15, release=hold * 0.7) * 0.6, reveal + 0.4)  # sustain, fades out

    # ── body: intentionally clear for the voiceover (a whisper-quiet low drone only) ──
    body_len = max(0.0, outro_start - intro_fade)
    if body_len > 1.0:
        _place(master, _pad(body_len, [LOW_D], attack=3.0, release=3.0, shimmer=0.0) * 0.05, intro_fade)

    # ── outro: a warm swell that resolves, a final soft impact, a tail ──
    outro_len = max(4.0, total - outro_start)
    _place(master, _pad(outro_len, CHORD, attack=3.5, release=3.0) * 0.5, outro_start)
    _place(master, _impact(2.6), close, gain=0.85)
    tail = max(3.0, total - close + 1.0)
    _place(master, _pad(tail, [LOW_D] + CHORD, attack=0.05, release=tail * 0.75) * 0.7, close)

    master = _norm(master, peak=0.85)

    # stereo width + master fades
    delay = int(0.011 * SR)
    left = master.copy()
    right = np.empty_like(master)
    right[:delay] = master[:delay]
    right[delay:] = 0.85 * master[delay:] + 0.15 * master[:-delay]
    f = int(1.5 * SR)
    ramp = np.linspace(0, 1, f)
    for ch in (left, right):
        ch[:f] *= ramp
        ch[-f:] *= ramp[::-1]

    pcm = (np.clip(np.stack([left, right], axis=1), -1, 1) * 32767).astype(np.int16)
    out = Path(path)
    with wave.open(str(out), "w") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(pcm.tobytes())
    return out


if __name__ == "__main__":
    make_score(40.0, "promo-score-test.wav", {"reveal": 15.5, "intro_fade": 26.0, "outro_start": 20.0, "close": 32.0})
    print("wrote promo-score-test.wav")

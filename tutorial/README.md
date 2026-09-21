# riff walkthrough

`riff-walkthrough.html` is an interactive, video-style tour of installing and
using riff: 31 steps with the real UI screenshots, autoplay grouped by part so a reader can take one
category at a time, a written transcript, the client-proxy table, and a shot list with voice-over text for
anyone who wants to record it as an actual video. Two steps are videos rather than screenshots: the
two-and-a-half-minute security scanner tour (`riff-scanner-tour.mp4`) sits in Part 2 and the
seven-minute Compose tour (`riff-compose-tour.mp4`) closes Part 4. Both are embedded in the page, autoplay
parks on them, and playing one pauses the tour.

Too small? **Theater** (or the `t` key) gives the screen the whole page width, and
**Fullscreen** (`f`) puts just the screen on the display. The MP4 is 1080p; use the
video player's own full-screen button.

Press Play and the page reads each step aloud using the embedded Andrew American
English neural narration. The exact same tracks are used by the MP4 export, so
playback does not depend on which voices the browser has installed. Narration
can be turned on or off from the control bar.

Open it by double-clicking it.

The page itself is small: screenshots, narration and the two videos are
linked by relative path from `docs/screenshots`, `tutorial/narration/ryan` and
`tutorial/`, so it works from the
share or a repo checkout and loads each step's media on demand. Fonts load from
Google Fonts when online and fall back to system faces offline; nothing else is
fetched. If the HTML has to travel on its own (say, by email), build the
inlined variant: `python tutorial/build.py --standalone` writes
`riff-walkthrough-standalone.html` with everything embedded (about 42 MB).

## Rebuilding

The page is generated from `walkthrough.template.html` plus the PNGs in
`docs/screenshots`. After regenerating screenshots with
`packaging/shoot-docs.py` and `packaging/shoot-extension.py`, run:

    python tutorial/build.py                # linked page (default)
    python tutorial/build.py --standalone   # plus the single-file variant

Edit step text, commands or callout positions in the `STEPS` array near the
bottom of the template, then rebuild. Callout rings are `[left, top, width,
height]` as percentages of the 2880x1760 capture.

`build.py` also precomputes the presenter's mouth timing from each narration
track (voiced spans, via ffmpeg from `imageio-ffmpeg`) and embeds it as `MOUTH`,
so on the interactive page the jaw follows the actual words rather than a fixed
rhythm — on any protocol, `file://` included. If `imageio-ffmpeg` is absent the
page falls back to the old rhythm. After changing a track's audio, just rebuild.

## Narrated video

The walkthrough can also be exported as a 1080p MP4 narrated by the same Andrew
American English neural tracks embedded in the HTML. The renderer captures the
real player in Chrome, adds an illustrated presenter with speaking
animation, subtle camera movement, and scene fades, then combines the frames
with the generated narration. The presenter appears only in the MP4; the
interactive walkthrough keeps the full sidebar available for text and commands.

Install the optional tooling and build the video:

    python -m pip install -e ".[video]"
    python tutorial/build_video.py

The result is `tutorial/riff-walkthrough-ryan.mp4`. Canonical narration lives
under `tutorial/narration/ryan`; intermediate frames and clips are cached under
`tutorial/video-build`. Pass `--force` to regenerate narration and `--clean` to
remove cached render assets after changing the walkthrough. Frames and clips
are cached by step number, so after inserting or reordering a step always
rebuild with `--clean`, and shift the `NN.mp3` narration files from the
insertion point upwards first.

## The commercial

`tutorial/riff-promo.html` is a branded landing page that plays `riff-promo.mp4`, a ~4-minute
brand film pitching riff to developers, QA, DevOps and SecOps. Share the HTML page rather than the
bare MP4: it carries the poster, the tagline, per-audience value props, a feature list and a link
into the walkthrough. `tutorial/build_promo_video.py` renders the film — animated title cards and
Ken-Burns moves over the real UI screenshots, an American-female neural voiceover (Ava), and a
self-synthesised cinematic bed (gusting wind, distant storm and a soft pad, from
`tutorial/promo_audio.py`) that ducks under the narration. Nothing is licensed; only the TTS
endpoint is fetched.

    python tutorial/build_promo_video.py
    python tutorial/build_promo_video.py --scenes secure,close --no-concat   # iterate on scenes

Regenerate the poster after re-rendering: `ffmpeg -ss 19 -i riff-promo.mp4 -frames:v 1 riff-promo-poster.jpg`.

## The scanner tour video

`tutorial/build_scanner_video.py` renders `tutorial/riff-scanner-tour.mp4`, a
two-and-a-half-minute narrated tour of the security scanner: the passive findings
that appear on their own as traffic is captured, then an active scan that stays
inside the scope you set and turns up reflected XSS, SQL injection, and an open
redirect. It starts its own riff on ports 8896/8897 pointed at a tiny,
deliberately vulnerable app it runs on loopback (8898) with
`tutorial/scanner-demo.riff`, so the recording is deterministic and touches only
loopback. Same Playwright/TTS/ffmpeg tooling as the Compose tour.

    python tutorial/build_scanner_video.py
    python tutorial/build_scanner_video.py --scenes active --no-concat   # redo one scene

## The Compose tour video

`tutorial/build_compose_video.py` renders `tutorial/riff-compose-tour.mp4`, a
seven-minute narrated tour of Compose for people new to API clients:
building a request and reading the response, Edit & send from a captured row,
saving into a collection and folders (drag and drop, fold, filter),
environments and personal values, logging in once and capturing the token for
the other requests, and collection import and export. It starts its own riff on
ports 8894/8895 with a scratch workspace and `tutorial/compose-demo.riff`, whose
`respond` rules answer every request to `demo-api.riff.local`, so the recording
is deterministic and needs no network. Each scene is a live Playwright
recording with a drawn cursor, and every action is cued to the sentence that
describes it.

    python tutorial/build_compose_video.py
    python tutorial/build_compose_video.py --scenes auth,interchange --no-concat   # redo two scenes

If riff's dependencies and the video tooling live in different interpreters,
point `RIFF_PYTHON` at the one that can run riff (the project venv). Narration
is cached under `tutorial/video-build/compose`; delete a scene's `.mp3` after
changing its text. Anyone can follow the video by hand with
`riff run -s tutorial/compose-demo.riff`.

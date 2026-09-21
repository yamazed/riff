"""Passive checks: read one captured flow, raise findings, send nothing.

Every check here is deterministic and low-noise. It looks at headers, cookies,
and a couple of unambiguous body signatures that riff already captured. Nothing
in this module opens a socket, so running it carries no authorization concern
beyond having captured the traffic in the first place. That is why the passive
scanner is on by default.

A check is a function `(flow) -> Iterable[Finding]`. Register it in
``PASSIVE_CHECKS``; ``scan_flow`` runs them all and never raises.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable

from ..flow import Flow
from .findings import Finding

Check = Callable[[Flow], Iterable[Finding]]

# Response content types worth holding to browser-security expectations.
_HTML_TYPES = ("text/html", "application/xhtml+xml")
# Header banners that leak stack/version detail with no upside.
_BANNER_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime")
# Request headers that carry a credential; sent in clear text they are exposed.
_CREDENTIAL_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token")
# Near-zero-false-positive secret signatures. Kept deliberately narrow.
_SECRET_PATTERNS = (
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack-token", re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
)


def _host(flow: Flow) -> str:
    return flow.request.host or "?"


def _is_html(flow: Flow) -> bool:
    ctype = (flow.response.headers.get("content-type") or "").lower() if flow.response else ""
    return any(ctype.startswith(t) for t in _HTML_TYPES)


def check_security_headers(flow: Flow) -> Iterable[Finding]:
    """HTML responses missing the standard browser-hardening headers."""
    if not flow.response or flow.response.status >= 400 or not _is_html(flow):
        return
    h = flow.response.headers
    host = _host(flow)
    wanted = [
        ("missing-csp", "Content-Security-Policy", "medium",
         "No Content-Security-Policy, so the page has no defence-in-depth against injected scripts."),
        ("missing-nosniff", "X-Content-Type-Options", "low",
         "No X-Content-Type-Options: nosniff, so the browser may MIME-sniff a response into script."),
        ("missing-frame-options", "X-Frame-Options", "low",
         "No X-Frame-Options and no frame-ancestors, so the page can be framed for clickjacking."),
    ]
    for check, header, severity, detail in wanted:
        if header == "X-Frame-Options" and "frame-ancestors" in (h.get("content-security-policy") or "").lower():
            continue
        if h.get(header) is None:
            yield Finding(check=check, title=f"{header} not set", severity=severity, flow_id=flow.id,
                          url=flow.request.url, evidence=f"response from {host} has no {header}",
                          detail=detail, where=host)


def check_hsts(flow: Flow) -> Iterable[Finding]:
    """HTTPS responses without HTTP Strict-Transport-Security."""
    if not flow.tls or not flow.response or flow.response.status >= 400:
        return
    if flow.response.headers.get("strict-transport-security") is None:
        host = _host(flow)
        yield Finding(check="missing-hsts", title="Strict-Transport-Security not set", severity="low",
                      flow_id=flow.id, url=flow.request.url,
                      evidence=f"HTTPS response from {host} has no Strict-Transport-Security",
                      detail="Without HSTS a network attacker can strip TLS on the next visit.", where=host)


def _cookie_attrs(setcookie: str) -> tuple[str, set[str]]:
    name = setcookie.split("=", 1)[0].strip()
    attrs = {p.strip().lower() for p in setcookie.split(";")[1:]}
    return name, attrs


def check_cookie_flags(flow: Flow) -> Iterable[Finding]:
    """Set-Cookie missing Secure (on HTTPS), HttpOnly, or SameSite."""
    if not flow.response:
        return
    for raw in flow.response.headers.get_all("set-cookie"):
        name, attrs = _cookie_attrs(raw)
        if not name:
            continue
        has_secure = "secure" in attrs
        has_httponly = "httponly" in attrs
        has_samesite = any(a.startswith("samesite") for a in attrs)
        scope = f"{_host(flow)}:{name}"
        if flow.tls and not has_secure:
            yield Finding(check="cookie-no-secure", title=f"Cookie '{name}' without Secure", severity="medium",
                          flow_id=flow.id, url=flow.request.url, evidence=raw[:120],
                          detail="A cookie set over HTTPS without Secure can leak over a plaintext request.",
                          where=scope + "|secure")
        if not has_httponly:
            yield Finding(check="cookie-no-httponly", title=f"Cookie '{name}' without HttpOnly", severity="low",
                          flow_id=flow.id, url=flow.request.url, evidence=raw[:120],
                          detail="Without HttpOnly the cookie is readable from JavaScript, so XSS can steal it.",
                          where=scope + "|httponly")
        if not has_samesite:
            yield Finding(check="cookie-no-samesite", title=f"Cookie '{name}' without SameSite", severity="low",
                          flow_id=flow.id, url=flow.request.url, evidence=raw[:120],
                          detail="No SameSite attribute leaves the cookie exposed to cross-site request forgery.",
                          where=scope + "|samesite")


def check_banners(flow: Flow) -> Iterable[Finding]:
    """Server/framework version banners that aid an attacker and help nobody."""
    if not flow.response:
        return
    host = _host(flow)
    for header in _BANNER_HEADERS:
        value = flow.response.headers.get(header)
        # A bare product name is fine; a version number is the leak.
        if value and any(ch.isdigit() for ch in value):
            yield Finding(check="version-banner", title=f"{header} reveals a version", severity="info",
                          flow_id=flow.id, url=flow.request.url, evidence=f"{header}: {value}",
                          detail="Version banners let an attacker match known CVEs to the stack. Remove them.",
                          where=f"{host}:{header}:{value}")


def check_plaintext_credentials(flow: Flow) -> Iterable[Finding]:
    """A credential header sent over plaintext HTTP."""
    if flow.tls or flow.request.scheme != "http":
        return
    host = _host(flow)
    for header in _CREDENTIAL_HEADERS:
        if flow.request.headers.get(header) is not None:
            yield Finding(check="credential-cleartext", title=f"{header} sent over plaintext HTTP", severity="high",
                          flow_id=flow.id, url=flow.request.url,
                          evidence=f"{header} header on an http:// request to {host}",
                          detail="Anyone on the network path can read this credential. Use HTTPS.",
                          where=f"{host}:{header}")


def check_cors(flow: Flow) -> Iterable[Finding]:
    """Access-Control-Allow-Origin: * together with credentials true."""
    if not flow.response:
        return
    h = flow.response.headers
    origin = (h.get("access-control-allow-origin") or "").strip()
    creds = (h.get("access-control-allow-credentials") or "").strip().lower()
    if origin == "*" and creds == "true":
        host = _host(flow)
        yield Finding(check="cors-wildcard-credentials",
                      title="CORS allows any origin with credentials", severity="high", flow_id=flow.id,
                      url=flow.request.url,
                      evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                      detail="This lets any site read authenticated responses. Reflect a vetted origin instead.",
                      where=host)


def check_body_secrets(flow: Flow) -> Iterable[Finding]:
    """Unambiguous secret material in a response body."""
    if not flow.response or flow.response.body_streamed or not flow.response.body:
        return
    body = flow.response.body
    host = _host(flow)
    for name, pattern in _SECRET_PATTERNS:
        if pattern.search(body):
            yield Finding(check=f"secret-{name}", title=f"Response body contains a {name.replace('-', ' ')}",
                          severity="high", flow_id=flow.id, url=flow.request.url,
                          evidence=f"{name} pattern matched in the response body",
                          detail="Secret material should never be served to a client. Rotate it and remove it.",
                          where=f"{host}:{flow.request.path}:{name}")


PASSIVE_CHECKS: tuple[Check, ...] = (
    check_security_headers,
    check_hsts,
    check_cookie_flags,
    check_banners,
    check_plaintext_credentials,
    check_cors,
    check_body_secrets,
)


def scan_flow(flow: Flow) -> list[Finding]:
    """Run every passive check over one flow. A broken check never stops the others."""
    out: list[Finding] = []
    for check in PASSIVE_CHECKS:
        try:
            out.extend(check(flow))
        except Exception:  # a check bug must not break capture
            continue
    return out

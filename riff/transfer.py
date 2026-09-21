"""Export captured flows to a file and read them back — riff's own JSON, or HAR.

The riff format is simply the detail dictionaries the UI already shows
(`Flow.to_dict`) wrapped in an envelope, so nothing is lost on a round trip.
HAR 1.2 is offered because Chrome DevTools and most other
tools open it, at the cost of riff-specific fields (tags, client, TLS flag)
which travel in the entry `comment`.
"""

from __future__ import annotations

import base64
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import __version__
from .flow import DEFAULT_PORTS, Flow, Request, Response
from .http import Headers

RIFF_FORMAT = "riff-flows"
RIFF_FORMAT_VERSION = 1
IMPORT_TAG = "imported"


class TransferError(ValueError):
    """The file is not something riff can import."""


# ------------------------------------------------------------------ export


def export_riff(details: list[dict]) -> dict:
    return {
        "format": RIFF_FORMAT,
        "version": RIFF_FORMAT_VERSION,
        "riff": __version__,
        "exported": time.time(),
        "flows": details,
    }


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _har_headers(pairs) -> list[dict]:
    return [{"name": name, "value": value} for name, value in pairs]


def _har_cookies(pairs, header: str) -> list[dict]:
    out = []
    for name, value in pairs:
        if name.lower() != header:
            continue
        for part in value.split(";"):
            if header == "set-cookie" and out and part.strip().lower().split("=")[0] in _COOKIE_ATTRS:
                continue
            cookie, _, cookie_value = part.strip().partition("=")
            if cookie:
                out.append({"name": cookie, "value": cookie_value})
            if header == "set-cookie":
                break  # only the first pair of a Set-Cookie is the cookie itself
    return out


_COOKIE_ATTRS = {"path", "domain", "expires", "max-age", "secure", "httponly", "samesite", "priority"}


def _har_body_text(body: dict) -> tuple[str, str | None]:
    """HAR carries text, or base64 with encoding='base64'."""
    if "text" in body:
        return body["text"], None
    if "base64" in body:
        return body["base64"], "base64"
    return "", None


def _mime(pairs) -> str:
    for name, value in pairs:
        if name.lower() == "content-type":
            return value
    return ""


def export_har(details: list[dict]) -> dict:
    entries = []
    for d in details:
        req = d["request"]
        req_headers = [tuple(h) for h in req.get("headers", [])]
        req_body = req.get("body") or {}
        started = float(d.get("started") or time.time())
        duration = float(d.get("duration_ms") or 0)
        parts = urlsplit(req["url"])
        query = []
        for pair in parts.query.split("&") if parts.query else []:
            name, _, value = pair.partition("=")
            if name:
                query.append({"name": name, "value": value})

        entry: dict = {
            "startedDateTime": _iso(started),
            "time": round(duration, 3),
            "request": {
                "method": req["method"],
                "url": req["url"],
                "httpVersion": req.get("http_version", "HTTP/1.1"),
                "cookies": _har_cookies(req_headers, "cookie"),
                "headers": _har_headers(req_headers),
                "queryString": query,
                "headersSize": -1,
                "bodySize": int(req_body.get("size") or 0),
            },
            "cache": {},
            "timings": {"send": 0, "wait": round(duration, 3), "receive": 0},
            "comment": _comment(d),
        }
        if req_body.get("size"):
            text, encoding = _har_body_text(req_body)
            post: dict = {"mimeType": _mime(req_headers), "text": text}
            if encoding:
                post["encoding"] = encoding
            entry["request"]["postData"] = post

        resp = d.get("response")
        if resp is None:
            entry["response"] = {
                "status": 0,
                "statusText": d.get("error") or "",
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [],
                "content": {"size": 0, "mimeType": ""},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": -1,
            }
        else:
            resp_headers = [tuple(h) for h in resp.get("headers", [])]
            body = resp.get("body") or {}
            text, encoding = _har_body_text(body)
            content: dict = {"size": int(body.get("size") or 0), "mimeType": _mime(resp_headers), "text": text}
            if encoding:
                content["encoding"] = encoding
            location = ""
            for name, value in resp_headers:
                if name.lower() == "location":
                    location = value
            entry["response"] = {
                "status": int(resp.get("status") or 0),
                "statusText": resp.get("reason") or "",
                "httpVersion": resp.get("http_version", "HTTP/1.1"),
                "cookies": _har_cookies(resp_headers, "set-cookie"),
                "headers": _har_headers(resp_headers),
                "content": content,
                "redirectURL": location,
                "headersSize": -1,
                "bodySize": int(body.get("size") or 0),
            }
        entries.append(entry)

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "riff", "version": __version__},
            "entries": entries,
        }
    }


def _comment(detail: dict) -> str:
    bits = []
    if detail.get("tags"):
        bits.append("tags=" + ",".join(detail["tags"]))
    if detail.get("client"):
        bits.append("client=" + detail["client"])
    if detail.get("tls"):
        bits.append("tls")
    if detail.get("intercepted"):
        bits.append("synthetic")
    return " ".join(bits)


# ------------------------------------------------------------------ import


def _body_bytes(body: dict | None) -> bytes:
    if not body:
        return b""
    if "text" in body and body.get("encoding") != "base64":
        return str(body["text"]).encode("utf-8")
    raw = body.get("base64") if "base64" in body else body.get("text", "")
    try:
        return base64.b64decode(raw or "")
    except (ValueError, TypeError):
        return b""


def _pairs(headers) -> list[tuple[str, str]]:
    out = []
    for item in headers or []:
        if isinstance(item, dict):
            out.append((str(item.get("name", "")), str(item.get("value", ""))))
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            out.append((str(item[0]), str(item[1])))
    return [(k, v) for k, v in out if k]


def _request(method: str, url: str, headers, body: bytes, version: str) -> Request:
    request = Request(method=(method or "GET").upper(), headers=Headers(headers), body=body, version=version)
    request.set_url(url)
    if not request.host:
        raise TransferError(f"a flow has no usable URL: {url!r}")
    request.port = request.port or DEFAULT_PORTS.get(request.scheme, 80)
    return request


def _from_riff(detail: dict) -> Flow:
    req = detail.get("request") or {}
    request = _request(
        req.get("method", "GET"),
        req.get("url", ""),
        _pairs(req.get("headers")),
        _body_bytes(req.get("body")),
        req.get("http_version", "HTTP/1.1"),
    )
    started = float(detail.get("started") or time.time())
    duration = float(detail.get("duration_ms") or 0)
    flow = Flow(
        client=str(detail.get("client") or "import"),
        tls=bool(detail.get("tls", request.scheme == "https")),
        request=request,
        started=started,
        ended=started + duration / 1000.0,
        tags=[str(t) for t in detail.get("tags") or []],
        error=str(detail.get("error") or ""),
        intercepted=bool(detail.get("intercepted")),
        logs=[str(line) for line in detail.get("logs") or []],
    )
    resp = detail.get("response")
    if resp:
        flow.response = Response(
            version=resp.get("http_version", "HTTP/1.1"),
            status=int(resp.get("status") or 0),
            reason=str(resp.get("reason") or ""),
            headers=Headers(_pairs(resp.get("headers"))),
            body=_body_bytes(resp.get("body")),
        )
    return flow


def _from_har(entry: dict) -> Flow:
    req = entry.get("request") or {}
    post = req.get("postData") or {}
    body = _body_bytes({"text": post.get("text", ""), "encoding": post.get("encoding")}) if post else b""
    request = _request(
        req.get("method", "GET"), req.get("url", ""), _pairs(req.get("headers")), body, req.get("httpVersion") or "HTTP/1.1"
    )
    started = time.time()
    raw_started = entry.get("startedDateTime")
    if raw_started:
        try:
            started = datetime.fromisoformat(str(raw_started).replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    duration = float(entry.get("time") or 0)
    tags: list[str] = []
    tls = request.scheme == "https"
    for bit in str(entry.get("comment") or "").split():
        if bit.startswith("tags="):
            tags = [t for t in bit[5:].split(",") if t]
        elif bit == "tls":
            tls = True
    flow = Flow(client="import", tls=tls, request=request, started=started, ended=started + duration / 1000.0, tags=tags)
    resp = entry.get("response") or {}
    if resp and int(resp.get("status") or 0) > 0:
        content = resp.get("content") or {}
        flow.response = Response(
            version=resp.get("httpVersion") or "HTTP/1.1",
            status=int(resp.get("status") or 0),
            reason=str(resp.get("statusText") or ""),
            headers=Headers(_pairs(resp.get("headers"))),
            body=_body_bytes({"text": content.get("text", ""), "encoding": content.get("encoding")}),
        )
    elif resp.get("statusText"):
        flow.error = str(resp["statusText"])
    return flow


def import_flows(payload) -> list[Flow]:
    """Turn a parsed riff export or HAR file into Flow objects (ids unassigned)."""
    if isinstance(payload, list):
        items, build = payload, _from_riff
    elif isinstance(payload, dict) and isinstance(payload.get("log"), dict):
        items, build = payload["log"].get("entries") or [], _from_har
    elif isinstance(payload, dict) and payload.get("format") == RIFF_FORMAT:
        items, build = payload.get("flows") or [], _from_riff
    elif isinstance(payload, dict) and "request" in payload:
        items, build = [payload], _from_riff
    else:
        raise TransferError("not a riff export or a HAR file")
    if not isinstance(items, list):
        raise TransferError("the file's flow list is malformed")

    flows = []
    for index, item in enumerate(items, 1):
        if not isinstance(item, dict):
            raise TransferError(f"entry {index} is not an object")
        try:
            flow = build(item)
        except (KeyError, TypeError, ValueError) as exc:
            raise TransferError(f"entry {index} could not be read: {exc}") from None
        flow.tag(IMPORT_TAG)
        flows.append(flow)
    return flows

"""The Flow object: one request/response exchange, as scripts see it."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .http import Headers, Query, reason_for

DEFAULT_PORTS = {"http": 80, "https": 443}
_UNSAFE_PATH = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(slots=True)
class Request:
    method: str = "GET"
    scheme: str = "http"
    host: str = ""
    port: int = 80
    path: str = "/"
    query: Query = field(default_factory=Query)
    version: str = "HTTP/1.1"
    headers: Headers = field(default_factory=Headers)
    body: bytes = b""
    content_encoding: str = ""
    body_streamed: bool = False
    body_decoded: bool = True

    @property
    def origin_form(self) -> str:
        qs = self.query.encode()
        return f"{self.path}?{qs}" if qs else self.path

    @property
    def authority(self) -> str:
        if self.port == DEFAULT_PORTS.get(self.scheme):
            return self.host
        return f"{self.host}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.authority}{self.origin_form}"

    def set_url(self, url: str) -> None:
        if url.startswith("/"):  # path-only rewrite, keep the origin
            parts = urlsplit(url)
            self.path = parts.path or "/"
            self.query = Query.parse(parts.query)
            return
        if "://" not in url:
            url = f"{self.scheme}://{url}"
        parts = urlsplit(url)
        self.scheme = parts.scheme or self.scheme
        if parts.hostname:
            self.host = parts.hostname
            self.port = parts.port or DEFAULT_PORTS.get(self.scheme, 80)
        self.path = parts.path or "/"
        self.query = Query.parse(parts.query)

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


@dataclass(slots=True)
class Response:
    version: str = "HTTP/1.1"
    status: int = 200
    reason: str = "OK"
    headers: Headers = field(default_factory=Headers)
    body: bytes = b""
    content_encoding: str = ""
    body_streamed: bool = False
    body_decoded: bool = True

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


@dataclass(slots=True)
class Flow:
    id: int = 0
    client: str = ""
    tls: bool = False
    request: Request = field(default_factory=Request)
    response: Response | None = None
    started: float = field(default_factory=time.time)
    request_done: float = 0.0
    ended: float = 0.0
    tags: list[str] = field(default_factory=list)
    error: str = ""
    intercepted: bool = False  # answered by a `respond` rule, never hit the network
    aborted: bool = False
    logs: list[str] = field(default_factory=list)

    @property
    def duration_ms(self) -> float:
        """Elapsed time so far, so `duration` is usable inside response rules."""
        return ((self.ended or time.time()) - self.started) * 1000

    @property
    def content_type(self) -> str:
        source = self.response.headers if self.response else self.request.headers
        return (source.get("content-type") or "").split(";")[0].strip()

    def tag(self, name: str) -> None:
        if name not in self.tags:
            self.tags.append(name)

    # -- serialisation -----------------------------------------------------

    def to_dict(self, include_bodies: bool = True, body_limit: int = 256 * 1024) -> dict:
        def body_of(msg) -> dict:
            if msg.body_streamed:
                return {"streamed": True}
            data = msg.body
            info: dict = {"size": len(data)}
            if not include_bodies:
                return info
            if len(data) > body_limit:
                info["truncated"] = True
                data = data[:body_limit]
            try:
                info["text"] = data.decode("utf-8")
            except UnicodeDecodeError:
                import base64

                info["base64"] = base64.b64encode(data).decode("ascii")
            return info

        out = {
            "id": self.id,
            "client": self.client,
            "tls": self.tls,
            "started": self.started,
            "duration_ms": round(self.duration_ms, 2),
            "tags": list(self.tags),
            "intercepted": self.intercepted,
            "request": {
                "method": self.request.method,
                "url": self.request.url,
                "http_version": self.request.version,
                "headers": self.request.headers.items(),
                "content_encoding": self.request.content_encoding,
                "body": body_of(self.request),
            },
        }
        if self.error:
            out["error"] = self.error
        if self.logs:
            out["logs"] = list(self.logs)
        if self.response is not None:
            out["response"] = {
                "http_version": self.response.version,
                "status": self.response.status,
                "reason": self.response.reason,
                "headers": self.response.headers.items(),
                "content_encoding": self.response.content_encoding,
                "body": body_of(self.response),
            }
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))

    def save_to(self, directory: str) -> str:
        """Write this flow to `directory` as a readable .http transcript."""
        os.makedirs(directory, exist_ok=True)
        slug = _UNSAFE_PATH.sub("-", f"{self.request.host}{self.request.path}").strip("-")[:60]
        name = f"{self.id:05d}-{self.request.method.lower()}-{slug or 'root'}.http"
        target = os.path.join(directory, name)
        out = bytearray()
        out += f"{self.request.method} {self.request.origin_form} {self.request.version}\r\n".encode("latin-1")
        out += self.request.headers.to_bytes()
        out += b"\r\n"
        out += self.request.body if not self.request.body_streamed else b"<streamed>"
        if self.response is not None:
            reason = self.response.reason or reason_for(self.response.status)
            out += b"\r\n\r\n"
            out += f"{self.response.version} {self.response.status} {reason}\r\n".encode("latin-1")
            out += self.response.headers.to_bytes()
            out += b"\r\n"
            out += self.response.body if not self.response.body_streamed else b"<streamed>"
        with open(target, "wb") as fh:
            fh.write(bytes(out))
        return target

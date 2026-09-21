"""Out-of-band interaction server: riff's own small Collaborator.

Some vulnerabilities never show in the direct response. A blind SSRF makes the
server fetch a URL; a blind command injection runs `curl`; a blind XXE opens an
entity — and the only evidence is that *something reached out*. This module runs
a tiny HTTP listener the scanner can point those payloads at. Each payload
carries a unique token; when a request for that token arrives, we know the input
reached code that made an outbound request.

It is off by default and never started implicitly. It binds a plain HTTP port
(loopback unless told otherwise). Against a remote target the listener must be
on an address that target can actually reach, so `--collaborator-host` takes a
routable address, the usual arrangement for out-of-band detection. There is
no DNS component and nothing is sent anywhere: it only records inbound hits.
"""

from __future__ import annotations

import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class Collaborator:
    def __init__(self, host: str = "127.0.0.1", port: int = 0, advertise_host: str | None = None):
        self.host = host
        self.port = port
        self.advertise_host = advertise_host or host
        self._hits: dict[str, list[dict]] = {}
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "Collaborator":
        collaborator = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args) -> None:  # keep quiet
                pass

            def _record(self) -> None:
                token = self.path.lstrip("/").split("/", 1)[0].split("?", 1)[0]
                if token:
                    collaborator._note(token, {
                        "at": time.time(),
                        "method": self.command,
                        "path": self.path,
                        "from": self.client_address[0],
                        "user_agent": self.headers.get("User-Agent", ""),
                    })
                body = b"riff\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = do_OPTIONS = _record

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name="riff-collab")
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    # -- tokens and hits ---------------------------------------------------

    @property
    def base_url(self) -> str:
        host = self.advertise_host
        if ":" in host and not host.startswith("["):  # bare IPv6
            host = f"[{host}]"
        return f"http://{host}:{self.port}"

    def issue(self) -> tuple[str, str]:
        """A fresh token and the URL a payload should reach out to."""
        token = "rc" + secrets.token_hex(6)
        with self._lock:
            self._hits.setdefault(token, [])
        return token, f"{self.base_url}/{token}"

    def _note(self, token: str, hit: dict) -> None:
        with self._lock:
            self._hits.setdefault(token, []).append(hit)

    def hits(self, token: str) -> list[dict]:
        with self._lock:
            return list(self._hits.get(token, []))

    def any_hits(self) -> dict[str, list[dict]]:
        with self._lock:
            return {t: list(h) for t, h in self._hits.items() if h}

    def public(self) -> dict[str, Any]:
        return {"base_url": self.base_url, "tokens": len(self._hits),
                "interactions": sum(len(h) for h in self._hits.values())}

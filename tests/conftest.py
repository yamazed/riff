"""Shared fixtures: a throwaway origin server and a proxy pointed at it."""

from __future__ import annotations

import gzip
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from riff.access import AccessPolicy
from riff.ca import CertAuthority
from riff.hub import Hub
from riff.proxy import Options, Proxy
from riff.script import Engine


class OriginHandler(BaseHTTPRequestHandler):
    """A small origin server with one route per protocol quirk worth testing."""

    protocol_version = "HTTP/1.1"
    server_version = "origin"

    def log_message(self, *args):
        pass

    # -- routes ------------------------------------------------------------

    def _param(self, name: str, default: int) -> int:
        from urllib.parse import parse_qs, urlsplit

        values = parse_qs(urlsplit(self.path).query).get(name)
        return int(values[0]) if values else default

    def _route(self):
        path = self.path.split("?", 1)[0]
        body = b""
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            body = self.rfile.read(length)

        if path == "/json":
            return self._plain(200, b'{"hello": "world", "n": 1}', "application/json")

        if path == "/echo":
            payload = {
                "method": self.command,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body.decode("utf-8", "replace"),
            }
            return self._plain(200, json.dumps(payload).encode(), "application/json")

        if path == "/gzip":
            raw = gzip.compress(json.dumps({"compressed": True, "pad": "x" * 200}).encode())
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if path == "/chunked":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for piece in (b"alpha", b"beta", b"gamma"):
                self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            return

        if path == "/big":
            size = self._param("size", 100000)
            return self._plain(200, b"B" * size, "application/octet-stream")

        if path == "/size":
            return self._plain(200, json.dumps({"received": len(body)}).encode(), "application/json")

        if path == "/nocontent":
            self.send_response(204)
            self.end_headers()
            return

        if path == "/notmodified":
            self.send_response(304)
            self.send_header("ETag", '"abc"')
            self.end_headers()
            return

        if path == "/slow":
            time.sleep(0.25)
            return self._plain(200, b"slept", "text/plain")

        if path == "/events":
            # Server-sent events: no length, held open, second event well after the first.
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            self.wfile.write(b"data: one\n\n")
            self.wfile.flush()
            time.sleep(0.8)
            self.wfile.write(b"data: two\n\n")
            self.wfile.flush()
            return

        if path == "/status":
            code = self._param("code", 500)
            return self._plain(code, b'{"error": "boom"}', "application/json")

        return self._plain(404, b"nope", "text/plain")

    def _plain(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = lambda self: self._route()


class Origin:
    def __init__(self, tls_context: ssl.SSLContext | None = None):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), OriginHandler)
        self.server.daemon_threads = True
        if tls_context is not None:
            self.server.socket = tls_context.wrap_socket(self.server.socket, server_side=True)
        self.scheme = "https" if tls_context else "http"
        self.host, self.port = self.server.server_address[:2]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def authority(self) -> str:
        return f"{self.host}:{self.port}"

    def url(self, path: str) -> str:
        return f"{self.scheme}://{self.authority}{path}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture(scope="session")
def ca(tmp_path_factory) -> CertAuthority:
    authority = CertAuthority(str(tmp_path_factory.mktemp("riff-ca")))
    authority.load_or_create()
    return authority


@pytest.fixture
def origin():
    server = Origin()
    yield server
    server.stop()


@pytest.fixture
def tls_origin(ca):
    """An HTTPS origin using a leaf minted by the test CA."""
    context = ca.context_for("localhost")
    server = Origin(tls_context=context)
    server.host = "localhost"
    yield server
    server.stop()


class Harness:
    def __init__(self, proxy: Proxy, hub: Hub):
        self.proxy = proxy
        self.hub = hub
        self.thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        self.thread.start()
        _wait_for_port(*proxy.address)

    @property
    def address(self):
        return self.proxy.address

    def flows(self):
        return self.hub.list()

    def wait_for_flows(self, count: int, timeout: float = 3.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if len(self.hub.list()) >= count:
                return self.hub.list()
            time.sleep(0.02)
        return self.hub.list()

    def wait_for_tunnels(self, count: int, timeout: float = 3.0):
        deadline = time.time() + timeout
        while time.time() < deadline and self.hub.tunnels < count:
            time.sleep(0.02)
        return self.hub.tunnels

    def stop(self):
        self.proxy.shutdown()


def _wait_for_port(host: str, port: int, timeout: float = 5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError(f"proxy never came up on {host}:{port}")


@pytest.fixture
def make_proxy(ca):
    created: list[Harness] = []

    def factory(script: str = "", **option_overrides) -> Harness:
        engine = Engine.from_source(script) if script else Engine.empty()
        access = AccessPolicy.build(
            auth=option_overrides.pop("auth", ""),
            allow_from=option_overrides.pop("allow_from", ""),
        )
        options = Options(
            listen_host="127.0.0.1",
            listen_port=0,
            verify_upstream=option_overrides.pop("verify_upstream", False),
            **option_overrides,
        )
        hub = Hub()
        proxy = Proxy(options, engine=engine, ca=ca, observer=hub, access=access)
        proxy.bind()
        harness = Harness(proxy, hub)
        created.append(harness)
        return harness

    yield factory
    for harness in created:
        harness.stop()


@pytest.fixture
def client_ssl_context(ca):
    """A client context that trusts the riff CA, as a real client would after install."""
    context = ssl.create_default_context(cafile=ca.ca_cert_path)
    context.check_hostname = True
    return context

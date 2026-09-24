"""The interception proxy itself.

One thread per client connection. Each connection is either

  * a plain HTTP proxy conversation (absolute-form request targets), or
  * a CONNECT tunnel, which is then either passed through opaquely or
    terminated with a minted certificate and re-spoken as HTTP/1.1.

Everything the rules can see or change happens in `_exchange`.
"""

from __future__ import annotations

import io
import selectors
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import http as H
from .access import PROXY_AUTH_REALM, AccessPolicy
from .ca import CertAuthority
from .flow import DEFAULT_PORTS, Flow, Request, Response
from .listen import bind_exclusive
from .script import Engine, Verdict
from .script.errors import RiffRuntimeError

CONNECT_ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\n\r\n"


@dataclass(slots=True)
class Options:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8888
    max_body: int = 8 * 1024 * 1024
    connect_timeout: float = 15.0
    read_timeout: float = 120.0
    idle_timeout: float = 300.0
    verify_upstream: bool = True
    upstream_proxy: str = ""
    client_backlog: int = 200


class Observer:
    """Everything the proxy wants to tell the outside world."""

    def on_start(self, proxy: "Proxy") -> None: ...
    def on_flow(self, flow: Flow) -> None: ...
    def on_log(self, flow: Flow | None, text: str) -> None: ...
    def on_tunnel(self, host: str, port: int, sent: int, received: int, seconds: float) -> None: ...
    def on_error(self, text: str) -> None: ...


class _Counter:
    def __init__(self) -> None:
        self._value = 0
        self._lock = threading.Lock()

    def next(self) -> int:
        with self._lock:
            self._value += 1
            return self._value

    @property
    def value(self) -> int:
        return self._value


@dataclass
class _Upstream:
    sock: socket.socket
    rfile: io.BufferedReader
    wfile: io.BufferedWriter
    scheme: str
    host: str
    port: int

    @property
    def origin(self) -> tuple[str, str, int]:
        return (self.scheme, self.host, self.port)

    def close(self) -> None:
        for closeable in (self.wfile, self.rfile, self.sock):
            try:
                closeable.close()
            except OSError:
                pass


class ProxyError(Exception):
    """A failure that should be reported to the client as a 502."""


class Proxy:
    def __init__(
        self,
        options: Options,
        engine: Engine | None = None,
        ca: CertAuthority | None = None,
        observer: Observer | None = None,
        access: AccessPolicy | None = None,
    ):
        self.options = options
        self.engine = engine or Engine.empty()
        self.ca = ca or CertAuthority()
        self.observer = observer or Observer()
        self.access = access or AccessPolicy()
        self.flow_ids = _Counter()
        self._server: socket.socket | None = None
        self._stopping = threading.Event()
        self._threads: set[threading.Thread] = set()
        self._threads_lock = threading.Lock()
        self._upstream_ctx = self._build_upstream_context()

    # -- lifecycle ---------------------------------------------------------

    def _build_upstream_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        if not self.options.verify_upstream:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            return (self.options.listen_host, self.options.listen_port)
        return self._server.getsockname()[:2]

    def bind(self) -> tuple[str, int]:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Exclusive: two riffs sharing a port send traffic to an arbitrary one.
        bind_exclusive(server, (self.options.listen_host, self.options.listen_port), what="the proxy")
        server.listen(self.options.client_backlog)
        server.settimeout(0.5)
        self._server = server
        self.ca.load_or_create()
        self.observer.on_start(self)
        return self.address

    def serve_forever(self) -> None:
        if self._server is None:
            self.bind()
        if self._server is None:  # bind() raises rather than returning silently, but be explicit
            raise ProxyError("the proxy socket is not bound")
        while not self._stopping.is_set():
            try:
                client, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.access.allows_address(addr[0]):
                self.observer.on_error(f"refused connection from {addr[0]} — not in the allowed range")
                try:
                    client.close()
                except OSError:
                    pass
                continue
            thread = threading.Thread(
                target=self._run_connection, args=(client, addr), daemon=True, name=f"riff-{addr[1]}"
            )
            with self._threads_lock:
                self._threads.add(thread)
            thread.start()

    def shutdown(self) -> None:
        self._stopping.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass

    def _run_connection(self, client: socket.socket, addr) -> None:
        try:
            _ClientConnection(self, client, addr).serve()
        except Exception as exc:  # pragma: no cover - defensive
            self.observer.on_error(f"connection from {addr[0]}:{addr[1]} failed: {exc!r}")
        finally:
            with self._threads_lock:
                self._threads.discard(threading.current_thread())

    # -- upstream ----------------------------------------------------------

    def connect_upstream(self, scheme: str, host: str, port: int) -> _Upstream:
        proxy_url = self.options.upstream_proxy
        timeout = self.options.connect_timeout
        try:
            if proxy_url:
                sock = self._connect_via_proxy(proxy_url, scheme, host, port)
            else:
                sock = socket.create_connection((host, port), timeout=timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if scheme == "https":
                sock = self._upstream_ctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(self.options.read_timeout)
        except ssl.SSLCertVerificationError as exc:
            raise ProxyError(
                f"upstream TLS certificate for {host} failed verification: {exc.verify_message or exc}. "
                f"Start riff with --insecure to accept it anyway."
            ) from None
        except OSError as exc:
            raise ProxyError(f"cannot reach {host}:{port} — {exc}") from None
        return _Upstream(
            sock=sock,
            rfile=sock.makefile("rb", buffering=65536),
            wfile=sock.makefile("wb"),
            scheme=scheme,
            host=host,
            port=port,
        )

    def _connect_via_proxy(self, proxy_url: str, scheme: str, host: str, port: int) -> socket.socket:
        parts = urlsplit(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
        sock = socket.create_connection(
            (parts.hostname, parts.port or 8080), timeout=self.options.connect_timeout
        )
        if scheme != "https":
            return sock  # plain HTTP goes out in absolute form, no CONNECT needed
        sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode("latin-1"))
        reader = sock.makefile("rb", buffering=0)
        head = H.read_response_head(reader)
        if head.status != 200:
            sock.close()
            raise ProxyError(f"upstream proxy refused CONNECT to {host}:{port}: {head.status} {head.reason}")
        return sock


# ------------------------------------------------------------ per-connection


class _ClientConnection:
    def __init__(self, proxy: Proxy, sock: socket.socket, addr):
        self.proxy = proxy
        self.options = proxy.options
        self.engine = proxy.engine
        self.observer = proxy.observer
        self.sock = sock
        self.client = f"{addr[0]}:{addr[1]}"
        self.upstream: _Upstream | None = None

    # -- entry -------------------------------------------------------------

    def serve(self) -> None:
        try:
            self.sock.settimeout(self.options.idle_timeout)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            raw = self.sock.makefile("rb", buffering=0)
            wfile = self.sock.makefile("wb")
            try:
                head = H.read_request_head(raw)
            except (H.HttpError, OSError):
                return
            if head is None:
                return
            if not self.proxy.access.check_credentials(head.headers.get("proxy-authorization")):
                self._challenge(wfile)
                return
            if head.method == "CONNECT":
                self._handle_connect(head, wfile)
            else:
                self._http_loop(io.BufferedReader(raw, 65536), wfile, "http", tls=False, first=head)
        except (OSError, ssl.SSLError):
            pass
        finally:
            self._close()

    def _close(self) -> None:
        if self.upstream is not None:
            self.upstream.close()
            self.upstream = None
        try:
            self.sock.close()
        except OSError:
            pass

    # -- CONNECT -----------------------------------------------------------

    def _handle_connect(self, head: H.RequestHead, wfile) -> None:
        host, _, port_text = head.target.rpartition(":")
        if not host:
            host, port_text = head.target, "443"
        host = host.strip("[]")
        try:
            port = int(port_text)
        except ValueError:
            port = 443

        if self.engine.tls_policy(host) == "passthru":
            self._tunnel(host, port, wfile)
            return

        try:
            wfile.write(CONNECT_ESTABLISHED)
            wfile.flush()
        except OSError:
            return

        context = self.proxy.ca.context_for(host)
        context.sni_callback = self.proxy.ca.sni_callback
        try:
            tls_sock = context.wrap_socket(self.sock, server_side=True)
        except ssl.SSLError as exc:
            # Almost always the client rejecting our CA, or a pinned certificate.
            self.observer.on_error(
                f"TLS handshake with client failed for {host}:{port} ({exc.reason or exc}). "
                f"Is the riff CA trusted by this client?"
            )
            return
        except OSError:
            return

        self.sock = tls_sock
        try:
            # Route to the CONNECT authority, not to whatever Host header
            # arrives inside the tunnel.
            self._http_loop(
                tls_sock.makefile("rb", buffering=65536),
                tls_sock.makefile("wb"),
                "https",
                tls=True,
                default_host=host,
                default_port=port,
            )
        except (OSError, ssl.SSLError):
            pass

    def _tunnel(self, host: str, port: int, wfile) -> None:
        started = time.time()
        try:
            upstream = socket.create_connection((host, port), timeout=self.options.connect_timeout)
        except OSError as exc:
            self._write_error(wfile, 502, f"cannot reach {host}:{port} — {exc}")
            return
        try:
            wfile.write(CONNECT_ESTABLISHED)
            wfile.flush()
        except OSError:
            upstream.close()
            return
        sent, received = _pump(self.sock, upstream, self.options.idle_timeout)
        upstream.close()
        if self.engine.should_capture(host):
            self.observer.on_tunnel(host, port, sent, received, time.time() - started)

    # -- HTTP loop ---------------------------------------------------------

    def _http_loop(
        self,
        rfile,
        wfile,
        scheme: str,
        tls: bool,
        default_host: str | None = None,
        default_port: int | None = None,
        first: H.RequestHead | None = None,
    ) -> None:
        head = first
        while True:
            if head is None:
                try:
                    head = H.read_request_head(rfile)
                except (H.HttpError, OSError, ssl.SSLError):
                    return
                if head is None:
                    return
            try:
                keep_alive = self._exchange(head, rfile, wfile, scheme, tls, default_host, default_port)
            except ProxyError as exc:
                self._write_error(wfile, 502, str(exc))
                return
            except (H.HttpError, OSError, ssl.SSLError):
                return
            if not keep_alive:
                return
            head = None

    # -- one request/response ---------------------------------------------

    def _exchange(
        self,
        head: H.RequestHead,
        rfile,
        wfile,
        scheme: str,
        tls: bool,
        default_host: str | None,
        default_port: int | None,
    ) -> bool:
        options = self.options
        request = self._build_request(head, scheme, default_host, default_port)
        flow = Flow(id=self.proxy.flow_ids.next(), client=self.client, tls=tls, request=request)

        client_wants_close = _wants_close(head.headers, head.version)

        # --- request body -------------------------------------------------
        req_mode, req_length = H.body_mode(head.headers, is_response=False, method=request.method)
        if (head.headers.get("expect") or "").lower().startswith("100-continue"):
            # riff answers the continuation itself; forwarding Expect upstream
            # would leave the origin waiting for a handshake that already happened.
            wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            wfile.flush()
            head.headers.remove("expect")
            request.headers.remove("expect")
        raw_body, req_truncated = H.read_body_capped(rfile, req_mode, req_length, options.max_body)
        request.body_streamed = req_truncated
        consumed = len(raw_body)
        if not req_truncated:
            request.content_encoding = (head.headers.get("content-encoding") or "").lower()
            request.body, request.body_decoded = H.decode_content(raw_body, request.content_encoding)
        else:
            request.body = b""

        # --- request rules --------------------------------------------------
        verdict = self._run_rules(flow, "request")
        if verdict.delay_ms:
            time.sleep(verdict.delay_ms / 1000.0)

        if verdict.abort:
            self._finish(flow, verdict, wfile)
            return False

        body_allowed = request.method != "HEAD"

        if flow.intercepted and flow.response is not None:
            if req_truncated:
                H.discard_body(rfile, req_mode, req_length - consumed if req_mode == H.BodyMode.LENGTH else 0)
            self._write_response(
                wfile, flow.response, head.version, force_close=client_wants_close, body_allowed=body_allowed
            )
            self._finish(flow, verdict, wfile)
            return not client_wants_close

        # --- upstream -------------------------------------------------------
        upstream = self._ensure_upstream(request)
        headers = request.headers.copy()
        headers.strip_hop_by_hop()
        headers.set("Host", request.authority)
        if not req_truncated:
            if request.body_decoded and request.content_encoding:
                headers.remove("content-encoding")
            if req_mode != H.BodyMode.NONE or request.body:
                headers.set("Content-Length", str(len(request.body)))
        else:
            req_framing = _frame_oversized(headers, req_mode, req_length)

        try:
            upstream.wfile.write(
                H.build_request(request.method, request.origin_form, "HTTP/1.1", headers, b"")
            )
            if req_truncated:
                _write_oversized(upstream.wfile, req_framing, raw_body, rfile, req_mode, req_length)
            elif request.body:
                upstream.wfile.write(request.body)
            upstream.wfile.flush()
        except OSError as exc:
            self._drop_upstream()
            raise ProxyError(f"sending to {request.host} failed — {exc}") from None

        flow.request_done = time.time()

        # --- response -------------------------------------------------------
        try:
            resp_head = H.read_response_head(upstream.rfile)
            while 100 <= resp_head.status < 200 and resp_head.status != 101:
                wfile.write(
                    H.build_response(resp_head.version, resp_head.status, resp_head.reason, H.Headers(), b"")
                )
                wfile.flush()
                resp_head = H.read_response_head(upstream.rfile)
        except (H.HttpError, OSError) as exc:
            self._drop_upstream()
            raise ProxyError(f"no usable response from {request.host} — {exc}") from None

        if resp_head.status == 101:
            return self._handle_upgrade(flow, resp_head, rfile, wfile, upstream)

        resp_mode, resp_length = H.body_mode(
            resp_head.headers, is_response=True, method=request.method, status=resp_head.status
        )
        if resp_mode != H.BodyMode.NONE and _is_event_stream(resp_head.headers):
            # Server-sent events never end on their own, so buffering the body would
            # hold every event back until the connection closed. Relay it as it
            # arrives, the same way an oversized body is streamed.
            raw_resp, resp_truncated = b"", True
        else:
            try:
                raw_resp, resp_truncated = H.read_body_capped(
                    upstream.rfile, resp_mode, resp_length, options.max_body
                )
            except (H.HttpError, OSError) as exc:
                self._drop_upstream()
                raise ProxyError(f"reading response from {request.host} failed — {exc}") from None

        response = Response(
            version=resp_head.version,
            status=resp_head.status,
            reason=resp_head.reason,
            headers=resp_head.headers,
            body_streamed=resp_truncated,
        )
        if not resp_truncated:
            response.content_encoding = (resp_head.headers.get("content-encoding") or "").lower()
            response.body, response.body_decoded = H.decode_content(raw_resp, response.content_encoding)
        flow.response = response

        upstream_closes = _wants_close(resp_head.headers, resp_head.version) or resp_mode == H.BodyMode.UNTIL_CLOSE

        # --- response rules -------------------------------------------------
        verdict2 = self._run_rules(flow, "response")
        verdict.save_dirs.extend(d for d in verdict2.save_dirs if d not in verdict.save_dirs)
        verdict.messages.extend(verdict2.messages)
        if verdict2.delay_ms:
            time.sleep(verdict2.delay_ms / 1000.0)
        if verdict2.abort:
            self._drop_upstream()
            self._finish(flow, verdict, wfile)
            return False

        # A `respond` inside an `on response` rule swaps in a whole new message.
        replaced = flow.intercepted
        response = flow.response
        force_close = client_wants_close or (resp_truncated and resp_mode == H.BodyMode.UNTIL_CLOSE)

        # --- write it back ----------------------------------------------------
        if resp_truncated and not replaced and body_allowed:
            out = response.headers.copy()
            out.strip_hop_by_hop()
            framing = _frame_oversized(out, resp_mode, resp_length)
            http_1_1 = head.version.startswith("HTTP/1.1")
            if framing == "chunked" and not http_1_1:
                # An HTTP/1.0 client cannot read chunked, so fall back to
                # letting the closing connection delimit the message.
                out.remove("transfer-encoding")
                framing = "raw"
                force_close = True
            if force_close:
                out.set("Connection", "close")
            wfile.write(
                H.build_response(
                    "HTTP/1.1" if http_1_1 else "HTTP/1.0",
                    response.status,
                    response.reason or H.reason_for(response.status),
                    out,
                    b"",
                )
            )
            wfile.flush()
            _write_oversized(wfile, framing, raw_resp, upstream.rfile, resp_mode, resp_length)
        else:
            if resp_truncated:  # the parked upstream body can never be resynced
                self._drop_upstream()
            self._write_response(
                wfile, response, head.version, force_close=force_close, body_allowed=body_allowed
            )

        if upstream_closes:
            self._drop_upstream()

        self._finish(flow, verdict, wfile)
        return not force_close

    # -- helpers ------------------------------------------------------------

    def _build_request(
        self, head: H.RequestHead, scheme: str, default_host: str | None, default_port: int | None
    ) -> Request:
        target = head.target
        host_header = head.headers.get("host") or ""
        if target.startswith(("http://", "https://")):
            parts = urlsplit(target)
            scheme = parts.scheme
            host = parts.hostname or host_header.split(":")[0]
            port = parts.port or DEFAULT_PORTS.get(scheme, 80)
            path, query = parts.path or "/", parts.query
        else:
            authority = default_host or host_header
            if not authority:
                raise ProxyError("request has no Host header and no absolute URL — cannot route it")
            host, _, port_text = authority.rpartition(":")
            if not host or not port_text.isdigit():
                host, port_text = authority.strip("[]"), ""
            host = host.strip("[]")
            port = int(port_text) if port_text.isdigit() else (default_port or DEFAULT_PORTS.get(scheme, 80))
            path, _, query = target.partition("?")

        headers = head.headers.copy()
        headers.remove("proxy-connection")
        return Request(
            method=head.method,
            scheme=scheme,
            host=host.lower(),
            port=port,
            path=path or "/",
            query=H.Query.parse(query),
            version=head.version,
            headers=headers,
        )

    def _ensure_upstream(self, request: Request) -> _Upstream:
        origin = (request.scheme, request.host, request.port)
        if self.upstream is not None and self.upstream.origin != origin:
            self._drop_upstream()
        if self.upstream is None:
            self.upstream = self.proxy.connect_upstream(*origin)
        return self.upstream

    def _drop_upstream(self) -> None:
        if self.upstream is not None:
            self.upstream.close()
            self.upstream = None

    def _run_rules(self, flow: Flow, phase: str):
        try:
            return self.engine.run(flow, phase)
        except RiffRuntimeError as exc:
            text = f"rule error ({phase}): {exc}"
            flow.error = text
            self.observer.on_error(text)
            return Verdict()

    def _write_response(
        self, wfile, response: Response, client_version: str, force_close: bool, body_allowed: bool = True
    ) -> None:
        headers = response.headers.copy()
        headers.strip_hop_by_hop()
        if response.body_decoded and response.content_encoding:
            headers.remove("content-encoding")
        # HEAD replies and 204/304 carry no body; their Content-Length describes
        # the entity that *would* have been sent, so leave it untouched.
        framed = body_allowed and response.status not in H.NO_BODY_STATUS and not 100 <= response.status < 200
        if framed:
            headers.set("Content-Length", str(len(response.body)))
        if force_close:
            headers.set("Connection", "close")
        version = "HTTP/1.1" if client_version.startswith("HTTP/1.1") else "HTTP/1.0"
        reason = response.reason or H.reason_for(response.status)
        body = response.body if framed else b""
        wfile.write(H.build_response(version, response.status, reason, headers, body))
        wfile.flush()

    def _handle_upgrade(self, flow: Flow, resp_head, rfile, wfile, upstream: _Upstream) -> bool:
        """101 Switching Protocols: forward the handshake, then get out of the way."""
        flow.response = Response(
            version=resp_head.version,
            status=resp_head.status,
            reason=resp_head.reason,
            headers=resp_head.headers,
        )
        flow.tag("upgrade")
        flow.ended = time.time()
        wfile.write(
            H.build_response(
                resp_head.version, resp_head.status, resp_head.reason or "Switching Protocols",
                resp_head.headers, b"",
            )
        )
        wfile.flush()
        self.observer.on_flow(flow)
        pending_client = H.drain_buffer(rfile)
        pending_upstream = H.drain_buffer(upstream.rfile)
        if pending_upstream:
            wfile.write(pending_upstream)
            wfile.flush()
        if pending_client:
            upstream.wfile.write(pending_client)
            upstream.wfile.flush()
        sent, received = _pump(self.sock, upstream.sock, self.options.idle_timeout)
        self.observer.on_tunnel(flow.request.host, flow.request.port, sent, received, 0.0)
        self._drop_upstream()
        return False

    def _finish(self, flow: Flow, verdict, wfile) -> None:
        flow.ended = time.time()
        for message in verdict.messages:
            self.observer.on_log(flow, message)
        for directory in verdict.save_dirs:
            try:
                flow.save_to(directory)
            except OSError as exc:
                self.observer.on_error(f"could not save flow {flow.id} to {directory}: {exc}")
        # `capture`/`ignore` decide what gets recorded; the traffic itself has
        # already been proxied normally either way.
        if self.engine.should_capture(flow.request.host):
            self.observer.on_flow(flow)

    def _challenge(self, wfile) -> None:
        """407, so the client knows to retry with Proxy-Authorization."""
        body = b"riff requires proxy credentials.\n"
        headers = H.Headers(
            [
                ("Proxy-Authenticate", f'Basic realm="{PROXY_AUTH_REALM}", charset="UTF-8"'),
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Connection", "close"),
                ("X-Riff", "auth-required"),
            ]
        )
        try:
            wfile.write(H.build_response("HTTP/1.1", 407, "Proxy Authentication Required", headers, body))
            wfile.flush()
        except OSError:
            pass

    def _write_error(self, wfile, status: int, message: str) -> None:
        body = message.encode("utf-8")
        headers = H.Headers(
            [
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Connection", "close"),
                ("X-Riff", "error"),
            ]
        )
        try:
            wfile.write(H.build_response("HTTP/1.1", status, H.reason_for(status), headers, body))
            wfile.flush()
        except OSError:
            pass
        self.observer.on_error(message)


# ------------------------------------------------------------------ plumbing


def _prefix_then(prefix: bytes, iterator):
    if prefix:
        yield prefix
    yield from iterator


def _frame_oversized(headers: H.Headers, mode: str, length: int) -> str:
    """Pick the framing for a body riff will stream instead of buffering.

    When the original message declared a Content-Length there is no reason to
    re-frame: keeping it means the bytes go out exactly as they came in, which
    also spares origins that do not accept chunked request bodies.
    """
    if mode == H.BodyMode.LENGTH:
        headers.set("Content-Length", str(length))
        headers.remove("transfer-encoding")
        return "length"
    headers.remove("content-length")
    headers.set("Transfer-Encoding", "chunked")
    return "chunked"


def _write_oversized(wfile, framing: str, prefix: bytes, rfile, mode: str, length: int) -> None:
    remaining = H.iter_remaining(rfile, mode, length, len(prefix))
    if framing == "chunked":
        H.write_chunked(wfile, _prefix_then(prefix, remaining))
        return
    wfile.write(prefix)
    for block in remaining:
        wfile.write(block)
        wfile.flush()  # each block goes out as it arrives: this path also carries live streams
    wfile.flush()


def _is_event_stream(headers: H.Headers) -> bool:
    content_type = (headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    return content_type == "text/event-stream"


def _wants_close(headers: H.Headers, version: str) -> bool:
    tokens = {
        token.strip().lower()
        for value in headers.get_all("connection") + headers.get_all("proxy-connection")
        for token in value.split(",")
    }
    if "close" in tokens:
        return True
    return version == "HTTP/1.0" and "keep-alive" not in tokens


def _pump(a: socket.socket, b: socket.socket, idle_timeout: float) -> tuple[int, int]:
    """Blindly relay bytes between two sockets until either side hangs up."""
    a.setblocking(True)
    b.setblocking(True)
    a.settimeout(None)
    b.settimeout(None)
    totals = {a: 0, b: 0}

    # select() only sees the TCP layer, so decrypted bytes already sitting in an
    # SSLSocket's buffer would never wake it up. Flush those across first.
    for source, target in ((a, b), (b, a)):
        pending = getattr(source, "pending", lambda: 0)()
        while pending:
            chunk = source.recv(pending)
            if not chunk:
                return totals[a], totals[b]
            totals[source] += len(chunk)
            target.sendall(chunk)
            pending = source.pending()

    with selectors.DefaultSelector() as sel:
        try:
            sel.register(a, selectors.EVENT_READ, b)
            sel.register(b, selectors.EVENT_READ, a)
        except (ValueError, OSError):
            return 0, 0
        while True:
            events = sel.select(timeout=idle_timeout)
            if not events:
                break
            for key, _mask in events:
                source: socket.socket = key.fileobj  # type: ignore[assignment]
                target: socket.socket = key.data
                try:
                    chunk = source.recv(65536)
                except OSError:
                    return totals[a], totals[b]
                if not chunk:
                    return totals[a], totals[b]
                try:
                    while True:
                        totals[source] += len(chunk)
                        target.sendall(chunk)
                        pending = getattr(source, "pending", lambda: 0)()
                        if not pending:
                            break
                        chunk = source.recv(pending)
                        if not chunk:
                            return totals[a], totals[b]
                except OSError:
                    return totals[a], totals[b]
    return totals[a], totals[b]

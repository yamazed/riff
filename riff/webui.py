"""The local web UI: a hardened, loopback-only control surface for the proxy.

Security posture, deliberately conservative because this endpoint can read every
byte of intercepted traffic:

* bound to loopback unless the operator explicitly asks otherwise;
* a random per-run token, delivered once via `?token=` then held in a
  SameSite=Strict, HttpOnly cookie;
* mutating requests must *also* echo the token in `X-Riff-Token`
  (double-submit), so a hostile page cannot drive the UI with the cookie alone;
* the `Host` header is checked against an allowlist, which is what stops
  DNS-rebinding attacks from reaching this server through a victim's browser;
* a strict CSP with no inline script, and no CORS headers at all.
"""

from __future__ import annotations

import json
import mimetypes
import os
import queue
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import replay
from .ca import expires_at, restrict_to_owner
from .hub import Hub
from .scan import DEFAULT_CHECK_NAMES, ScanConfig, Scanner, ScopeError, host_in_scope, targets_from_details
from .scan.active import ACTIVE_CHECKS
from .proxy import Proxy, ProxyError
from .transfer import TransferError, export_har, export_riff, import_flows
from .workspace import Workspace, WorkspaceError, detect_and_import, export_collection_v2, extract_captures, prepare
from .script import Engine
from .script.errors import RiffSyntaxError

def _ui_dir() -> str:
    """Where the SPA lives, in a source checkout or inside a frozen build."""
    bundled = getattr(sys, "_MEIPASS", None)  # set by PyInstaller
    if bundled:
        return os.path.join(bundled, "riff", "ui")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")


UI_DIR = _ui_dir()
STATIC_FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/app.js": "app.js",
    "/compose.js": "compose.js",
    "/app.css": "app.css",
}

CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "font-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)

HEARTBEAT_SECONDS = 15.0


@dataclass(slots=True)
class UiOptions:
    host: str = "127.0.0.1"
    port: int = 8899
    token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    enabled: bool = True


class UiServer:
    def __init__(
        self, options: UiOptions, proxy: Proxy, hub: Hub, script_path: str = "", workspace: Workspace | None = None
    ):
        self.options = options
        self.proxy = proxy
        self.hub = hub
        self.script_path = script_path
        # Saved requests live next to the rules file (shareable); personal
        # values such as tokens stay in the riff home with the CA.
        root = os.path.dirname(os.path.abspath(script_path)) if script_path else proxy.ca.home
        self.workspace = workspace or Workspace(root, proxy.ca.home)
        # The active scanner: idle until the operator starts a scan with an in-scope host.
        self.scanner = Scanner(proxy, hub)
        self._collaborator = None  # lazily started when an out-of-band scan is first requested
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host = self.options.host
        shown = "localhost" if host in ("127.0.0.1", "0.0.0.0", "::1") else host  # nosec B104 - display only, not a bind
        return f"http://{shown}:{self.options.port}/?token={self.options.token}"

    def allowed_hosts(self) -> set[str]:
        port = self.options.port
        names = {"localhost", "127.0.0.1", "[::1]", "::1", self.options.host}
        return {f"{name}:{port}" for name in names} | names

    @property
    def url_file(self) -> str:
        """Where the current UI address is parked so `riff ui` can find it."""
        return os.path.join(self.proxy.ca.home, "ui-url.txt")

    def _write_url_file(self) -> None:
        # The startup banner scrolls away as soon as traffic arrives, so leave
        # the address somewhere a second console can read it. It carries the
        # token, so it is written owner-only, next to the CA.
        try:
            os.makedirs(self.proxy.ca.home, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(self.url_file, flags, 0o600)
            try:
                os.write(fd, (self.url + "\n").encode("utf-8"))
            finally:
                os.close(fd)
            restrict_to_owner(self.url_file)
        except OSError:
            pass  # `riff ui` simply will not find it; the banner still works

    def _remove_url_file(self) -> None:
        try:
            os.remove(self.url_file)
        except OSError:
            pass

    def start(self) -> None:
        handler = _make_handler(self)
        self._server = ThreadingHTTPServer((self.options.host, self.options.port), handler)
        self._server.daemon_threads = True
        self.options.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name="riff-ui")
        self._thread.start()
        self._write_url_file()

    def stop(self) -> None:
        self._remove_url_file()
        if self._collaborator is not None:
            self._collaborator.stop()
            self._collaborator = None
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def ensure_collaborator(self):
        """Start a loopback out-of-band collaborator on first use, and reuse it."""
        if self._collaborator is None:
            from .scan import Collaborator

            self._collaborator = Collaborator(host="127.0.0.1").start()
        return self._collaborator

    # -- actions the UI can trigger ---------------------------------------

    def load_script(self, source: str) -> Engine:
        """Parse `source`, and on success swap it into the running proxy."""
        engine = Engine.from_source(source, self.script_path or "<ui>")
        self.proxy.engine = engine
        return engine

    def save_script(self, source: str) -> Engine:
        engine = self.load_script(source)
        if self.script_path:
            with open(self.script_path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(source)
        return engine

    def current_script(self) -> str:
        if self.script_path and os.path.exists(self.script_path):
            with open(self.script_path, "r", encoding="utf-8") as fh:
                return fh.read()
        return ""


def _make_handler(ui: UiServer):
    class Handler(BaseHTTPRequestHandler):
        server_version = "riff-ui"
        protocol_version = "HTTP/1.1"

        # -- plumbing --------------------------------------------------------

        def log_message(self, *args) -> None:  # keep the console for traffic only
            pass

        def _security_headers(self) -> None:
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")

        def _send(self, status: int, body: bytes, content_type: str, extra: list[tuple[str, str]] = ()) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self._security_headers()
            for key, value in extra:
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, payload) -> None:
            self._send(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

        def _fail(self, status: int, message: str) -> None:
            self._json(status, {"error": message})

        # -- guards ----------------------------------------------------------

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").strip().lower()
            return host in {h.lower() for h in ui.allowed_hosts()}

        def _cookie_token(self) -> str:
            raw = self.headers.get("Cookie") or ""
            for chunk in raw.split(";"):
                name, _, value = chunk.strip().partition("=")
                if name == "riff_token":
                    return value
            return ""

        def _authorised(self, mutating: bool) -> bool:
            token = ui.options.token
            header = self.headers.get("X-Riff-Token") or ""
            if mutating:
                # Double-submit: the cookie alone must never be enough.
                return secrets.compare_digest(header, token)
            return secrets.compare_digest(self._cookie_token(), token) or secrets.compare_digest(header, token)

        # -- verbs -----------------------------------------------------------

        def do_GET(self) -> None:
            self._handle("GET")

        def do_HEAD(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

        def do_PUT(self) -> None:
            self._handle("PUT")

        def do_DELETE(self) -> None:
            self._handle("DELETE")

        def _handle(self, verb: str) -> None:
            if not self._host_ok():
                self._fail(421, "unrecognised Host header — refusing to serve (DNS-rebinding guard)")
                return
            parsed = urlsplit(self.path)
            path, params = parsed.path, parse_qs(parsed.query)

            # The one unauthenticated route: the token hand-off that sets the cookie.
            if verb == "GET" and path in ("/", "/index.html"):
                supplied = (params.get("token") or [""])[0]
                if secrets.compare_digest(supplied, ui.options.token):
                    self._send(
                        302,
                        b"",
                        "text/plain",
                        [
                            ("Location", "/"),
                            (
                                "Set-Cookie",
                                f"riff_token={ui.options.token}; Path=/; HttpOnly; SameSite=Strict",
                            ),
                        ],
                    )
                    return
                if not self._authorised(mutating=False):
                    self._send(
                        401,
                        b"riff: this page needs the access token.\n\n"
                        b"Run  riff ui --open  in a terminal to open it with the token,\n"
                        b"or  riff ui  to print the address.\n",
                        "text/plain; charset=utf-8",
                    )
                    return

            mutating = verb in ("POST", "PUT", "DELETE")
            if not self._authorised(mutating=mutating):
                self._fail(401, "missing or invalid riff token")
                return

            if verb == "GET" and path in STATIC_FILES:
                self._static(STATIC_FILES[path])
                return
            handler = _ROUTES.get((verb, path))
            if handler is None and path.startswith("/api/flow/"):
                handler = _flow_detail if verb == "GET" else None
            if handler is None:
                for prefix, table in _PREFIX_ROUTES:
                    if path.startswith(prefix):
                        handler = table.get(verb)
                        break
            if handler is None:
                self._fail(404, f"no route for {verb} {path}")
                return
            try:
                handler(self, params)
            except BrokenPipeError:
                pass
            except Exception as exc:  # pragma: no cover - defensive
                self._fail(500, f"{type(exc).__name__}: {exc}")

        # -- payload helpers -------------------------------------------------

        def _body(self) -> bytes:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return b""
            return self.rfile.read(min(length, 32 * 1024 * 1024)) if length > 0 else b""

        def _json_body(self) -> dict:
            raw = self._body()
            if not raw:
                return {}
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProxyError(f"request body is not valid JSON: {exc}") from None
            return value if isinstance(value, dict) else {}

        def _static(self, name: str) -> None:
            target = os.path.join(UI_DIR, name)
            try:
                with open(target, "rb") as fh:
                    body = fh.read()
            except OSError:
                self._fail(404, f"{name} is missing from the installation")
                return
            guessed = mimetypes.guess_type(name)[0] or "application/octet-stream"
            if guessed.startswith("text/") or guessed in ("application/javascript",):
                guessed += "; charset=utf-8"
            self._send(200, body, guessed)

        # -- SSE -------------------------------------------------------------

        def stream(self) -> None:
            channel = ui.hub.subscribe()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self._security_headers()
            self.end_headers()
            self.close_connection = True
            try:
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                last_beat = time.time()
                while True:
                    try:
                        message = channel.get(timeout=1.0)
                    except queue.Empty:
                        if time.time() - last_beat > HEARTBEAT_SECONDS:
                            self.wfile.write(b": ping\n\n")
                            self.wfile.flush()
                            last_beat = time.time()
                        continue
                    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
                    self.wfile.write(b"data: " + payload + b"\n\n")
                    self.wfile.flush()
                    last_beat = time.time()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                ui.hub.unsubscribe(channel)

    # -- routes ---------------------------------------------------------------

    def _flow_detail(handler: "Handler", params) -> None:
        try:
            flow_id = int(urlsplit(handler.path).path.rsplit("/", 1)[-1])
        except ValueError:
            handler._fail(400, "flow id must be a number")
            return
        detail = ui.hub.detail(flow_id)
        if detail is None:
            handler._fail(404, f"flow {flow_id} is not in the buffer")
            return
        handler._json(200, detail)

    def _flows(handler: "Handler", params) -> None:
        since = int((params.get("since") or ["0"])[0] or 0)
        handler._json(200, {"flows": ui.hub.list(since=since)})

    def _stream(handler: "Handler", params) -> None:
        handler.stream()

    def _stats(handler: "Handler", params) -> None:
        handler._json(200, ui.hub.stats())

    def _findings(handler: "Handler", params) -> None:
        handler._json(200, {"findings": ui.hub.finding_rows(), "counts": ui.hub.finding_counts(),
                            "enabled": ui.hub.scan_enabled})

    def _findings_clear(handler: "Handler", params) -> None:
        ui.hub.clear_findings()
        handler._json(200, {"ok": True})

    def _findings_rescan(handler: "Handler", params) -> None:
        total = ui.hub.rescan()
        handler._json(200, {"total": total, "counts": ui.hub.finding_counts()})

    # -- active scanner ---------------------------------------------------

    def _scan_info(handler: "Handler", params) -> None:
        """What can be scanned: the distinct in-buffer hosts, and the available checks."""
        hosts = sorted({row["host"] for row in ui.hub.list(limit=ui.hub.capacity) if row.get("host")})
        checks = [{"name": c.name, "default_on": c.default_on} for c in ACTIVE_CHECKS]
        handler._json(200, {"hosts": hosts, "checks": checks, "jobs": ui.scanner.jobs()})

    def _scan_start(handler: "Handler", params) -> None:
        payload = handler._json_body()
        hosts = tuple(h.strip() for h in (payload.get("hosts") or []) if isinstance(h, str) and h.strip())
        if not hosts:
            handler._fail(400, "a scan needs at least one in-scope host (you must name what you are authorised to test)")
            return
        ids = payload.get("ids")
        if ids:
            details = [d for d in (ui.hub.detail(int(i)) for i in ids) if d is not None]
        else:
            rows = ui.hub.list(limit=ui.hub.capacity)
            details = [d for d in (ui.hub.detail(r["id"]) for r in rows) if d is not None]
        targets = targets_from_details(details)
        check_names = payload.get("checks")
        if check_names is not None:
            check_names = tuple(str(c) for c in check_names)
        collaborator = ui.ensure_collaborator() if payload.get("oob") else None
        config = ScanConfig(
            allowed_hosts=hosts,
            check_names=check_names,
            max_points_per_flow=int(payload.get("max_points", 40)),
            max_workers=int(payload.get("max_workers", 6)),
            delay_ms=int(payload.get("delay_ms", 0)),
            time_delay_s=float(payload.get("time_delay_s", 3.0)),
            collaborator=collaborator,
        )
        try:
            job = ui.scanner.start(targets, config)
        except ScopeError as exc:
            handler._fail(400, str(exc))
            return
        handler._json(200, job.public())

    def _scan_status(handler: "Handler", params) -> None:
        raw = (params.get("id") or [""])[0]
        if raw:
            job = ui.scanner.job(int(raw))
            if job is None:
                handler._fail(404, "no such scan job")
                return
            handler._json(200, job.public())
            return
        handler._json(200, {"jobs": ui.scanner.jobs()})

    def _scan_cancel(handler: "Handler", params) -> None:
        payload = handler._json_body()
        ok = ui.scanner.cancel(int(payload.get("id", 0)))
        handler._json(200, {"cancelled": ok})

    def _csrf(handler: "Handler", params) -> None:
        # Safe to hand back: the same-origin policy stops a hostile page from
        # reading this response, so only our own UI can learn the token and
        # complete the double-submit on mutating calls.
        handler._json(200, {"token": ui.options.token})

    def _config(handler: "Handler", params) -> None:
        ca = ui.proxy.ca
        cert, _ = ca.load_or_create()
        handler._json(
            200,
            {
                "version": __import__("riff").__version__,
                "proxy": {"host": ui.proxy.address[0], "port": ui.proxy.address[1]},
                "ui": {"host": ui.options.host, "port": ui.options.port},
                "ca": {
                    "path": ca.ca_cert_path,
                    "fingerprint": ca.fingerprint(),
                    "expires": expires_at(cert).isoformat(),
                },
                "script": {"path": ui.script_path, "rules": ui.proxy.engine.rule_count},
                "tls_rules": [{"mode": m, "pattern": p} for m, p in ui.proxy.engine.tls_rules],
                "verify_upstream": ui.proxy.options.verify_upstream,
                "max_body": ui.proxy.options.max_body,
            },
        )

    def _clear(handler: "Handler", params) -> None:
        ui.hub.clear()
        handler._json(200, {"ok": True})

    def _script_get(handler: "Handler", params) -> None:
        handler._json(
            200,
            {
                "path": ui.script_path,
                "source": ui.current_script(),
                "rules": ui.proxy.engine.rule_count,
                "counters": dict(ui.proxy.engine.counters),
            },
        )

    def _script_put(handler: "Handler", params) -> None:
        source = handler._json_body().get("source", "")
        try:
            engine = ui.save_script(source)
        except RiffSyntaxError as exc:
            handler._json(400, {"error": exc.message, "line": exc.line, "col": exc.col, "render": exc.render()})
            return
        except OSError as exc:
            handler._fail(500, f"could not write {ui.script_path}: {exc}")
            return
        handler._json(200, {"ok": True, "rules": engine.rule_count, "saved": bool(ui.script_path)})

    def _script_check(handler: "Handler", params) -> None:
        source = handler._json_body().get("source", "")
        try:
            engine = Engine.from_source(source, "<check>")
        except RiffSyntaxError as exc:
            handler._json(200, {"ok": False, "error": exc.message, "line": exc.line, "col": exc.col})
            return
        handler._json(200, {"ok": True, "rules": engine.rule_count})

    def _replay(handler: "Handler", params) -> None:
        payload = handler._json_body()
        apply_rules = bool(payload.get("apply_rules", True))
        if "id" in payload:
            detail = ui.hub.detail(int(payload["id"]))
            if detail is None:
                handler._fail(404, "that flow is no longer buffered")
                return
            source = detail["request"]
            method, url = source["method"], source["url"]
            headers = [(k, v) for k, v in source["headers"]]
            body = (source.get("body") or {}).get("text", "") or ""
        else:
            method = payload.get("method", "GET")
            url = payload.get("url", "")
            headers = [(k, v) for k, v in (payload.get("headers") or [])]
            body = payload.get("body", "") or ""
        try:
            request = replay.build_request(method, url, headers, body.encode("utf-8"))
        except ProxyError as exc:
            handler._fail(400, str(exc))
            return
        flow = replay.send(ui.proxy, request, apply_rules=apply_rules)
        handler._json(200, {"id": flow.id, "error": flow.error})

    def _export(handler: "Handler", params) -> None:
        """Selected flows as a file: riff's own JSON (lossless) or HAR 1.2."""
        fmt = (params.get("format") or ["riff"])[0].lower()
        if fmt not in ("riff", "har"):
            handler._fail(400, "format must be 'riff' or 'har'")
            return
        raw_ids = (params.get("ids") or [""])[0]
        try:
            ids = [int(part) for part in raw_ids.split(",") if part.strip()]
        except ValueError:
            handler._fail(400, "ids must be a comma-separated list of flow numbers")
            return
        if not ids:
            ids = [row["id"] for row in ui.hub.list(limit=ui.hub.capacity)]
        details = [d for d in (ui.hub.detail(i) for i in ids) if d is not None]
        if not details:
            handler._fail(404, "none of those flows are in the buffer")
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        if fmt == "har":
            payload, name = export_har(details), f"riff-{stamp}.har"
        else:
            payload, name = export_riff(details), f"riff-{stamp}.json"
        body = json.dumps(payload, indent=1).encode("utf-8")
        handler._send(
            200,
            body,
            "application/json; charset=utf-8",
            [("Content-Disposition", f'attachment; filename="{name}"'), ("X-Riff-Exported", str(len(details)))],
        )

    def _import(handler: "Handler", params) -> None:
        """Load a riff export or HAR file into the buffer, tagged `imported`."""
        raw = handler._body()
        if not raw:
            handler._fail(400, "send the file's JSON as the request body")
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            handler._fail(400, f"that file is not valid JSON: {exc}")
            return
        try:
            flows = import_flows(payload)
        except TransferError as exc:
            handler._fail(400, str(exc))
            return
        ids = []
        for flow in flows:
            flow.id = ui.proxy.flow_ids.next()
            ui.hub.on_flow(flow)
            ids.append(flow.id)
        handler._json(200, {"imported": len(ids), "ids": ids})

    # -- composer workspace: collections, environments, personal values, send --------

    def _tail(handler: "Handler", prefix: str) -> str:
        return urlsplit(handler.path).path[len(prefix):].strip("/")

    def _ws(handler: "Handler", action):
        try:
            return action()
        except WorkspaceError as exc:
            handler._fail(400, str(exc))
            return None

    def _collections(handler: "Handler", params) -> None:
        listing = _ws(handler, ui.workspace.list_collections)
        if listing is not None:
            handler._json(200, {"collections": listing})

    def _collection(handler: "Handler", params) -> None:
        """GET one, PUT (create or replace) one, DELETE one: /api/collections/<slug>."""
        slug = _tail(handler, "/api/collections")
        if not slug:
            _collections(handler, params)
            return
        if slug.endswith("/export"):
            _collection_export(handler, params, slug[: -len("/export")])
            return
        verb = handler.command
        if verb == "GET":
            doc = _ws(handler, lambda: ui.workspace.load_collection(slug))
            if doc is not None:
                handler._json(200, doc)
        elif verb == "PUT":
            body = handler._json_body()
            doc = _ws(handler, lambda: ui.workspace.save_collection(slug, body))
            if doc is not None:
                handler._json(200, {"ok": True, "slug": slug, "requests": len(doc["requests"])})
        elif verb == "DELETE":
            if _ws(handler, lambda: (ui.workspace.delete_collection(slug), True)[1]):
                handler._json(200, {"ok": True})
        else:
            handler._fail(405, "method not allowed")

    def _collection_create(handler: "Handler", params) -> None:
        """POST /api/collections {name} -> a new, empty collection with a fresh slug."""
        body = handler._json_body()
        result = _ws(handler, lambda: ui.workspace.create_collection(str(body.get("name") or "")))
        if result is not None:
            slug, doc = result
            handler._json(200, {"ok": True, "slug": slug, "name": doc["name"]})

    def _collection_import(handler: "Handler", params) -> None:
        """POST /api/collections/import: a riff collection, a v2.1 collection or HAR."""
        raw = handler._body()
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            handler._fail(400, f"that file is not valid JSON: {exc}")
            return
        name = (params.get("name") or [""])[0]

        def do():
            doc = detect_and_import(payload, name=name)
            slug, _ = ui.workspace.create_collection(doc["name"])
            return slug, ui.workspace.save_collection(slug, doc)

        result = _ws(handler, do)
        if result is not None:
            slug, doc = result
            handler._json(200, {"ok": True, "slug": slug, "name": doc["name"], "requests": len(doc["requests"])})

    def _collection_export(handler: "Handler", params, slug: str) -> None:
        fmt = (params.get("format") or ["v2"])[0].lower()
        if fmt not in ("v2", "riff"):
            handler._fail(400, "format must be 'v2' or 'riff'")
            return
        doc = _ws(handler, lambda: ui.workspace.load_collection(slug))
        if doc is None:
            return
        payload = export_collection_v2(doc) if fmt == "v2" else doc
        name = f"{slug}.collection-v2.json" if fmt == "v2" else f"{slug}.riff-collection.json"
        handler._send(
            200,
            json.dumps(payload, indent=2).encode("utf-8"),
            "application/json; charset=utf-8",
            [("Content-Disposition", f'attachment; filename="{name}"')],
        )

    def _environments(handler: "Handler", params) -> None:
        listing = _ws(handler, ui.workspace.list_environments)
        if listing is not None:
            handler._json(200, {"environments": listing})

    def _environment(handler: "Handler", params) -> None:
        """/api/environments/<name>: GET shared+personal values, PUT shared values, DELETE."""
        name = _tail(handler, "/api/environments")
        if not name:
            _environments(handler, params)
            return
        verb = handler.command
        if verb == "GET":
            def load():
                doc = ui.workspace.load_environment(name)
                doc["personal"] = ui.workspace.personal(name)
                return doc
            doc = _ws(handler, load)
            if doc is not None:
                handler._json(200, doc)
        elif verb == "PUT":
            body = handler._json_body()
            doc = _ws(handler, lambda: ui.workspace.save_environment(name, body.get("values") or {}))
            if doc is not None:
                handler._json(200, {"ok": True, "name": name, "values": len(doc["values"])})
        elif verb == "DELETE":
            if _ws(handler, lambda: (ui.workspace.delete_environment(name), True)[1]):
                handler._json(200, {"ok": True})
        else:
            handler._fail(405, "method not allowed")

    def _personal(handler: "Handler", params) -> None:
        """GET/PUT /api/personal?environment=<name|*>: this machine's private values."""
        env = (params.get("environment") or ["*"])[0] or "*"
        if handler.command == "GET":
            values = _ws(handler, lambda: ui.workspace.personal(env))
            if values is not None:
                handler._json(200, {"environment": env, "values": values})
            return
        body = handler._json_body()
        values = _ws(handler, lambda: ui.workspace.set_personal(env, body.get("values") or {}, merge=bool(body.get("merge"))))
        if values is not None:
            handler._json(200, {"ok": True, "environment": env, "values": len(values)})

    def _send(handler: "Handler", params) -> None:
        """POST /api/send: a composer request, resolved against an environment, sent through riff."""
        body = handler._json_body()
        request = body.get("request")
        if not isinstance(request, dict):
            handler._fail(400, "send needs a `request` object")
            return
        environment = str(body.get("environment") or "")
        slug = str(body.get("collection") or "")
        apply_rules = bool(body.get("apply_rules", True))

        def build():
            collection = ui.workspace.load_collection(slug) if slug else None
            variables = ui.workspace.variables(environment, collection)
            return prepare(request, variables, (collection or {}).get("auth")), variables

        built = _ws(handler, build)
        if built is None:
            return
        prepared, _variables = built
        if any(token in prepared.url for token in ("{{", "%7B%7B")):
            handler._json(400, {"error": "the URL still has unresolved variables: " + ", ".join(prepared.missing), "missing": prepared.missing})
            return
        try:
            outgoing = replay.build_request(prepared.method, prepared.url, prepared.headers, prepared.body)
        except ProxyError as exc:
            handler._fail(400, str(exc))
            return
        flow = replay.send(ui.proxy, outgoing, apply_rules=apply_rules)
        captured = {}
        if not flow.error and request.get("capture"):
            try:
                captured = extract_captures(request.get("capture") or [], flow)
                if captured:
                    ui.workspace.set_personal(environment or "*", captured, merge=True)
            except WorkspaceError as exc:
                captured = {"_error": str(exc)}
        handler._json(
            200,
            {
                "id": flow.id,
                "error": flow.error,
                "status": flow.response.status if flow.response else 0,
                "duration_ms": round(flow.duration_ms, 1),
                "missing": prepared.missing,
                "captured": captured,
                "detail": ui.hub.detail(flow.id),
            },
        )

    def _ca_download(handler: "Handler", params) -> None:
        path = ui.proxy.ca.ca_cert_path
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except OSError as exc:
            handler._fail(500, f"cannot read the CA certificate: {exc}")
            return
        handler._send(
            200,
            body,
            "application/x-x509-ca-cert",
            [("Content-Disposition", 'attachment; filename="riff-ca.crt"')],
        )

    _ROUTES = {
        ("GET", "/api/flows"): _flows,
        ("GET", "/api/stream"): _stream,
        ("GET", "/api/stats"): _stats,
        ("GET", "/api/findings"): _findings,
        ("POST", "/api/findings/clear"): _findings_clear,
        ("POST", "/api/findings/rescan"): _findings_rescan,
        ("GET", "/api/scan"): _scan_info,
        ("POST", "/api/scan"): _scan_start,
        ("GET", "/api/scan/status"): _scan_status,
        ("POST", "/api/scan/cancel"): _scan_cancel,
        ("GET", "/api/csrf"): _csrf,
        ("GET", "/api/config"): _config,
        ("GET", "/api/script"): _script_get,
        ("PUT", "/api/script"): _script_put,
        ("GET", "/api/ca.crt"): _ca_download,
        ("GET", "/api/export"): _export,
        ("POST", "/api/import"): _import,
        ("GET", "/api/collections"): _collections,
        ("POST", "/api/collections"): _collection_create,
        ("POST", "/api/collections/import"): _collection_import,
        ("GET", "/api/environments"): _environments,
        ("GET", "/api/personal"): _personal,
        ("PUT", "/api/personal"): _personal,
        ("POST", "/api/send"): _send,
        ("POST", "/api/clear"): _clear,
        ("POST", "/api/script/check"): _script_check,
        ("POST", "/api/replay"): _replay,
    }

    _PREFIX_ROUTES = (
        ("/api/collections/", {"GET": _collection, "PUT": _collection, "DELETE": _collection}),
        ("/api/environments/", {"GET": _environment, "PUT": _environment, "DELETE": _environment}),
    )

    return Handler

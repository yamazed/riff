"""A small demo web app for exercising riff, on loopback only.

It serves three things:

* a JSON API under ``/v1`` with a realistic spread of outcomes — success,
  a 500, a 403, a 404 and one deliberately slow route — so the traffic list,
  the rule tags and the detail tabs all have something to show;
* a few HTML pages, so a browser pointed through riff produces page loads
  and static assets rather than bare API calls;
* a handful of **deliberately vulnerable** endpoints that riff's scanner is
  meant to find.

.. warning::
   The ``/shop``, ``/item`` and ``/go`` routes are insecure *on purpose*:
   reflected XSS, a SQL error leak and an open redirect, plus a cookie with
   no flags and a version banner. That is the point — they give the scanner
   something real to detect. The server binds ``127.0.0.1`` and refuses any
   other address unless you pass ``--unsafe-host``. Do not expose it.

Run it with::

    python -m demo.app --port 8123           # plain HTTP
    python -m demo.app --tls --port 8443     # HTTPS, self-signed

``--tls`` mints a throwaway self-signed certificate at startup, so riff has a
real TLS origin to intercept. Nothing is written to the repo, and the origin
certificate is *not* trusted by anything, so point riff at it with
``riff run --insecure``.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import http.server
import json
import os
import socketserver
import ssl
import tempfile
import threading
import time
import urllib.parse

VERSION_BANNER = "DemoShop/1.4.2"  # a version banner the scanner will flag

USERS = [
    {"id": 1, "name": "Ada Lovelace", "email": "ada@example.com", "role": "admin"},
    {"id": 2, "name": "Grace Hopper", "email": "grace@example.com", "role": "engineer"},
    {"id": 3, "name": "Alan Turing", "email": "alan@example.com", "role": "engineer"},
    {"id": 4, "name": "Katherine Johnson", "email": "katherine@example.com", "role": "analyst"},
]

FLAGS = {"new-checkout": True, "dark-mode": True, "beta-search": False, "audit-log": True}

APP_JS = b"""// demo static asset - riff tags this 'static'
(function () {
  const boot = () => console.log("demo app ready");
  document.readyState === "loading"
    ? document.addEventListener("DOMContentLoaded", boot)
    : boot();
})();
"""

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{title} · DemoShop</title>
<script src="/assets/app.js" defer></script>
<style>
  body {{ font: 15px/1.6 system-ui, sans-serif; margin: 0; background: #0f1115; color: #e6e8ee; }}
  header {{ padding: 18px 28px; border-bottom: 1px solid #262a33; display: flex; gap: 22px; align-items: baseline; }}
  header b {{ font-size: 18px; }}
  a {{ color: #7aa2f7; text-decoration: none; }}
  main {{ padding: 28px; max-width: 760px; }}
  h1 {{ margin: 0 0 12px; font-size: 24px; }}
  li {{ margin: 6px 0; }}
</style></head>
<body>
<header><b>DemoShop</b>
  <a href="/">Home</a><a href="/news">News</a><a href="/products">Products</a><a href="/shop?q=widget">Search</a>
</header>
<main><h1>{title}</h1>{body}</main>
</body></html>
"""


def _page(title: str, body: str) -> bytes:
    return PAGE.format(title=title, body=body).encode("utf-8")


class DemoHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = VERSION_BANNER

    def log_message(self, *args) -> None:  # keep the console for riff's output
        pass

    # -- helpers ---------------------------------------------------------

    def _send(self, body: bytes, status: int = 200, ctype: str = "text/html; charset=utf-8", extra=()) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        # No Secure / HttpOnly / SameSite: the passive scanner flags this.
        self.send_header("Set-Cookie", "sid=8f3a1c; Path=/")
        for key, value in extra:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload, status: int = 200, extra=()) -> None:
        self._send(json.dumps(payload, indent=2).encode("utf-8"), status, "application/json", extra)

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    # -- routing ---------------------------------------------------------

    def do_GET(self) -> None:
        parts = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(parts.query)
        path = parts.path
        one = lambda key: (params.get(key) or [""])[0]  # noqa: E731

        # ---- static ----
        if path == "/assets/app.js":
            self._send(APP_JS, ctype="application/javascript")
            return

        # ---- deliberately vulnerable ----
        if path == "/go" and one("next"):  # open redirect
            self._send(b"", status=302, extra=[("Location", one("next"))])
            return
        if path == "/item":  # SQL error leaked on a stray quote
            ident = one("id")
            if "'" in ident:
                self._send(
                    b"<html><body>SQL error: unclosed quotation mark after the "
                    b"character string near ''</body></html>",
                    status=500,
                )
                return
            self._send(_page(f"Item {ident or '—'}", "<p>Blue Widget, 9.99, in stock.</p>"))
            return
        if path == "/shop":  # reflected XSS: q goes straight into the page
            query = one("q")
            self._send(_page(
                "Search",
                f"<p>Results for {query}</p><ul><li>Blue Widget</li><li>Red Widget</li></ul>",
            ))
            return

        # ---- JSON API ----
        if path == "/v1/users":
            self._json(USERS)
            return
        if path.startswith("/v1/users/"):
            ident = path.rsplit("/", 1)[-1]
            match = next((u for u in USERS if str(u["id"]) == ident), None)
            self._json(match or {"error": "no such user", "id": ident}, 200 if match else 404)
            return
        if path == "/v1/flags":
            self._json(FLAGS)
            return
        if path == "/v1/report":
            self._json({
                "generated": "2026-01-14T09:31:00Z",
                "window": "last 30 days",
                "totals": {"orders": 1284, "revenue": 98231.55, "refunds": 37},
                "by_region": [
                    {"region": r, "orders": n, "revenue": v}
                    for r, n, v in (("north", 412, 31890.10), ("south", 388, 29104.75),
                                    ("east", 297, 22556.40), ("west", 187, 14680.30))
                ],
            })
            return
        if path == "/v1/orders":  # 500 -> tagged server-error by the rules
            self._json({"error": "upstream order service unavailable"}, 500)
            return
        if path == "/v1/secret":  # 403 -> tagged auth
            self._json({"error": "forbidden"}, 403)
            return
        if path == "/v1/search":  # deliberately slow -> tagged slow
            time.sleep(2.4)
            self._json({"query": one("q") or "widget", "hits": 3, "took_ms": 2400})
            return

        # ---- HTML pages ----
        if path == "/":
            self._send(_page("Everything for the well-equipped workshop", """
              <p>A stand-in storefront for trying riff against something that behaves
                 like a real site: HTML, a static asset and a JSON API.</p>
              <ul><li><a href="/news">Latest news</a></li>
                  <li><a href="/products">Products</a></li>
                  <li><a href="/v1/users">API: users</a></li></ul>"""))
            return
        if path == "/news":
            self._send(_page("News", """
              <ul><li>Widget production up 12% this quarter</li>
                  <li>New east-region distribution centre opens</li>
                  <li>Refund policy updated for bulk orders</li></ul>"""))
            return
        if path == "/products":
            self._send(_page("Products", """
              <ul><li>Blue Widget — 9.99</li><li>Red Widget — 11.50</li>
                  <li>Widget Multipack — 44.00</li></ul>"""))
            return

        self._json({"error": "not found", "path": path}, 404)

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        raw = self._body()
        if path == "/v1/session":
            self._json({"token": "demo-session-2f9c41", "expires_in": 3600}, 201)
            return
        if path == "/v1/users":
            try:
                sent = json.loads(raw or b"{}")
            except ValueError:
                self._json({"error": "invalid json"}, 400)
                return
            self._json({**sent, "id": len(USERS) + 1}, 200)
            return
        self._json({"error": "not found", "path": path}, 404)

    def do_PUT(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        raw = self._body()
        if path.startswith("/v1/users/"):
            try:
                sent = json.loads(raw or b"{}")
            except ValueError:
                self._json({"error": "invalid json"}, 400)
                return
            self._json({**sent, "id": int(path.rsplit("/", 1)[-1] or 0)}, 200)
            return
        self._json({"error": "not found", "path": path}, 404)

    def do_DELETE(self) -> None:
        self._json({"error": "no such user"}, 404)

    def do_HEAD(self) -> None:
        self.do_GET()


def self_signed(host: str = "localhost") -> tuple[str, str]:
    """Mint a throwaway self-signed cert/key pair in a temp dir; return their paths.

    Only good enough to give riff a real TLS origin to intercept. Nothing
    trusts it, which is why the shoots run `riff run --insecure`.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host), x509.DNSName("localhost"),
                                         x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    out = tempfile.mkdtemp(prefix="demo-app-tls-")
    cert_path, key_path = os.path.join(out, "cert.pem"), os.path.join(out, "key.pem")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    return cert_path, key_path


def _wrap_tls(httpd: socketserver.TCPServer, host: str) -> socketserver.TCPServer:
    cert_path, key_path = self_signed(host)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # PROTOCOL_TLS_SERVER on its own still permits TLS 1.0 and 1.1. This app is
    # insecure on purpose in its *routes*; its transport should not be.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    return httpd


def serve(port: int = 8123, host: str = "127.0.0.1", *, tls: bool = False) -> socketserver.TCPServer:
    """Start the demo app on a background thread and return the server."""
    httpd = http.server.ThreadingHTTPServer((host, port), DemoHandler)
    if tls:
        _wrap_tls(httpd, host)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", type=int, default=8123)
    ap.add_argument("--tls", action="store_true", help="serve HTTPS with a throwaway self-signed certificate")
    ap.add_argument(
        "--unsafe-host",
        default="",
        metavar="ADDR",
        help="bind somewhere other than 127.0.0.1 (this app is vulnerable on purpose; don't)",
    )
    args = ap.parse_args()
    host = args.unsafe_host or "127.0.0.1"
    if host != "127.0.0.1":
        print(f"!! binding {host} - this app is deliberately vulnerable. Do not expose it.")
    httpd = http.server.ThreadingHTTPServer((host, args.port), DemoHandler)
    if args.tls:
        _wrap_tls(httpd, host)
    scheme = "https" if args.tls else "http"
    print(f"demo app on {scheme}://{host}:{args.port}  (Ctrl-C to stop)")
    if args.tls:
        print("  self-signed origin: point riff at it with `riff run --insecure`")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        with contextlib.suppress(OSError):
            httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

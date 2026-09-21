"""Drive a run of demo traffic through riff, for screenshots and demos.

Sends a fixed sequence against :mod:`demo.app` so the traffic list always has
the same spread: successes, a 500, a 403, a 404, a static asset and one slow
request. Point it at riff's proxy port so the flows are captured::

    python -m demo.app --port 8123 &
    riff run -p 8888 --ui-port 8899 -s examples/starter.riff
    python -m demo.traffic --proxy 127.0.0.1:8888 --app 127.0.0.1:8123
"""

from __future__ import annotations

import argparse
import http.client
import json

# (method, path, body) — the order the flow list shows them in.
SEQUENCE = [
    ("GET", "/v1/users", None),
    ("GET", "/v1/users/1", None),
    ("GET", "/v1/flags", None),
    ("GET", "/assets/app.js", None),
    ("GET", "/v1/report", None),
    ("POST", "/v1/session", {"email": "ada@example.com", "password": "hunter2"}),
    ("GET", "/v1/orders", None),
    ("GET", "/v1/secret", None),
    ("GET", "/v1/missing", None),
    ("POST", "/v1/users", {"name": "Edsger Dijkstra", "email": "edsger@example.com", "role": "engineer"}),
    ("PUT", "/v1/users/1", {"name": "Ada Lovelace", "email": "ada@example.com", "role": "owner"}),
    ("DELETE", "/v1/users/9", None),
    ("GET", "/v1/search?q=widget", None),  # slow, on purpose — leave it last
]


def run(proxy: str, app: str, *, quiet: bool = False) -> int:
    proxy_host, _, proxy_port = proxy.partition(":")
    sent = 0
    for method, path, payload in SEQUENCE:
        conn = http.client.HTTPConnection(proxy_host, int(proxy_port or 8888), timeout=30)
        headers = {
            "Host": app,
            "Accept": "application/json",
            "User-Agent": "demo-traffic/1.0",
            "Authorization": "Bearer demo-token-9f21ac",
        }
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            # absolute-form request line: this is how a client talks to a proxy
            conn.request(method, f"http://{app}{path}", body=body, headers=headers)
            response = conn.getresponse()
            response.read()
            sent += 1
            if not quiet:
                print(f"  {method:6} {response.status}  {path}")
        except OSError as exc:
            print(f"  {method:6} ---  {path}  ({exc})")
        finally:
            conn.close()
    return sent


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--proxy", default="127.0.0.1:8888", help="riff's proxy address")
    ap.add_argument("--app", default="127.0.0.1:8123", help="where demo.app is listening")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    sent = run(args.proxy, args.app, quiet=args.quiet)
    print(f"sent {sent}/{len(SEQUENCE)} requests through {args.proxy}")
    return 0 if sent == len(SEQUENCE) else 1


if __name__ == "__main__":
    raise SystemExit(main())

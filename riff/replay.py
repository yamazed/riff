"""Re-issue a request outside the live client connection (the UI's Composer)."""

from __future__ import annotations

import time

from . import http as H
from .flow import DEFAULT_PORTS, Flow, Request, Response
from .proxy import Proxy, ProxyError


def build_request(method: str, url: str, headers: list[tuple[str, str]], body: bytes) -> Request:
    request = Request(method=(method or "GET").upper(), headers=H.Headers(headers), body=body)
    request.set_url(url)
    if not request.host:
        raise ProxyError(f"cannot work out a host from {url!r}")
    request.port = request.port or DEFAULT_PORTS.get(request.scheme, 80)
    return request


def send(proxy: Proxy, request: Request, apply_rules: bool = True, client: str = "composer", tags: tuple[str, ...] = ()) -> Flow:
    """Send `request` upstream and return the completed Flow."""
    flow = Flow(
        id=proxy.flow_ids.next(),
        client=client,
        tls=request.scheme == "https",
        request=request,
    )
    flow.tag("replay")
    for extra in tags:
        flow.tag(extra)

    if apply_rules:
        verdict = proxy.engine.run(flow, "request")
        if verdict.delay_ms:
            time.sleep(verdict.delay_ms / 1000.0)
        if verdict.abort:
            flow.ended = time.time()
            flow.error = "aborted by a rule"
            proxy.observer.on_flow(flow)
            return flow
        if flow.intercepted:
            flow.ended = time.time()
            proxy.observer.on_flow(flow)
            return flow

    response, error, _elapsed = exchange(proxy, request)
    if response is not None:
        flow.response = response
        if apply_rules:
            proxy.engine.run(flow, "response")
    else:
        flow.error = error
    flow.ended = time.time()

    proxy.observer.on_flow(flow)
    return flow


def exchange(proxy: Proxy, request: Request) -> tuple[Response | None, str, float]:
    """Send one request upstream and read the response. No Flow, no observer, no rules.

    Returns `(response, error, seconds)`. This is the quiet primitive the scanner
    drives: a probe must not land in the capture buffer or trigger passive checks,
    so it never goes through the hub. `send` wraps this for the visible Composer path.
    """
    outgoing = request.headers.copy()
    outgoing.strip_hop_by_hop()
    outgoing.set("Host", request.authority)
    outgoing.remove("content-encoding")
    outgoing.set("Content-Length", str(len(request.body)))
    outgoing.set("Accept-Encoding", outgoing.get("accept-encoding") or "gzip, deflate")
    outgoing.set("Connection", "close")

    upstream = None
    started = time.time()
    try:
        upstream = proxy.connect_upstream(request.scheme, request.host, request.port)
        upstream.wfile.write(
            H.build_request(request.method, request.origin_form, "HTTP/1.1", outgoing, request.body)
        )
        upstream.wfile.flush()

        head = H.read_response_head(upstream.rfile)
        while 100 <= head.status < 200 and head.status != 101:
            head = H.read_response_head(upstream.rfile)

        mode, length = H.body_mode(
            head.headers, is_response=True, method=request.method, status=head.status
        )
        raw, truncated = H.read_body_capped(upstream.rfile, mode, length, proxy.options.max_body)
        response = Response(
            version=head.version,
            status=head.status,
            reason=head.reason,
            headers=head.headers,
            body_streamed=truncated,
        )
        if not truncated:
            response.content_encoding = (head.headers.get("content-encoding") or "").lower()
            response.body, response.body_decoded = H.decode_content(raw, response.content_encoding)
        else:
            response.body = raw
        return response, "", time.time() - started
    except (ProxyError, H.HttpError, OSError) as exc:
        return None, str(exc), time.time() - started
    finally:
        if upstream is not None:
            upstream.close()

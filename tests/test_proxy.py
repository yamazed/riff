"""End-to-end: real sockets, real TLS, real HTTP framing."""

from __future__ import annotations

import http.client
import json

import pytest


def get(harness, url, method="GET", body=None, headers=None):
    host, port = harness.address
    conn = http.client.HTTPConnection(host, port, timeout=10)
    try:
        conn.request(method, url, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def get_tls(harness, origin, path, ssl_context, method="GET", body=None, headers=None):
    host, port = harness.address
    conn = http.client.HTTPSConnection(host, port, timeout=10, context=ssl_context)
    try:
        conn.set_tunnel(origin.host, origin.port)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


# ── plain HTTP ──────────────────────────────────────────────────────────


def test_forwards_a_plain_request(make_proxy, origin):
    harness = make_proxy()
    status, headers, body = get(harness, origin.url("/json"))
    assert status == 200
    assert json.loads(body) == {"hello": "world", "n": 1}

    flows = harness.wait_for_flows(1)
    assert len(flows) == 1
    assert flows[0]["method"] == "GET"
    assert flows[0]["status"] == 200
    assert flows[0]["host"] == "127.0.0.1"


def test_hop_by_hop_headers_do_not_reach_the_origin(make_proxy, origin):
    harness = make_proxy()
    _, _, body = get(
        harness,
        origin.url("/echo"),
        headers={"Proxy-Connection": "keep-alive", "X-Keep": "yes", "Connection": "keep-alive"},
    )
    seen = json.loads(body)["headers"]
    assert "proxy-connection" not in seen
    assert seen["x-keep"] == "yes"
    assert seen["host"] == origin.authority


def test_post_body_round_trips(make_proxy, origin):
    harness = make_proxy()
    status, _, body = get(harness, origin.url("/echo"), method="POST", body=b'{"a": 1}',
                          headers={"Content-Type": "application/json"})
    assert status == 200
    assert json.loads(body)["body"] == '{"a": 1}'


def test_keep_alive_carries_several_requests_on_one_connection(make_proxy, origin):
    harness = make_proxy()
    host, port = harness.address
    conn = http.client.HTTPConnection(host, port, timeout=10)
    try:
        for _ in range(3):
            conn.request("GET", origin.url("/json"))
            response = conn.getresponse()
            assert response.status == 200
            response.read()
    finally:
        conn.close()
    assert len(harness.wait_for_flows(3)) == 3


# ── body framing ────────────────────────────────────────────────────────


def test_gzip_is_decoded_for_rules_and_delivered_as_identity(make_proxy, origin):
    harness = make_proxy('on response where body contains "compressed" { tag "saw-json" }')
    status, headers, body = get(harness, origin.url("/gzip"), headers={"Accept-Encoding": "gzip"})
    assert status == 200
    assert "content-encoding" not in {k.lower() for k in headers}
    assert json.loads(body)["compressed"] is True
    assert harness.wait_for_flows(1)[0]["tags"] == ["saw-json"]


def test_chunked_response_is_reframed_with_a_length(make_proxy, origin):
    harness = make_proxy()
    status, headers, body = get(harness, origin.url("/chunked"))
    assert status == 200
    assert body == b"alphabetagamma"
    assert headers["Content-Length"] == "14"


def test_event_streams_are_relayed_as_they_arrive(make_proxy, origin):
    """riff's own UI stream goes through the proxy when the Chrome extension is on: it must not be buffered."""
    import socket
    import time

    harness = make_proxy()
    host, port = harness.address
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(
            f"GET {origin.url('/events')} HTTP/1.1\r\nHost: {origin.authority}\r\nAccept: text/event-stream\r\n\r\n".encode()
        )
        started = time.time()
        got = b""
        while b"data: one" not in got and time.time() - started < 3:
            got += sock.recv(65536)
        first_at = time.time() - started
        assert b"data: one" in got, got
        assert b"data: two" not in got, "the first event must not wait for the second"
        assert first_at < 0.6, f"first event took {first_at:.2f}s: the proxy buffered the stream"
        while b"data: two" not in got:
            chunk = sock.recv(65536)
            if not chunk:
                break
            got += chunk
    assert b"data: two" in got
    head = got.split(b"\r\n\r\n", 1)[0].lower()
    assert b"text/event-stream" in head and b"transfer-encoding: chunked" in head
    flows = harness.wait_for_flows(1)
    assert flows[-1]["status"] == 200 and flows[-1]["path"] == "/events"


def test_head_response_keeps_its_length_and_sends_no_body(make_proxy, origin):
    harness = make_proxy()
    status, headers, body = get(harness, origin.url("/json"), method="HEAD")
    assert status == 200
    assert body == b""
    assert headers["Content-Length"] == "26"


def test_204_and_304_are_passed_through_without_a_body(make_proxy, origin):
    harness = make_proxy()
    assert get(harness, origin.url("/nocontent"))[0] == 204
    status, headers, body = get(harness, origin.url("/notmodified"))
    assert status == 304
    assert body == b""
    assert headers.get("ETag") == '"abc"'


def test_body_over_the_cap_still_arrives_intact(make_proxy, origin):
    harness = make_proxy(max_body=16 * 1024)
    status, _, body = get(harness, origin.url("/big?size=200000"))
    assert status == 200
    assert body == b"B" * 200000

    flow = harness.wait_for_flows(1)[0]
    detail = harness.hub.detail(flow["id"])
    assert detail["response"]["body"]["streamed"] is True


# ── rules over the wire ─────────────────────────────────────────────────


def test_rule_injects_a_header_the_origin_sees(make_proxy, origin):
    harness = make_proxy('on request { set header "X-Riff-Test" = "hello" }')
    _, _, body = get(harness, origin.url("/echo"))
    assert json.loads(body)["headers"]["x-riff-test"] == "hello"


def test_respond_never_reaches_the_origin(make_proxy, origin):
    harness = make_proxy(
        'on request where path starts with "/json" { respond 418 "{\\"faked\\": true}" as json }'
    )
    status, headers, body = get(harness, origin.url("/json"))
    assert status == 418
    assert json.loads(body) == {"faked": True}
    assert headers["Content-Type"] == "application/json"
    assert headers["X-Riff"] == "synthetic"
    assert harness.wait_for_flows(1)[0]["intercepted"] is True


def test_response_body_rewrite_reaches_the_client(make_proxy, origin):
    harness = make_proxy('on response where status == 200 { set body = "{\\"patched\\": 1}" }')
    status, headers, body = get(harness, origin.url("/json"))
    assert status == 200
    assert json.loads(body) == {"patched": 1}
    assert headers["Content-Length"] == "14"


def test_status_rewrite(make_proxy, origin):
    harness = make_proxy("on response where status == 500 { set status = 200 }")
    assert get(harness, origin.url("/status?code=500"))[0] == 200


def test_url_rewrite_redirects_upstream(make_proxy, origin):
    harness = make_proxy('on request where path == "/old" { rewrite url "/json" }')
    status, _, body = get(harness, origin.url("/old"))
    assert status == 200
    assert json.loads(body)["hello"] == "world"


def test_abort_drops_the_connection(make_proxy, origin):
    harness = make_proxy('on request where path contains "json" { abort }')
    host, port = harness.address
    conn = http.client.HTTPConnection(host, port, timeout=5)
    with pytest.raises((http.client.RemoteDisconnected, ConnectionError, OSError)):
        conn.request("GET", origin.url("/json"))
        conn.getresponse().read()
    conn.close()


def test_redaction_applies_before_the_flow_is_stored(make_proxy, origin):
    harness = make_proxy('on request { redact header "authorization" }')
    _, _, body = get(harness, origin.url("/echo"), headers={"Authorization": "Bearer secret-token"})

    # Redaction rewrites the request, so the origin sees the mask too.
    assert "secret-token" not in json.loads(body)["headers"]["authorization"]
    detail = harness.hub.detail(harness.wait_for_flows(1)[0]["id"])
    stored = dict((k.lower(), v) for k, v in detail["request"]["headers"])
    assert "secret-token" not in stored["authorization"]


def test_counters_accumulate_across_requests(make_proxy, origin):
    harness = make_proxy('on response where status >= 500 { count "5xx" }')
    for _ in range(2):
        get(harness, origin.url("/status?code=503"))
    get(harness, origin.url("/json"))
    harness.wait_for_flows(3)
    assert harness.proxy.engine.counters == {"5xx": 2}


def test_delay_slows_the_response(make_proxy, origin):
    import time

    harness = make_proxy('on request where path == "/json" { delay 300ms }')
    start = time.time()
    assert get(harness, origin.url("/json"))[0] == 200
    assert time.time() - start >= 0.28


# ── HTTPS interception ──────────────────────────────────────────────────


def test_connect_is_decrypted_and_rules_apply(make_proxy, tls_origin, client_ssl_context):
    harness = make_proxy('on request { set header "X-Seen" = "1" }')
    status, _, body = get_tls(harness, tls_origin, "/echo", client_ssl_context)
    assert status == 200
    payload = json.loads(body)
    assert payload["headers"]["x-seen"] == "1"

    flow = harness.wait_for_flows(1)[0]
    assert flow["tls"] is True
    assert flow["scheme"] == "https"
    assert flow["host"] == "localhost"


def test_decrypted_https_body_is_readable_by_rules(make_proxy, tls_origin, client_ssl_context):
    harness = make_proxy('on response where body contains "hello" { tag "read-tls-body" }')
    status, _, _ = get_tls(harness, tls_origin, "/json", client_ssl_context)
    assert status == 200
    assert harness.wait_for_flows(1)[0]["tags"] == ["read-tls-body"]


def test_passthru_tunnels_without_decrypting(make_proxy, tls_origin, ca):
    import ssl as ssl_module

    harness = make_proxy('passthru "localhost"')
    # The client must trust the *origin's* certificate, not a riff-minted one;
    # both happen to be signed by the test CA, so a successful request only
    # proves the bytes were relayed untouched.
    context = ssl_module.create_default_context(cafile=ca.ca_cert_path)
    status, _, body = get_tls(harness, tls_origin, "/json", context)
    assert status == 200
    assert json.loads(body)["hello"] == "world"

    # A tunnelled connection produces no flow record, only a tunnel event.
    assert harness.hub.list() == []
    assert harness.wait_for_tunnels(1) == 1


def test_https_keep_alive_inside_one_tunnel(make_proxy, tls_origin, client_ssl_context):
    harness = make_proxy()
    host, port = harness.address
    conn = http.client.HTTPSConnection(host, port, timeout=10, context=client_ssl_context)
    conn.set_tunnel(tls_origin.host, tls_origin.port)
    try:
        for _ in range(3):
            conn.request("GET", "/json")
            assert conn.getresponse().read()
    finally:
        conn.close()
    assert len(harness.wait_for_flows(3)) == 3


# ── failure handling ────────────────────────────────────────────────────


def test_unreachable_origin_yields_502_not_a_crash(make_proxy):
    harness = make_proxy()
    status, _, body = get(harness, "http://127.0.0.1:1/nothing")
    assert status == 502
    assert b"cannot reach" in body


def test_rule_error_is_reported_without_dropping_the_request(make_proxy, origin):
    # `set status` is invalid in a request rule; the request must still go through.
    harness = make_proxy("on request { set status = 500 }")
    status, _, _ = get(harness, origin.url("/json"))
    assert status == 200
    flow = harness.wait_for_flows(1)[0]
    assert "on response" in flow["error"]


# ── less-travelled protocol paths ───────────────────────────────────────


def test_request_body_over_the_cap_is_relayed_whole(make_proxy, origin):
    harness = make_proxy(max_body=8 * 1024)
    payload = b"x" * 120_000
    status, _, body = get(harness, origin.url("/size"), method="POST", body=payload,
                          headers={"Content-Type": "application/octet-stream"})
    assert status == 200
    assert json.loads(body)["received"] == len(payload)

    detail = harness.hub.detail(harness.wait_for_flows(1)[0]["id"])
    assert detail["request"]["body"]["streamed"] is True


def test_expect_100_continue_is_answered_so_the_client_sends(make_proxy, origin):
    import socket

    host, port = harness_address = make_proxy().address
    payload = b'{"hi": true}'
    request = (
        f"POST {origin.url('/echo')} HTTP/1.1\r\n"
        f"Host: {origin.authority}\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Content-Type: application/json\r\n"
        f"Expect: 100-continue\r\n\r\n"
    ).encode()

    with socket.create_connection(harness_address, timeout=10) as sock:
        sock.sendall(request)
        interim = sock.recv(64)
        assert interim.startswith(b"HTTP/1.1 100"), interim
        sock.sendall(payload)
        rest = b""
        sock.settimeout(5)
        while b"\r\n\r\n" not in rest or len(rest.split(b"\r\n\r\n", 1)[1]) < 10:
            chunk = sock.recv(65536)
            if not chunk:
                break
            rest += chunk
    assert b"200 OK" in rest
    # The proxy must not forward Expect upstream, or the origin would stall.
    assert b'"expect"' not in rest.lower()


def test_http_1_0_client_gets_a_1_0_reply_and_a_close(make_proxy, origin):
    import socket

    host, port = make_proxy().address
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(f"GET {origin.url('/json')} HTTP/1.0\r\n\r\n".encode())
        received = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            received += chunk
    assert received.startswith(b"HTTP/1.0 200")
    assert b'"hello": "world"' in received


def test_ignored_hosts_are_proxied_but_not_recorded(make_proxy, origin):
    """The host display filter: the traffic still works, it just isn't listed."""
    harness = make_proxy(f'ignore "{origin.host}"')
    status, _, body = get(harness, origin.url("/json"))
    assert status == 200
    assert json.loads(body)["hello"] == "world"

    import time

    time.sleep(0.3)
    assert harness.hub.list() == []


def test_capture_allowlist_excludes_other_hosts(make_proxy, origin):
    harness = make_proxy('capture "some.other.host"')
    assert get(harness, origin.url("/json"))[0] == 200
    import time

    time.sleep(0.3)
    assert harness.hub.list() == []

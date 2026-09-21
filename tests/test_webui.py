"""The web UI's API surface, with the security guards front and centre."""

from __future__ import annotations

import http.client
import json

import pytest

from riff.hub import Hub
from riff.proxy import Options, Proxy
from riff.script import Engine
from riff.webui import UiOptions, UiServer


@pytest.fixture
def ui(ca, tmp_path):
    script = tmp_path / "rules.riff"
    script.write_text('on request { tag "seen" }\n', encoding="utf-8")

    proxy = Proxy(Options(listen_host="127.0.0.1", listen_port=0), engine=Engine.from_file(str(script)), ca=ca)
    proxy.bind()
    hub = Hub()
    proxy.observer = hub
    server = UiServer(UiOptions(host="127.0.0.1", port=0), proxy, hub, str(script))
    server.start()
    yield server
    server.stop()
    proxy.shutdown()


def call(ui, method, path, *, token=None, cookie=None, host=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", ui.options.port, timeout=10)
    headers = {"Host": host or f"127.0.0.1:{ui.options.port}"}
    if token:
        headers["X-Riff-Token"] = token
    if cookie:
        headers["Cookie"] = f"riff_token={cookie}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            parsed = raw
        return response.status, dict(response.getheaders()), parsed
    finally:
        conn.close()


# ── guards ──────────────────────────────────────────────────────────────


def test_api_needs_a_token(ui):
    assert call(ui, "GET", "/api/flows")[0] == 401


def test_token_works_as_header_or_cookie(ui):
    token = ui.options.token
    assert call(ui, "GET", "/api/flows", token=token)[0] == 200
    assert call(ui, "GET", "/api/flows", cookie=token)[0] == 200


def test_a_wrong_token_is_rejected(ui):
    assert call(ui, "GET", "/api/flows", token="not-the-token")[0] == 401


def test_unknown_host_header_is_refused(ui):
    """This is the DNS-rebinding guard: a hostile page cannot reach us."""
    status, _, body = call(ui, "GET", "/api/flows", token=ui.options.token, host="evil.example.com")
    assert status == 421
    assert "DNS-rebinding" in body["error"]


def test_mutating_calls_reject_a_cookie_on_its_own(ui):
    """Double-submit: a cross-site POST carrying only the cookie must fail."""
    status, _, _ = call(ui, "POST", "/api/clear", cookie=ui.options.token)
    assert status == 401
    status, _, _ = call(ui, "POST", "/api/clear", token=ui.options.token)
    assert status == 200


def test_the_index_hands_over_the_cookie_only_for_a_valid_token(ui):
    status, headers, _ = call(ui, "GET", f"/?token={ui.options.token}")
    assert status == 302
    assert "riff_token=" in headers["Set-Cookie"]
    assert "HttpOnly" in headers["Set-Cookie"]
    assert "SameSite=Strict" in headers["Set-Cookie"]

    assert call(ui, "GET", "/?token=wrong")[0] == 401


def test_security_headers_are_present(ui):
    _, headers, _ = call(ui, "GET", "/app.js", token=ui.options.token)
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_static_assets_are_served(ui):
    for path, marker in (("/", b"<title>riff</title>"), ("/app.js", b"EventSource"), ("/app.css", b"--accent")):
        status, _, body = call(ui, "GET", path, token=ui.options.token, cookie=ui.options.token)
        assert status == 200
        assert marker in body


def test_there_is_no_path_traversal_out_of_the_ui_directory(ui):
    for path in ("/../cli.py", "/..%2fcli.py", "/app.js/../../cli.py"):
        status, _, _ = call(ui, "GET", path, token=ui.options.token)
        assert status == 404


# ── behaviour ───────────────────────────────────────────────────────────


def test_config_reports_the_ca_and_script(ui):
    _, _, body = call(ui, "GET", "/api/config", token=ui.options.token)
    assert body["script"]["rules"] == 1
    assert body["ca"]["fingerprint"].count(":") == 31
    assert body["proxy"]["port"] == ui.proxy.address[1]


def test_script_round_trip_and_hot_reload(ui):
    token = ui.options.token
    _, _, before = call(ui, "GET", "/api/script", token=token)
    assert 'tag "seen"' in before["source"]

    new_source = 'on request { tag "one" }\non response { tag "two" }\n'
    status, _, result = call(ui, "PUT", "/api/script", token=token, body={"source": new_source})
    assert status == 200 and result["rules"] == 2
    assert ui.proxy.engine.rule_count == 2  # swapped into the live proxy
    assert ui.current_script() == new_source  # and written to disk


def test_a_broken_script_is_rejected_and_the_engine_is_untouched(ui):
    token = ui.options.token
    before = ui.proxy.engine
    status, _, result = call(ui, "PUT", "/api/script", token=token, body={"source": "on request where {"})
    assert status == 400
    assert result["line"] == 1
    assert "^" in result["render"]
    assert ui.proxy.engine is before
    assert 'tag "seen"' in ui.current_script()


def test_check_validates_without_applying(ui):
    token = ui.options.token
    before = ui.proxy.engine
    _, _, ok = call(ui, "POST", "/api/script/check", token=token, body={"source": 'on request { tag "x" }'})
    assert ok == {"ok": True, "rules": 1}
    _, _, bad = call(ui, "POST", "/api/script/check", token=token, body={"source": "on nonsense { }"})
    assert bad["ok"] is False
    assert ui.proxy.engine is before


def test_flows_and_detail_and_clear(ui, origin):
    import http.client as hc

    host, port = ui.proxy.address
    import threading

    threading.Thread(target=ui.proxy.serve_forever, daemon=True).start()
    conn = hc.HTTPConnection(host, port, timeout=10)
    conn.request("GET", origin.url("/json"))
    conn.getresponse().read()
    conn.close()

    token = ui.options.token
    import time

    for _ in range(100):
        _, _, listing = call(ui, "GET", "/api/flows", token=token)
        if listing["flows"]:
            break
        time.sleep(0.02)
    assert listing["flows"], "the proxy never reported a flow"
    flow_id = listing["flows"][0]["id"]

    status, _, detail = call(ui, "GET", f"/api/flow/{flow_id}", token=token)
    assert status == 200
    assert detail["request"]["method"] == "GET"
    assert "hello" in detail["response"]["body"]["text"]

    assert call(ui, "GET", "/api/flow/99999", token=token)[0] == 404

    assert call(ui, "POST", "/api/clear", token=token)[0] == 200
    _, _, empty = call(ui, "GET", "/api/flows", token=token)
    assert empty["flows"] == []


def test_ca_download_serves_the_certificate(ui):
    status, headers, body = call(ui, "GET", "/api/ca.crt", token=ui.options.token)
    assert status == 200
    assert body.startswith(b"-----BEGIN CERTIFICATE-----")
    assert "riff-ca.crt" in headers["Content-Disposition"]


def test_replay_reissues_a_request(ui, origin):
    import threading

    threading.Thread(target=ui.proxy.serve_forever, daemon=True).start()
    ui.proxy.options.verify_upstream = False
    status, _, result = call(
        ui,
        "POST",
        "/api/replay",
        token=ui.options.token,
        body={"method": "GET", "url": origin.url("/json"), "headers": [], "apply_rules": True},
    )
    assert status == 200
    assert not result["error"]
    detail = ui.hub.detail(result["id"])
    assert detail["response"]["status"] == 200
    assert "replay" in detail["tags"]


# ── recovering the UI address ───────────────────────────────────────────


def test_ui_address_is_parked_where_a_second_console_can_read_it(ui):
    import os

    assert os.path.exists(ui.url_file)
    with open(ui.url_file, encoding="utf-8") as fh:
        parked = fh.read().strip()
    assert parked == ui.url
    assert f"token={ui.options.token}" in parked

    # and it authenticates
    from urllib.parse import urlsplit

    status, headers, _ = call(ui, "GET", urlsplit(parked).path + "?" + urlsplit(parked).query)
    assert status == 302
    assert "riff_token=" in headers["Set-Cookie"]


def test_the_parked_address_is_removed_on_shutdown(ui):
    import os

    path = ui.url_file
    assert os.path.exists(path)
    ui.stop()
    assert not os.path.exists(path)


# ── export and import ───────────────────────────────────────────────────


def _seed(ui, count=3):
    """Put a few finished flows straight into the hub, as the proxy would."""
    from riff.flow import Flow, Request, Response
    from riff.http import Headers

    ids = []
    for n in range(count):
        request = Request(method="GET", headers=Headers([("Accept", "application/json")]))
        request.set_url(f"https://api.example.com/items/{n}")
        flow = Flow(id=ui.proxy.flow_ids.next(), client="test", tls=True, request=request)
        flow.response = Response(status=200, reason="OK", body=b'{"n":%d}' % n,
                                 headers=Headers([("Content-Type", "application/json")]))
        flow.ended = flow.started + 0.01
        flow.tag("seen")
        ui.hub.on_flow(flow)
        ids.append(flow.id)
    return ids


def test_export_selected_flows_as_riff_json(ui):
    ids = _seed(ui)
    token = ui.options.token
    status, headers, payload = call(ui, "GET", f"/api/export?ids={ids[0]},{ids[2]}", token=token)
    assert status == 200
    assert headers["Content-Disposition"].startswith('attachment; filename="riff-')
    assert headers["Content-Disposition"].endswith('.json"')
    assert headers["X-Riff-Exported"] == "2"
    assert payload["format"] == "riff-flows"
    assert [f["id"] for f in payload["flows"]] == [ids[0], ids[2]]
    assert payload["flows"][0]["response"]["body"]["text"] == '{"n":0}'


def test_export_without_ids_takes_everything_and_har_is_available(ui):
    ids = _seed(ui)
    status, headers, har = call(ui, "GET", "/api/export?format=har", token=ui.options.token)
    assert status == 200
    assert headers["Content-Disposition"].endswith('.har"')
    assert len(har["log"]["entries"]) == len(ids)
    assert har["log"]["entries"][1]["request"]["url"] == "https://api.example.com/items/1"


def test_export_of_unknown_flows_is_a_404_and_bad_input_a_400(ui):
    token = ui.options.token
    assert call(ui, "GET", "/api/export?ids=4242", token=token)[0] == 404
    assert call(ui, "GET", "/api/export?ids=abc", token=token)[0] == 400
    assert call(ui, "GET", "/api/export?format=xml", token=token)[0] == 400


def test_import_puts_flows_back_in_the_buffer_tagged_imported(ui):
    ids = _seed(ui, 2)
    token = ui.options.token
    _, _, exported = call(ui, "GET", f"/api/export?ids={ids[0]},{ids[1]}", token=token)
    call(ui, "POST", "/api/clear", token=token)

    status, _, result = call(ui, "POST", "/api/import", token=token, body=exported)
    assert status == 200
    assert result["imported"] == 2
    assert all(new > ids[1] for new in result["ids"]), "imports get fresh ids, never reuse old ones"

    _, _, listing = call(ui, "GET", "/api/flows", token=token)
    assert [f["id"] for f in listing["flows"]] == result["ids"]
    assert "imported" in listing["flows"][0]["tags"] and "seen" in listing["flows"][0]["tags"]
    _, _, detail = call(ui, "GET", f"/api/flow/{result['ids'][1]}", token=token)
    assert detail["request"]["url"] == "https://api.example.com/items/1"
    assert detail["response"]["body"]["text"] == '{"n":1}'


def test_import_accepts_har_and_rejects_junk(ui):
    _seed(ui, 1)
    token = ui.options.token
    _, _, har = call(ui, "GET", "/api/export?format=har", token=token)
    status, _, result = call(ui, "POST", "/api/import", token=token, body=har)
    assert status == 200 and result["imported"] == 1

    assert call(ui, "POST", "/api/import", token=token, body={"nonsense": True})[0] == 400
    assert call(ui, "POST", "/api/import", token=token)[0] == 400


def test_import_is_a_mutating_call_so_the_cookie_alone_is_refused(ui):
    status, _, _ = call(ui, "POST", "/api/import", cookie=ui.options.token, body={"log": {"entries": []}})
    assert status == 401


# ── composer workspace: collections, environments, send ─────────────────


def test_collections_crud_over_the_api(ui):
    token = ui.options.token
    status, _, created = call(ui, "POST", "/api/collections", token=token, body={"name": "Listings API"})
    assert status == 200 and created["slug"] == "listings-api"

    doc = call(ui, "GET", "/api/collections/listings-api", token=token)[2]
    doc["requests"].append({"name": "Ping", "method": "GET", "url": "{{baseUrl}}/ping"})
    status, _, saved = call(ui, "PUT", "/api/collections/listings-api", token=token, body=doc)
    assert status == 200 and saved["requests"] == 1

    listing = call(ui, "GET", "/api/collections", token=token)[2]["collections"]
    assert listing[0]["requests"][0]["name"] == "Ping"

    status, headers, exported = call(ui, "GET", "/api/collections/listings-api/export?format=v2", token=token)
    assert status == 200 and exported["item"][0]["request"]["url"]["raw"] == "{{baseUrl}}/ping"
    assert headers["Content-Disposition"].endswith('listings-api.collection-v2.json"')

    assert call(ui, "DELETE", "/api/collections/listings-api", token=token)[0] == 200
    assert call(ui, "GET", "/api/collections", token=token)[2]["collections"] == []
    assert call(ui, "GET", "/api/collections/../../etc", token=token)[0] in (400, 404)
    assert call(ui, "PUT", "/api/collections/Bad%20Name", token=token, body={"name": "x"})[0] == 400


def test_collection_import_takes_v2_and_har(ui):
    token = ui.options.token
    collection_v2 = {
        "info": {"name": "From Elsewhere", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [{"name": "Ping", "request": {"method": "GET", "url": "https://api.example.com/ping"}}],
    }
    status, _, result = call(ui, "POST", "/api/collections/import", token=token, body=collection_v2)
    assert status == 200 and result["slug"] == "from-elsewhere" and result["requests"] == 1

    har = {"log": {"entries": [{"request": {"method": "GET", "url": "https://api.example.com/x", "headers": []}}]}}
    status, _, result = call(ui, "POST", "/api/collections/import?name=Captured", token=token, body=har)
    assert status == 200 and result["name"] == "Captured"

    assert call(ui, "POST", "/api/collections/import", token=token, body={"junk": 1})[0] == 400


def test_environments_and_personal_values_over_the_api(ui):
    token = ui.options.token
    assert call(ui, "PUT", "/api/environments/dvm", token=token, body={"values": {"baseUrl": "https://dvm.example"}})[0] == 200
    assert call(ui, "PUT", "/api/personal?environment=dvm", token=token, body={"values": {"token": "secret"}})[0] == 200

    env = call(ui, "GET", "/api/environments/dvm", token=token)[2]
    assert env["values"] == {"baseUrl": "https://dvm.example"}
    assert env["personal"] == {"token": "secret"}
    assert call(ui, "GET", "/api/environments", token=token)[2]["environments"] == [{"name": "dvm", "values": 1, "personal": 1}]

    # the shared environment file never contains the personal value
    import os
    shared = open(os.path.join(ui.workspace.environments_dir, "dvm.json"), encoding="utf-8").read()
    assert "secret" not in shared

    assert call(ui, "DELETE", "/api/environments/dvm", token=token)[0] == 200
    assert call(ui, "GET", "/api/environments/dvm", token=token)[0] == 400


def test_send_resolves_variables_applies_auth_and_captures(ui, origin):
    import threading

    threading.Thread(target=ui.proxy.serve_forever, daemon=True).start()
    ui.proxy.options.verify_upstream = False
    token = ui.options.token
    call(ui, "PUT", "/api/environments/test", token=token, body={"values": {"baseUrl": origin.url("")}})
    call(ui, "PUT", "/api/personal?environment=test", token=token, body={"values": {"apiToken": "T0K"}})

    request = {
        "method": "GET",
        "url": "{{baseUrl}}/json",
        "params": [{"name": "q", "value": "{{apiToken}}", "enabled": True}],
        "auth": {"type": "bearer", "token": "{{apiToken}}"},
        "capture": [{"var": "greeting", "from": "json", "path": "hello"}, {"var": "code", "from": "status"}],
    }
    status, _, result = call(ui, "POST", "/api/send", token=token, body={"request": request, "environment": "test"})
    assert status == 200, result
    assert not result["error"]
    assert result["status"] == 200
    assert result["missing"] == []
    assert result["detail"]["request"]["url"].endswith("/json?q=T0K")
    assert ["Bearer T0K"] == [v for k, v in result["detail"]["request"]["headers"] if k.lower() == "authorization"]
    assert result["captured"]["code"] == "200"
    assert result["captured"]["greeting"] == "world"
    personal = call(ui, "GET", "/api/personal?environment=test", token=token)[2]["values"]
    assert personal["code"] == "200" and personal["apiToken"] == "T0K", "captures merge into personal values"

    # an unresolved variable in the URL is refused up front, not sent half-baked
    status, _, result = call(ui, "POST", "/api/send", token=token, body={"request": {"method": "GET", "url": "{{nope}}/x"}})
    assert status == 400 and result["missing"] == ["nope"]


def test_workspace_routes_need_the_header_token_to_mutate(ui):
    cookie = ui.options.token
    assert call(ui, "GET", "/api/collections", cookie=cookie)[0] == 200
    assert call(ui, "POST", "/api/collections", cookie=cookie, body={"name": "x"})[0] == 401
    assert call(ui, "DELETE", "/api/collections/x", cookie=cookie)[0] == 401
    assert call(ui, "PUT", "/api/personal", cookie=cookie, body={"values": {}})[0] == 401



# ── findings (passive scanner) ─────────────────────────────────────────────

def test_findings_route_lists_and_clears(ui, origin):
    token = ui.options.token
    # The origin's Server header carries a version, which the passive scanner flags.
    call(ui, "POST", "/api/replay", token=token,
         body={"url": origin.url("/json"), "method": "GET", "headers": [], "apply_rules": False})
    status, _, body = call(ui, "GET", "/api/findings", token=token)
    assert status == 200 and body["enabled"] is True
    assert isinstance(body["findings"], list) and body["counts"]["total"] > 0

    # Clearing needs the header token, not just a cookie.
    assert call(ui, "POST", "/api/findings/clear", cookie=token)[0] == 401
    assert call(ui, "POST", "/api/findings/clear", token=token)[0] == 200
    assert call(ui, "GET", "/api/findings", token=token)[2]["counts"]["total"] == 0


def test_findings_rescan_rebuilds_from_the_buffer(ui, origin):
    token = ui.options.token
    call(ui, "POST", "/api/replay", token=token,
         body={"url": origin.url("/json"), "method": "GET", "headers": [], "apply_rules": False})
    call(ui, "POST", "/api/findings/clear", token=token)
    assert call(ui, "GET", "/api/findings", token=token)[2]["counts"]["total"] == 0
    status, _, body = call(ui, "POST", "/api/findings/rescan", token=token)
    assert status == 200 and body["total"] == body["counts"]["total"] and body["total"] > 0


def test_findings_appear_from_real_proxied_traffic(ui, origin):
    """The live capture path (proxy -> hub.on_flow -> scan), not just replay."""
    import http.client as hc
    import threading
    import time

    threading.Thread(target=ui.proxy.serve_forever, daemon=True).start()
    host, port = ui.proxy.address
    conn = hc.HTTPConnection(host, port, timeout=10)
    conn.request("GET", origin.url("/json"))
    conn.getresponse().read()
    conn.close()

    token = ui.options.token
    for _ in range(100):
        counts = call(ui, "GET", "/api/findings", token=token)[2]["counts"]
        if counts["total"]:
            break
        time.sleep(0.02)
    assert counts["total"] > 0, "browsed traffic produced no findings"


# ── active scanner routes ──────────────────────────────────────────────────

def _seed_flow(ui, origin):
    """Put one real flow with a query parameter into the buffer via the proxy."""
    import http.client as hc
    import threading
    import time as _t
    threading.Thread(target=ui.proxy.serve_forever, daemon=True).start()
    host, port = ui.proxy.address
    conn = hc.HTTPConnection(host, port, timeout=10)
    conn.request("GET", origin.url("/json?q=hi"))
    conn.getresponse().read()
    conn.close()
    token = ui.options.token
    for _ in range(100):
        rows = call(ui, "GET", "/api/flows", token=token)[2]["flows"]
        if rows:
            return rows[0]
        _t.sleep(0.02)
    raise AssertionError("no flow captured")


def test_scan_info_lists_hosts_and_checks(ui, origin):
    _seed_flow(ui, origin)
    status, _, body = call(ui, "GET", "/api/scan", token=ui.options.token)
    assert status == 200
    assert any(h.startswith("127.0.0.1") for h in body["hosts"])
    names = {c["name"] for c in body["checks"]}
    assert "xss-reflected" in names and "sqli-time" in names


def test_scan_requires_a_host_in_scope(ui, origin):
    _seed_flow(ui, origin)
    status, _, body = call(ui, "POST", "/api/scan", token=ui.options.token, body={"hosts": []})
    assert status == 400 and "scope" in body["error"].lower()


def test_scan_start_runs_and_reports(ui, origin):
    row = _seed_flow(ui, origin)
    ui.proxy.options.verify_upstream = False
    host = row["host"]
    status, _, job = call(ui, "POST", "/api/scan", token=ui.options.token,
                          body={"hosts": [host], "ids": [row["id"]]})
    assert status == 200 and job["status"] in ("running", "done")

    import time as _t
    for _ in range(200):
        j = call(ui, "GET", f"/api/scan/status?id={job['id']}", token=ui.options.token)[2]
        if j["status"] != "running":
            break
        _t.sleep(0.05)
    assert j["status"] == "done" and j["probes_sent"] > 0


def test_scan_needs_the_header_token_to_start(ui):
    assert call(ui, "POST", "/api/scan", cookie=ui.options.token, body={"hosts": ["x"]})[0] == 401
    assert call(ui, "POST", "/api/scan/cancel", cookie=ui.options.token, body={"id": 1})[0] == 401


def test_scan_with_oob_starts_a_collaborator(ui, origin):
    row = _seed_flow(ui, origin)
    ui.proxy.options.verify_upstream = False
    status, _, job = call(ui, "POST", "/api/scan", token=ui.options.token,
                          body={"hosts": [row["host"]], "ids": [row["id"]], "oob": True})
    assert status == 200
    assert ui._collaborator is not None, "an out-of-band scan starts the collaborator"
    import time as _t
    for _ in range(200):
        j = call(ui, "GET", f"/api/scan/status?id={job['id']}", token=ui.options.token)[2]
        if j["status"] != "running":
            break
        _t.sleep(0.05)
    assert j["status"] == "done"

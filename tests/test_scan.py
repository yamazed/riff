"""The passive scanner: checks, findings model/store, and the Hub hook."""

from __future__ import annotations

import time

import pytest

from riff.flow import Flow, Request, Response
from riff.http import Headers
from riff.hub import Hub
from riff.scan import Finding, FindingStore, scan_flow
from riff.scan import passive as P


def make_flow(flow_id=1, method="GET", url="https://shop.example.com/account", tls=True,
              status=200, ctype="text/html", body=b"<html>hi</html>",
              req_headers=(), resp_headers=()):
    request = Request(method=method, headers=Headers(list(req_headers)))
    request.set_url(url)
    flow = Flow(id=flow_id, client="test", tls=tls, request=request, started=time.time() - 0.1)
    headers = [("Content-Type", ctype)] + list(resp_headers)
    flow.response = Response(status=status, reason="OK", body=body, headers=Headers(headers))
    flow.ended = time.time()
    return flow


def checks_named(flow) -> set[str]:
    return {f.check for f in scan_flow(flow)}


# ── findings model / store ────────────────────────────────────────

def test_finding_key_dedups_on_check_and_where():
    a = Finding(check="missing-csp", title="x", severity="medium", flow_id=1, url="u", where="host.com")
    b = Finding(check="missing-csp", title="x", severity="medium", flow_id=2, url="u2", where="host.com")
    c = Finding(check="missing-csp", title="x", severity="medium", flow_id=3, url="u3", where="other.com")
    assert a.key == b.key and a.key != c.key


def test_store_dedups_keeps_first_and_counts():
    store = FindingStore()
    first = Finding(check="missing-csp", title="t", severity="medium", flow_id=1, url="u", where="h")
    dup = Finding(check="missing-csp", title="t", severity="medium", flow_id=9, url="u", where="h")
    assert store.add(first) is True
    assert store.add(dup) is False, "same key is not added twice"
    rows = store.list()
    assert len(rows) == 1 and rows[0]["flow_id"] == 1, "first flow to show the issue wins"
    assert store.counts()["medium"] == 1 and store.counts()["total"] == 1


def test_store_sorts_by_severity_then_recency():
    store = FindingStore()
    store.add(Finding(check="a", title="low", severity="low", flow_id=1, url="u", where="1"))
    store.add(Finding(check="b", title="high", severity="high", flow_id=2, url="u", where="2"))
    store.add(Finding(check="c", title="info", severity="info", flow_id=3, url="u", where="3"))
    order = [r["severity"] for r in store.list()]
    assert order == ["high", "low", "info"]


def test_store_capacity_evicts_oldest():
    store = FindingStore(capacity=2)
    store.add(Finding(check="a", title="", severity="low", flow_id=1, url="u", where="1", at=1.0))
    store.add(Finding(check="b", title="", severity="low", flow_id=2, url="u", where="2", at=2.0))
    store.add(Finding(check="c", title="", severity="low", flow_id=3, url="u", where="3", at=3.0))
    keys = {r["key"] for r in store.list()}
    assert "a|1" not in keys and len(keys) == 2


# ── individual checks ─────────────────────────────────────────────

def test_security_headers_flagged_when_absent_and_clean_when_present():
    bare = make_flow()
    found = checks_named(bare)
    assert {"missing-csp", "missing-nosniff", "missing-frame-options", "missing-hsts"} <= found

    hardened = make_flow(resp_headers=[
        ("Content-Security-Policy", "default-src 'self'"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Strict-Transport-Security", "max-age=63072000"),
    ])
    assert not ({"missing-csp", "missing-nosniff", "missing-frame-options", "missing-hsts"} & checks_named(hardened))


def test_frame_ancestors_in_csp_satisfies_frame_options():
    flow = make_flow(resp_headers=[("Content-Security-Policy", "frame-ancestors 'none'")])
    assert "missing-frame-options" not in checks_named(flow)


def test_security_headers_skip_non_html_and_errors():
    assert not checks_named(make_flow(ctype="application/json", body=b"{}")) & {"missing-csp"}
    assert not checks_named(make_flow(status=404)) & {"missing-csp"}


def test_hsts_only_on_https():
    plain = make_flow(url="http://shop.example.com/x", tls=False, ctype="application/json", body=b"{}")
    assert "missing-hsts" not in checks_named(plain)


def test_cookie_flags():
    flow = make_flow(resp_headers=[("Set-Cookie", "sid=abc; Path=/")])
    names = checks_named(flow)
    assert {"cookie-no-secure", "cookie-no-httponly", "cookie-no-samesite"} <= names

    safe = make_flow(resp_headers=[("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax")])
    assert not ({"cookie-no-secure", "cookie-no-httponly", "cookie-no-samesite"} & checks_named(safe))


def test_cookie_secure_only_required_on_https():
    plain = make_flow(url="http://shop.example.com/x", tls=False, ctype="application/json", body=b"{}",
                      resp_headers=[("Set-Cookie", "sid=abc; HttpOnly; SameSite=Lax")])
    assert "cookie-no-secure" not in checks_named(plain)


def test_version_banner_only_when_version_present():
    with_version = make_flow(resp_headers=[("Server", "nginx/1.18.0")])
    assert "version-banner" in checks_named(with_version)
    bare_name = make_flow(resp_headers=[("Server", "nginx")])
    assert "version-banner" not in checks_named(bare_name)


def test_plaintext_credentials_high_severity():
    flow = make_flow(url="http://api.example.com/v1/x", tls=False, ctype="application/json", body=b"{}",
                     req_headers=[("Authorization", "Bearer secret")])
    findings = [f for f in scan_flow(flow) if f.check == "credential-cleartext"]
    assert findings and findings[0].severity == "high"
    # Over HTTPS the same request is fine.
    secure = make_flow(url="https://api.example.com/v1/x", ctype="application/json", body=b"{}",
                       req_headers=[("Authorization", "Bearer secret")])
    assert "credential-cleartext" not in checks_named(secure)


def test_cors_wildcard_with_credentials():
    bad = make_flow(ctype="application/json", body=b"{}", resp_headers=[
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Credentials", "true"),
    ])
    findings = [f for f in scan_flow(bad) if f.check == "cors-wildcard-credentials"]
    assert findings and findings[0].severity == "high"
    # Wildcard without credentials is not flagged.
    ok = make_flow(ctype="application/json", body=b"{}", resp_headers=[("Access-Control-Allow-Origin", "*")])
    assert "cors-wildcard-credentials" not in checks_named(ok)


def test_body_secret_signatures():
    key = make_flow(ctype="text/plain", body=b"-----BEGIN RSA PRIVATE KEY-----\nabc\n")
    assert "secret-private-key" in checks_named(key)
    aws = make_flow(ctype="text/plain", body=b"AKIAIOSFODNN7EXAMPLE is the id")
    assert "secret-aws-access-key" in checks_named(aws)
    clean = make_flow(ctype="text/plain", body=b"nothing sensitive here")
    assert not any(c.startswith("secret-") for c in checks_named(clean))


def test_a_broken_check_does_not_stop_the_others(monkeypatch):
    def boom(flow):
        raise RuntimeError("bad check")
    monkeypatch.setattr(P, "PASSIVE_CHECKS", (boom, P.check_security_headers))
    assert "missing-csp" in {f.check for f in P.scan_flow(make_flow())}


# ── Hub integration ───────────────────────────────────────────────

def test_hub_scans_on_flow_and_broadcasts_new_findings():
    hub = Hub()
    seen = []
    channel = hub.subscribe()
    hub.on_flow(make_flow(resp_headers=[("Set-Cookie", "sid=1; Path=/")]))
    while not channel.empty():
        seen.append(channel.get_nowait())
    kinds = [m["type"] for m in seen]
    assert "flow" in kinds and "finding" in kinds
    assert hub.finding_counts()["total"] > 0


def test_hub_scan_can_be_disabled():
    hub = Hub(scan=False)
    hub.on_flow(make_flow())
    assert hub.finding_counts()["total"] == 0


def test_hub_dedups_across_flows_same_host():
    hub = Hub()
    hub.on_flow(make_flow(flow_id=1))
    before = hub.finding_counts()["total"]
    hub.on_flow(make_flow(flow_id=2))  # same host, same issues
    assert hub.finding_counts()["total"] == before, "repeats on the same host collapse"


def test_hub_clear_wipes_findings():
    hub = Hub()
    hub.on_flow(make_flow())
    assert hub.finding_counts()["total"] > 0
    hub.clear()
    assert hub.finding_counts()["total"] == 0


def test_hub_rescan_rebuilds_from_buffer():
    hub = Hub(scan=False)  # captured before scanning was on
    hub.on_flow(make_flow(flow_id=1, resp_headers=[("Set-Cookie", "sid=1; Path=/")]))
    assert hub.finding_counts()["total"] == 0
    total = hub.rescan()
    assert total > 0 and hub.finding_counts()["total"] == total

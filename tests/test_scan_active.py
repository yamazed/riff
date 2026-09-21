"""The active scanner: insertion points, checks, and the job engine."""

from __future__ import annotations

import time

import pytest

from riff.flow import Request, Response
from riff.http import Headers
from riff.hub import Hub
from riff.scan import active as A
from riff.scan import points as P
from riff.scan.engine import (
    ScanConfig, ScanTarget, Scanner, ScopeError, host_in_scope, targets_from_flows,
)


def req(url, method="GET", headers=(), body=b""):
    r = Request(method=method, headers=Headers(list(headers)), body=body)
    r.set_url(url)
    return r


def resp(body=b"", status=200, headers=(("Content-Type", "text/html"),)):
    return Response(status=status, reason="OK", body=body, headers=Headers(list(headers)))


# ── insertion points ──────────────────────────────────────────────

def test_points_enumerate_query_and_path():
    labels = {p.label for p in P.insertion_points(req("http://h/a/b?x=1&y=2"))}
    assert "query:x" in labels and "query:y" in labels
    assert "path:1" in labels and "path:2" in labels


def test_points_form_body():
    r = req("http://h/login", method="POST",
            headers=[("Content-Type", "application/x-www-form-urlencoded")], body=b"user=a&pass=b")
    labels = {p.label for p in P.insertion_points(r)}
    assert "body-form:user" in labels and "body-form:pass" in labels


def test_points_json_body_leaves():
    r = req("http://h/api", method="POST", headers=[("Content-Type", "application/json")],
            body=b'{"user":{"id":5,"name":"bob"},"tags":["x","y"]}')
    labels = {p.label for p in P.insertion_points(r)}
    assert "body-json:user.id" in labels and "body-json:user.name" in labels
    assert "body-json:tags[0]" in labels


def test_inject_replaces_query_value():
    r = req("http://h/s?q=hi&z=2")
    point = next(p for p in P.insertion_points(r) if p.label == "query:q")
    mutated = point.inject(r, "PWN")
    assert mutated.query.get("q") == "PWN" and mutated.query.get("z") == "2"
    assert r.query.get("q") == "hi", "the original request is not mutated"


def test_inject_json_leaf():
    r = req("http://h/api", method="POST", headers=[("Content-Type", "application/json")],
            body=b'{"user":{"id":5}}')
    point = next(p for p in P.insertion_points(r) if p.label == "body-json:user.id")
    mutated = point.inject(r, "9 OR 1=1")
    import json
    assert json.loads(mutated.text())["user"]["id"] == "9 OR 1=1"


def test_inject_append_mode():
    r = req("http://h/file?name=report")
    point = next(p for p in P.insertion_points(r) if p.label == "query:name")
    mutated = point.inject(r, "/../../etc", mode="append")
    assert mutated.query.get("name") == "report/../../etc"


# ── checks (fake exchange, no network) ────────────────────────────

def context(base, exchange, baseline=None, time_delay_s=3.0):
    return A.ProbeContext(base_flow_id=1, base_url=base.url, base_request=base,
                          baseline=baseline, exchange=exchange, time_delay_s=time_delay_s)


def only(check, point, ctx):
    return list(check.run(point, ctx))


def test_reflected_xss_fires_on_raw_reflection():
    base = req("http://h/s?q=hi")
    point = next(p for p in P.insertion_points(base) if p.label == "query:q")

    def reflect(request):
        return resp(f"<html>{request.query.get('q')}</html>".encode()), "", 0.01
    findings = only(A.CHECKS_BY_NAME["xss-reflected"], point, context(base, reflect))
    assert findings and findings[0].check == "xss-reflected" and findings[0].severity == "high"


def test_reflected_xss_silent_when_escaped():
    base = req("http://h/s?q=hi")
    point = next(p for p in P.insertion_points(base) if p.label == "query:q")

    def escaped(request):
        raw = request.query.get("q") or ""
        return resp(f"<html>{raw.replace('<', '&lt;')}</html>".encode()), "", 0.01
    assert not only(A.CHECKS_BY_NAME["xss-reflected"], point, context(base, escaped))


def test_reflected_xss_silent_when_not_html():
    base = req("http://h/s?q=hi")
    point = next(p for p in P.insertion_points(base) if p.label == "query:q")

    def json_echo(request):
        return resp(f'{{"q":"{request.query.get("q")}"}}'.encode(),
                    headers=(("Content-Type", "application/json"),)), "", 0.01
    assert not only(A.CHECKS_BY_NAME["xss-reflected"], point, context(base, json_echo))


def test_sqli_error_fires_on_new_db_error():
    base = req("http://h/i?id=5")
    point = next(p for p in P.insertion_points(base) if p.label == "query:id")

    def db(request):
        if "'" in (request.query.get("id") or ""):
            return resp(b"You have an error in your SQL syntax near", status=500), "", 0.01
        return resp(b"<html>ok</html>"), "", 0.01
    findings = only(A.CHECKS_BY_NAME["sqli-error"], point, context(base, db, baseline=resp(b"<html>ok</html>")))
    assert findings and findings[0].check == "sqli-error"


def test_sqli_error_silent_when_error_preexists():
    base = req("http://h/i?id=5")
    point = next(p for p in P.insertion_points(base) if p.label == "query:id")
    noisy = resp(b"SQL syntax error was already on the page")

    def always_error(request):
        return noisy, "", 0.01
    assert not only(A.CHECKS_BY_NAME["sqli-error"], point, context(base, always_error, baseline=noisy))


def test_open_redirect_fires_on_marker_location():
    base = req("http://h/go?next=/home")
    point = next(p for p in P.insertion_points(base) if p.label == "query:next")

    def redir(request):
        return resp(b"", status=302, headers=(("Location", request.query.get("next") or ""),)), "", 0.01
    findings = only(A.CHECKS_BY_NAME["open-redirect"], point, context(base, redir))
    assert findings and findings[0].check == "open-redirect" and findings[0].severity == "medium"


def test_path_traversal_fires_on_passwd_signature():
    base = req("http://h/read?file=notes.txt")
    point = next(p for p in P.insertion_points(base) if p.label == "query:file")

    def fs(request):
        if "etc/passwd" in (request.query.get("file") or ""):
            return resp(b"root:x:0:0:root:/root:/bin/bash\n", headers=(("Content-Type", "text/plain"),)), "", 0.01
        return resp(b"notes", headers=(("Content-Type", "text/plain"),)), "", 0.01
    findings = only(A.CHECKS_BY_NAME["path-traversal"], point, context(base, fs))
    assert findings and findings[0].check == "path-traversal"


def test_sqli_time_fires_on_reproducible_delay():
    base = req("http://h/i?id=5")
    point = next(p for p in P.insertion_points(base) if p.label == "query:id")

    def timed(request):
        idv = request.query.get("id") or ""
        slow = "SLEEP" in idv.upper() or "WAITFOR" in idv.upper()
        return resp(b"ok"), "", (3.2 if slow else 0.05)
    findings = only(A.CHECKS_BY_NAME["sqli-time"], point, context(base, timed, time_delay_s=3.0))
    assert findings and findings[0].check == "sqli-time" and findings[0].confidence == "tentative"


def test_sqli_time_silent_when_baseline_slow():
    base = req("http://h/i?id=5")
    point = next(p for p in P.insertion_points(base) if p.label == "query:id")

    def always_slow(request):
        return resp(b"ok"), "", 5.0
    assert not only(A.CHECKS_BY_NAME["sqli-time"], point, context(base, always_slow, time_delay_s=3.0))


def test_a_broken_check_returns_no_findings():
    base = req("http://h/s?q=1")
    point = P.insertion_points(base)[0]

    def boom(request):
        raise RuntimeError("network gone")
    # send raises inside the check; ActiveCheck.run swallows it
    assert A.CHECKS_BY_NAME["xss-reflected"].run(point, context(base, boom)) == []


def test_select_checks_default_excludes_time_based():
    names = {c.name for c in A.select_checks(None)}
    assert "sqli-time" not in names and "xss-reflected" in names
    assert A.select_checks(("sqli-time",))[0].name == "sqli-time"


# ── engine: scope, progress, cancel ───────────────────────────────

def test_host_in_scope_exact_and_glob():
    assert host_in_scope("api.example.com", ("api.example.com",))
    assert host_in_scope("api.example.com", ("*.example.com",))
    assert not host_in_scope("evil.com", ("*.example.com",))


def fake_scanner(monkeypatch, exchange):
    import riff.replay as R
    monkeypatch.setattr(R, "exchange", exchange)
    hub = Hub()
    return Scanner(proxy=object(), hub=hub), hub


def wait_done(job, timeout=5.0):
    start = time.time()
    while job.status == "running" and time.time() - start < timeout:
        time.sleep(0.02)
    return job


def test_engine_requires_scope():
    scanner = Scanner(proxy=object(), hub=Hub())
    with pytest.raises(ScopeError):
        scanner.start([], ScanConfig(allowed_hosts=()))


def test_engine_skips_out_of_scope_hosts(monkeypatch):
    scanner, hub = fake_scanner(monkeypatch, lambda proxy, r: (resp(b"<html>x</html>"), "", 0.01))
    t = ScanTarget(flow_id=1, request=req("http://evil.test/s?q=1"), baseline=None)
    job = wait_done(scanner.start([t], ScanConfig(allowed_hosts=("good.test",))))
    assert job.status == "done" and job.units_total == 0 and hub.finding_counts()["total"] == 0


def test_engine_finds_and_reports_progress(monkeypatch):
    def reflect(proxy, request):
        return resp(f"<html>{request.query.get('q')}</html>".encode()), "", 0.01
    scanner, hub = fake_scanner(monkeypatch, reflect)
    t = ScanTarget(flow_id=7, request=req("http://shop.test/s?q=hi"), baseline=None)
    job = wait_done(scanner.start([t], ScanConfig(allowed_hosts=("*.test",))))
    assert job.status == "done"
    assert job.units_done == job.units_total and job.units_total > 0
    assert job.probes_sent > 0
    rows = hub.finding_rows()
    assert any(r["check"] == "xss-reflected" and r["flow_id"] == 7 for r in rows)


def test_engine_probe_refused_out_of_scope_even_if_check_targets_elsewhere(monkeypatch):
    # The bound exchange must refuse any host not in scope, regardless of the check.
    calls = []

    def spy(proxy, request):
        calls.append(request.host)
        return resp(b"x"), "", 0.01
    scanner, hub = fake_scanner(monkeypatch, spy)
    t = ScanTarget(flow_id=1, request=req("http://good.test/s?q=1"), baseline=None)
    wait_done(scanner.start([t], ScanConfig(allowed_hosts=("good.test",))))
    assert calls and all(h == "good.test" for h in calls)


def test_engine_cancel_stops_early(monkeypatch):
    def slow(proxy, request):
        time.sleep(0.05)
        return resp(b"<html>x</html>"), "", 0.01
    scanner, hub = fake_scanner(monkeypatch, slow)
    targets = [ScanTarget(flow_id=i, request=req(f"http://shop.test/s{i}?a=1&b=2&c=3"), baseline=None)
               for i in range(20)]
    job = scanner.start(targets, ScanConfig(allowed_hosts=("*.test",), max_workers=2))
    time.sleep(0.05)
    scanner.cancel(job.id)
    wait_done(job)
    assert job.status == "cancelled"


def test_targets_from_flows_carries_ids():
    from riff.flow import Flow
    f = Flow(id=42, request=req("http://h/x?a=1"))
    targets = targets_from_flows([f])
    assert targets[0].flow_id == 42 and targets[0].request.host == "h"


# ── phase 3 checks: boolean SQLi, command injection, SSRF ──────────────────

def test_sqli_boolean_fires_when_true_matches_and_false_differs():
    base = req("http://h/i?id=5")
    point = next(p for p in P.insertion_points(base) if p.label == "query:id")
    baseline = resp(b"<html>Product: Widget in stock, price 9.99</html>")

    def db(request):
        v = request.query.get("id") or ""
        false_like = "1=2" in v or "'1'='2" in v or '"1"="2' in v
        return (resp(b"<html>No results found</html>") if false_like
                else resp(b"<html>Product: Widget in stock, price 9.99</html>")), "", 0.01
    findings = only(A.CHECKS_BY_NAME["sqli-boolean"], point, context(base, db, baseline=baseline))
    assert findings and findings[0].check == "sqli-boolean"


def test_sqli_boolean_silent_when_true_and_false_identical():
    base = req("http://h/i?id=5")
    point = next(p for p in P.insertion_points(base) if p.label == "query:id")

    def same(request):
        return resp(b"<html>always the same</html>"), "", 0.01
    assert not only(A.CHECKS_BY_NAME["sqli-boolean"], point, context(base, same, baseline=resp(b"<html>always the same</html>")))


def test_cmd_injection_time_based():
    base = req("http://h/ping?host=127.0.0.1")
    point = next(p for p in P.insertion_points(base) if p.label == "query:host")

    def sh(request):
        v = (request.query.get("host") or "").lower()
        slow = "sleep" in v or "ping" in v
        return resp(b"ok"), "", (3.3 if slow else 0.04)
    findings = only(A.CHECKS_BY_NAME["cmd-injection"], point, context(base, sh, time_delay_s=3.0))
    assert findings and findings[0].check == "cmd-injection" and findings[0].confidence == "tentative"


def test_ssrf_fires_on_metadata_signature_for_urlish_param():
    base = req("http://h/fetch?url=http://example.com/a")
    point = next(p for p in P.insertion_points(base) if p.label == "query:url")

    def server(request):
        u = request.query.get("url") or ""
        if "169.254.169.254" in u:
            return resp(b"ami-id: ami-1\niam/security-credentials/role", headers=(("Content-Type", "text/plain"),)), "", 0.01
        return resp(b"<html>ok</html>"), "", 0.01
    findings = only(A.CHECKS_BY_NAME["ssrf"], point, context(base, server))
    assert findings and findings[0].check == "ssrf"


def test_ssrf_skips_non_urlish_params():
    base = req("http://h/i?id=5")
    point = next(p for p in P.insertion_points(base) if p.label == "query:id")

    def server(request):
        return resp(b"ami-id: ami-1", headers=(("Content-Type", "text/plain"),)), "", 0.01  # would match if probed
    assert not only(A.CHECKS_BY_NAME["ssrf"], point, context(base, server))


def test_default_checks_now_include_boolean_and_ssrf_but_not_timing():
    names = {c.name for c in A.select_checks(None)}
    assert {"sqli-boolean", "ssrf"} <= names
    assert "sqli-time" not in names and "cmd-injection" not in names


# ── report ─────────────────────────────────────────────────────────────────

def test_report_markdown_groups_by_category_and_has_remediation():
    from riff.scan import report
    rows = [
        {"check": "sqli-error", "title": "SQLi in query:id", "severity": "high", "flow_id": 1,
         "url": "http://h/i", "evidence": "db error", "confidence": "firm"},
        {"check": "missing-csp", "title": "CSP not set", "severity": "medium", "flow_id": 2,
         "url": "http://h/", "evidence": "no csp", "confidence": "firm"},
    ]
    md = report.to_markdown(rows, {"hosts": ["h"], "probes": 12})
    assert "SQL injection (A03 Injection)" in md and "**Fix:**" in md
    assert "Security misconfiguration (A05)" in md
    assert md.index("A03") < md.index("A05"), "worse categories first"


def test_report_json_enriches_with_category():
    import json
    from riff.scan import report
    rows = [{"check": "ssrf", "title": "SSRF", "severity": "high", "flow_id": 1, "url": "http://h/f", "confidence": "firm"}]
    doc = json.loads(report.to_json(rows, {"hosts": ["h"]}))
    assert doc["findings"][0]["category"].startswith("Server-side request forgery")
    assert doc["findings"][0]["remediation"]


# ── phase 4: out-of-band collaborator ──────────────────────────────────────

def test_collaborator_records_hits_by_token():
    from riff.scan.collaborator import Collaborator
    import urllib.request
    c = Collaborator().start()
    try:
        token, url = c.issue()
        assert c.hits(token) == []
        urllib.request.urlopen(url, timeout=3).read()
        # give the server thread a moment
        for _ in range(50):
            if c.hits(token):
                break
            time.sleep(0.02)
        assert c.hits(token) and c.hits(token)[0]["method"] == "GET"
        assert c.public()["interactions"] >= 1
    finally:
        c.stop()


def test_oob_check_inert_without_collaborator():
    base = req("http://h/f?url=http://x/")
    point = next(p for p in P.insertion_points(base) if p.label == "query:url")
    ctx = context(base, lambda r: (resp(b"ok"), "", 0.01))  # no collaborator
    assert only(A.CHECKS_BY_NAME["oob-interaction"], point, ctx) == []


def test_oob_check_registers_token_and_probes():
    from riff.scan.collaborator import Collaborator
    c = Collaborator().start()
    try:
        base = req("http://h/f?url=http://x/")
        point = next(p for p in P.insertion_points(base) if p.label == "query:url")
        sent = []
        registry = {}
        ctx = A.ProbeContext(base_flow_id=1, base_url=base.url, base_request=base, baseline=None,
                             exchange=lambda r: (sent.append(r.query.get("url")), (resp(b"ok"), "", 0.01))[1],
                             collaborator=c, oob_registry=registry)
        list(A.CHECKS_BY_NAME["oob-interaction"].run(point, ctx))
        assert registry, "a token was registered against a finding"
        assert any(c.base_url in (v or "") for v in sent), "the collaborator URL was injected"
    finally:
        c.stop()


def test_engine_out_of_band_detects_a_callback(monkeypatch):
    from riff.scan.collaborator import Collaborator
    import urllib.request
    c = Collaborator().start()
    try:
        # Fake target: whenever the injected value is the collaborator URL, "the server"
        # makes the outbound request itself (blind SSRF).
        def ssrf_target(proxy, request):
            u = request.query.get("url") or ""
            if u.startswith(c.base_url):
                try:
                    urllib.request.urlopen(u, timeout=2).read()
                except Exception:
                    pass
            return resp(b"<html>done</html>"), "", 0.01
        monkeypatch.setattr("riff.replay.exchange", ssrf_target)
        hub = Hub()
        scanner = Scanner(proxy=object(), hub=hub)
        t = ScanTarget(flow_id=3, request=req("http://shop.test/fetch?url=http://feeds.test/rss"), baseline=None)
        job = scanner.start([t], ScanConfig(allowed_hosts=("*.test",), collaborator=c, oob_grace_s=4.0))
        wait_done(job, timeout=10)
        assert job.status == "done"
        rows = hub.finding_rows()
        assert any(r["check"] == "oob-interaction" and r["flow_id"] == 3 for r in rows)
    finally:
        c.stop()


def test_collaborator_added_to_checks_when_configured():
    from riff.scan.collaborator import Collaborator
    c = Collaborator()  # not started; we only inspect config
    cfg = ScanConfig(allowed_hosts=("h",), collaborator=c)
    assert any(chk.name == "oob-interaction" for chk in cfg.checks)
    cfg2 = ScanConfig(allowed_hosts=("h",))
    assert not any(chk.name == "oob-interaction" for chk in cfg2.checks)

"""Lexer, parser and interpreter behaviour."""

from __future__ import annotations

import pytest

from riff.flow import Flow, Request, Response
from riff.http import Headers
from riff.script import Engine
from riff.script.errors import RiffSyntaxError
from riff.script.lexer import tokenize


def make_flow(
    method="GET",
    url="https://api.example.com/v1/things?page=2",
    headers=(("Host", "api.example.com"), ("Accept", "application/json")),
    body=b"",
) -> Flow:
    request = Request(method=method, headers=Headers(headers), body=body)
    request.set_url(url)
    return Flow(id=1, client="127.0.0.1:1", tls=url.startswith("https"), request=request)


def with_response(flow: Flow, status=200, headers=(("Content-Type", "application/json"),), body=b"{}") -> Flow:
    flow.response = Response(status=status, reason="OK", headers=Headers(headers), body=body)
    return flow


def run(source: str, flow: Flow, phase="request"):
    engine = Engine.from_source(source)
    return engine, engine.run(flow, phase)


# ── lexing ──────────────────────────────────────────────────────────────


def test_units_become_plain_numbers():
    kinds = [(t.kind, t.value) for t in tokenize("500ms 2s 64kb 1mb") if t.kind == "num"]
    assert kinds == [("num", 500), ("num", 2000), ("num", 65536), ("num", 1048576)]


def test_comments_and_raw_strings():
    tokens = [t for t in tokenize('# hi\n/* x */ r"a\\d+" // tail\n') if t.kind == "str"]
    assert [t.value for t in tokens] == ["a\\d+"]


def test_newline_is_a_statement_terminator_but_not_inside_brackets():
    kinds = [t.kind for t in tokenize("f(1,\n2)\ng")]
    assert kinds.count("nl") == 2  # one after f(...), one at end


def test_syntax_error_points_at_the_problem():
    with pytest.raises(RiffSyntaxError) as info:
        Engine.from_source('on request where host == { }')
    assert info.value.line == 1
    assert "expected a value" in info.value.message


def test_unknown_statement_is_rejected_with_a_hint():
    with pytest.raises(RiffSyntaxError) as info:
        Engine.from_source("on request { frobnicate 1 }")
    assert "frobnicate" in info.value.message


# ── matching ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "condition,expected",
    [
        ('host == "api.example.com"', True),
        ('host == "other.com"', False),
        ('host ~ "^api\\."', True),
        ('host !~ "^api\\."', False),
        ('path starts with "/v1"', True),
        ('path ends with "/things"', True),
        ('path contains "thing"', True),
        ('method in ["GET", "POST"]', True),
        ('method not in ["POST"]', True),
        ('query["page"] == 2', True),
        ('query["page"] > 1', True),
        ('query["missing"] == null', True),
        ('header["accept"] == "application/json"', True),
        ('header["ACCEPT"] contains "json"', True),
        ('header["nope"] == null', True),
        ("not tls", False),
        ('scheme == "https" and port == 443', True),
        ('host == "x" or method == "GET"', True),
        ("size == 0", True),
    ],
)
def test_conditions(condition, expected):
    flow = make_flow()
    engine, _ = run(f'on request where {condition} {{ tag "hit" }}', flow)
    assert ("hit" in flow.tags) is expected


def test_bare_domain_pattern_covers_subdomains_only_when_it_should():
    engine = Engine.from_source('decrypt "example.com"')
    assert engine.tls_policy("api.example.com") == "decrypt"
    assert engine.tls_policy("example.com") == "decrypt"
    assert engine.tls_policy("notexample.com") == "passthru"
    assert engine.tls_policy("other.org") == "passthru"


def test_decrypt_everything_when_no_directives():
    assert Engine.empty().tls_policy("anything.test") == "decrypt"


def test_passthru_only_still_decrypts_the_rest():
    engine = Engine.from_source('passthru "*.bank.com"')
    assert engine.tls_policy("secure.bank.com") == "passthru"
    assert engine.tls_policy("api.example.com") == "decrypt"


def test_regex_tls_pattern():
    engine = Engine.from_source('decrypt "re:^(api|edge)\\."')
    assert engine.tls_policy("api.x.com") == "decrypt"
    assert engine.tls_policy("www.x.com") == "passthru"


# ── mutation ────────────────────────────────────────────────────────────


def test_header_set_add_and_remove():
    flow = make_flow()
    run(
        """
        on request {
            set header "X-Trace" = "abc"
            add header "X-Multi" = "1"
            add header "X-Multi" = "2"
            remove header "Accept"
        }
        """,
        flow,
    )
    assert flow.request.headers.get("x-trace") == "abc"
    assert flow.request.headers.get_all("X-Multi") == ["1", "2"]
    assert flow.request.headers.get("accept") is None


def test_set_header_replaces_rather_than_duplicating():
    flow = make_flow(headers=(("Host", "h"), ("X-A", "1"), ("X-A", "2")))
    run('on request { set header "X-A" = "9" }', flow)
    assert flow.request.headers.get_all("X-A") == ["9"]


def test_url_and_host_rewrites_track_the_host_header():
    flow = make_flow()
    run('on request { set url = "https://new.example.com:8443/other?x=1" }', flow)
    assert flow.request.host == "new.example.com"
    assert flow.request.port == 8443
    assert flow.request.origin_form == "/other?x=1"
    assert flow.request.headers.get("Host") == "new.example.com:8443"


def test_path_only_rewrite_keeps_the_origin():
    flow = make_flow()
    run('on request { rewrite url "/replaced" }', flow)
    assert flow.request.url == "https://api.example.com/replaced"


def test_query_edits():
    flow = make_flow()
    run('on request { set query "page" = "9"\n set query "new" = "x"\n remove query "nope" }', flow)
    assert flow.request.query.as_dict() == {"page": "9", "new": "x"}


def test_body_replacement_fixes_content_length():
    flow = make_flow(method="POST", body=b"old")
    flow.request.headers.set("Content-Length", "3")
    run('on request { set body = "{\\"a\\": 1}" }', flow)
    assert flow.request.body == b'{"a": 1}'
    assert flow.request.headers.get("Content-Length") == "8"


def test_json_helpers_read_structured_bodies():
    flow = make_flow(method="POST", body=b'{"user": {"name": "ada"}, "n": 3}')
    run(
        """
        on request where json(body)["user"]["name"] == "ada" {
            tag "ada"
            set header "X-N" = json(body)["n"] + 1
        }
        """,
        flow,
    )
    assert flow.tags == ["ada"]
    assert flow.request.headers.get("X-N") == "4"


def test_respond_short_circuits_and_stops_later_rules():
    flow = make_flow()
    _, verdict = run(
        """
        on request { respond 200 "{\\"ok\\": true}" as json }
        on request { tag "should-not-run" }
        """,
        flow,
    )
    assert verdict.intercepted and flow.intercepted
    assert flow.response.status == 200
    assert flow.response.headers.get("Content-Type") == "application/json"
    assert flow.response.headers.get("Content-Length") == "12"
    assert flow.tags == []


def test_abort_and_delay_reach_the_verdict():
    flow = make_flow()
    _, verdict = run("on request { delay 250ms\n abort }", flow)
    assert verdict.delay_ms == 250
    assert verdict.abort and flow.aborted


def test_stop_halts_only_the_remaining_rules():
    flow = make_flow()
    run('on request { tag "a"\n stop }\non request { tag "b" }', flow)
    assert flow.tags == ["a"]


def test_if_else_chain():
    flow = with_response(make_flow(), status=503)
    run(
        """
        on response {
            if status >= 500 { tag "server" }
            else if status >= 400 { tag "client" }
            else { tag "fine" }
        }
        """,
        flow,
        phase="response",
    )
    assert flow.tags == ["server"]


def test_counters_and_variables():
    engine = Engine.from_source(
        """
        let threshold = 400
        on response where status >= threshold { count "bad" }
        """
    )
    for status in (200, 404, 500):
        flow = with_response(make_flow(), status=status)
        engine.run(flow, "response")
    assert engine.counters == {"bad": 2}


def test_response_rules_see_request_fields():
    flow = with_response(make_flow(), status=200)
    run(
        'on response where req.method == "GET" and host == "api.example.com" { tag "ok" }',
        flow,
        phase="response",
    )
    assert flow.tags == ["ok"]


def test_status_rewrite_and_body_swap_on_response():
    flow = with_response(make_flow(), status=200, body=b'{"real": true}')
    run('on response { set status = 503\n set body = "nope" }', flow, phase="response")
    assert flow.response.status == 503
    assert flow.response.body == b"nope"
    assert flow.response.headers.get("Content-Length") == "4"


# ── redaction ───────────────────────────────────────────────────────────


def test_redact_header_and_body_json():
    flow = make_flow(
        method="POST",
        headers=(("Host", "h"), ("Authorization", "Bearer supersecret")),
        body=b'{"password": "hunter2", "pin": 1234, "keep": "yes"}',
    )
    run('on request { redact header "authorization"\n redact body "password"\n redact body "pin" }', flow)
    assert "supersecret" not in flow.request.headers.get("Authorization")
    text = flow.request.text()
    assert "hunter2" not in text and "1234" not in text
    assert '"keep": "yes"' in text


def test_redact_body_handles_form_encoding():
    flow = make_flow(method="POST", body=b"user=ada&password=hunter2&x=1")
    run('on request { redact body "password" }', flow)
    assert b"hunter2" not in flow.request.body
    assert b"user=ada" in flow.request.body and b"x=1" in flow.request.body


def test_redacting_a_missing_header_is_a_no_op():
    flow = make_flow()
    run('on request { redact header "authorization" }', flow)
    assert flow.request.headers.get("authorization") is None


# ── errors ──────────────────────────────────────────────────────────────


def test_runtime_error_names_the_line():
    from riff.script.errors import RiffRuntimeError

    flow = make_flow()
    with pytest.raises(RiffRuntimeError) as info:
        run("on request {\n  set status = 500\n}", flow)
    assert info.value.line == 2
    assert "on response" in info.value.message


def test_unknown_function_lists_alternatives():
    from riff.script.errors import RiffRuntimeError

    with pytest.raises(RiffRuntimeError) as info:
        run('on request where nope(host) { tag "x" }', make_flow())
    assert "unknown function" in info.value.message


# ── capture / ignore (the host display filter) ──────────────────────────


def test_capture_turns_the_list_into_an_allowlist():
    engine = Engine.from_source('capture "localhost"\ncapture "*.example.com"')
    assert engine.should_capture("localhost") is True
    assert engine.should_capture("api.example.com") is True
    assert engine.should_capture("google.com") is False


def test_everything_is_captured_when_nothing_is_named():
    assert Engine.empty().should_capture("anything.test") is True
    engine = Engine.from_source('decrypt "*.example.com"')
    assert engine.should_capture("google.com") is True


def test_ignore_alone_captures_everything_else():
    engine = Engine.from_source('ignore "*.events.data.microsoft.com"')
    assert engine.should_capture("watsonc.events.data.microsoft.com") is False
    assert engine.should_capture("api.example.com") is True


def test_first_match_wins_so_ignore_goes_first():
    ordered = Engine.from_source('ignore "telemetry.example.com"\ncapture "*.example.com"')
    assert ordered.should_capture("telemetry.example.com") is False
    assert ordered.should_capture("api.example.com") is True

    # The other order is why the docs say to put ignore first.
    reversed_ = Engine.from_source('capture "*.example.com"\nignore "telemetry.example.com"')
    assert reversed_.should_capture("telemetry.example.com") is True


def test_capture_is_independent_of_decrypt():
    engine = Engine.from_source('decrypt "*.example.com"\ncapture "localhost"')
    assert engine.tls_policy("api.example.com") == "decrypt"
    assert engine.should_capture("api.example.com") is False

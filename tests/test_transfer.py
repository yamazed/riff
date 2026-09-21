"""Export to riff JSON / HAR and back again."""

import json

import pytest

from riff import transfer
from riff.flow import Flow, Request, Response
from riff.http import Headers


def _flow(flow_id=7, body=b'{"ok":true}', tags=("slow",)) -> Flow:
    request = Request(method="POST", headers=Headers([("Content-Type", "application/json"), ("Cookie", "a=1; b=2")]),
                      body=b'{"q":1}')
    request.set_url("https://api.example.com/v1/things?x=1&y=two")
    flow = Flow(id=flow_id, client="127.0.0.1:5000", tls=True, request=request, started=1_700_000_000.25)
    flow.response = Response(status=201, reason="Created", body=body,
                             headers=Headers([("Content-Type", "application/json"), ("Set-Cookie", "sid=abc; Path=/; HttpOnly")]))
    flow.ended = flow.started + 0.345
    for tag in tags:
        flow.tag(tag)
    return flow


def _details(*flows):
    return [f.to_dict() for f in flows]


# ── riff format ─────────────────────────────────────────────────────────


def test_riff_export_round_trips_every_field_that_matters():
    original = _flow()
    payload = json.loads(json.dumps(transfer.export_riff(_details(original))))
    assert payload["format"] == "riff-flows"

    [back] = transfer.import_flows(payload)
    assert back.request.method == "POST"
    assert back.request.url == original.request.url
    assert back.request.headers.get("cookie") == "a=1; b=2"
    assert back.request.body == b'{"q":1}'
    assert back.response.status == 201
    assert back.response.reason == "Created"
    assert back.response.body == b'{"ok":true}'
    assert back.response.headers.get("set-cookie") == "sid=abc; Path=/; HttpOnly"
    assert back.tls is True
    assert back.started == original.started
    assert round(back.duration_ms) == 345
    assert back.tags == ["slow", "imported"], "imported rows are marked, existing tags kept"
    assert back.id == 0, "ids are the importer's business"


def test_binary_bodies_survive_via_base64():
    original = _flow(body=b"\x89PNG\r\n\x1a\n\x00\x01\x02")
    [back] = transfer.import_flows(transfer.export_riff(_details(original)))
    assert back.response.body == b"\x89PNG\r\n\x1a\n\x00\x01\x02"


def test_a_flow_without_a_response_imports_with_its_error():
    flow = _flow()
    flow.response = None
    flow.error = "upstream refused"
    [back] = transfer.import_flows(transfer.export_riff(_details(flow)))
    assert back.response is None
    assert back.error == "upstream refused"


def test_a_bare_list_or_single_detail_is_accepted_too():
    detail = _flow().to_dict()
    assert len(transfer.import_flows([detail, detail])) == 2
    assert len(transfer.import_flows(detail)) == 1


# ── HAR ─────────────────────────────────────────────────────────────────


def test_har_export_has_the_shape_other_tools_expect():
    har = json.loads(json.dumps(transfer.export_har(_details(_flow()))))
    log = har["log"]
    assert log["version"] == "1.2"
    assert log["creator"]["name"] == "riff"
    [entry] = log["entries"]
    assert entry["startedDateTime"].endswith("Z")
    assert entry["time"] == 345.0
    req = entry["request"]
    assert req["method"] == "POST"
    assert req["queryString"] == [{"name": "x", "value": "1"}, {"name": "y", "value": "two"}]
    assert {"name": "Cookie", "value": "a=1; b=2"} in req["headers"]
    assert req["cookies"] == [{"name": "a", "value": "1"}, {"name": "b", "value": "2"}]
    assert req["postData"] == {"mimeType": "application/json", "text": '{"q":1}'}
    resp = entry["response"]
    assert resp["status"] == 201 and resp["statusText"] == "Created"
    assert resp["content"]["mimeType"] == "application/json"
    assert resp["content"]["text"] == '{"ok":true}'
    assert resp["cookies"] == [{"name": "sid", "value": "abc"}], "cookie attributes are not cookies"
    assert "tags=slow" in entry["comment"] and "tls" in entry["comment"]


def test_har_round_trip_keeps_request_response_and_tags():
    har = transfer.export_har(_details(_flow()))
    [back] = transfer.import_flows(json.loads(json.dumps(har)))
    assert back.request.url == "https://api.example.com/v1/things?x=1&y=two"
    assert back.request.body == b'{"q":1}'
    assert back.response.status == 201
    assert back.response.body == b'{"ok":true}'
    assert back.tls is True
    assert back.tags == ["slow", "imported"]
    assert abs(back.started - 1_700_000_000.25) < 0.001


def test_a_chrome_style_har_imports():
    """The subset Chrome DevTools writes, including a base64 body."""
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "WebInspector", "version": "537.36"},
            "entries": [
                {
                    "startedDateTime": "2026-09-08T10:00:00.000Z",
                    "time": 12.5,
                    "request": {
                        "method": "GET",
                        "url": "https://cdn.example.com/logo.png",
                        "httpVersion": "http/2.0",
                        "headers": [{"name": "accept", "value": "image/*"}],
                        "queryString": [],
                        "cookies": [],
                        "headersSize": -1,
                        "bodySize": 0,
                    },
                    "response": {
                        "status": 200,
                        "statusText": "",
                        "httpVersion": "http/2.0",
                        "headers": [{"name": "content-type", "value": "image/png"}],
                        "cookies": [],
                        "content": {"size": 4, "mimeType": "image/png", "text": "iVBORw==", "encoding": "base64"},
                        "redirectURL": "",
                        "headersSize": -1,
                        "bodySize": 4,
                    },
                    "cache": {},
                    "timings": {"send": 0, "wait": 12.5, "receive": 0},
                }
            ],
        }
    }
    [flow] = transfer.import_flows(har)
    assert flow.request.host == "cdn.example.com"
    assert flow.request.headers.get("accept") == "image/*"
    assert flow.response.body == b"\x89PNG"
    assert flow.tags == ["imported"]
    assert flow.tls is True


# ── rejection ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("payload", [{}, {"format": "something-else"}, "text", 42, {"log": {"entries": "nope"}}])
def test_things_that_are_not_exports_are_refused(payload):
    with pytest.raises(transfer.TransferError):
        transfer.import_flows(payload)


def test_an_entry_without_a_url_is_reported_by_position():
    payload = transfer.export_riff(_details(_flow()))
    payload["flows"].append({"request": {"method": "GET", "url": ""}})
    with pytest.raises(transfer.TransferError, match="entry 2"):
        transfer.import_flows(payload)

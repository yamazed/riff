"""Collections, environments, variables, auth and v2.1 collection interchange."""

import json
import os

import pytest

from riff import workspace as ws
from riff.flow import Flow, Response
from riff.http import Headers


@pytest.fixture
def space(tmp_path):
    return ws.Workspace(str(tmp_path / "work"), str(tmp_path / "home"))


# ── names ────────────────────────────────────────────────────────────────


def test_slugify_makes_safe_file_names():
    assert ws.slugify("Widget APIs (dvm)") == "widget-apis-dvm"
    assert ws.slugify("  ../../etc/passwd ") == "etc-passwd"
    with pytest.raises(ws.WorkspaceError):
        ws.slugify("!!!")


@pytest.mark.parametrize("bad", ["../x", "a/b", "A", "", "x" * 70, "con:"])
def test_path_traversal_and_junk_names_are_refused(space, bad):
    with pytest.raises(ws.WorkspaceError):
        space.load_collection(bad)
    with pytest.raises(ws.WorkspaceError):
        space.save_environment(bad, {})


# ── collections ─────────────────────────────────────────────────────────


def test_collection_round_trip_and_listing(space):
    slug, doc = space.create_collection("Listings API")
    assert slug == "listings-api"
    doc["requests"].append(
        {"name": "Search", "method": "post", "url": "{{baseUrl}}/v1/search",
         "headers": [{"name": "Accept", "value": "application/json"}],
         "body": {"mode": "json", "text": '{"q": "{{term}}"}'}}
    )
    saved = space.save_collection(slug, doc)
    assert saved["requests"][0]["method"] == "POST"
    assert saved["requests"][0]["id"], "requests get ids"
    assert saved["requests"][0]["auth"] == {"type": "inherit"}

    [summary] = space.list_collections()
    assert summary["slug"] == slug and summary["name"] == "Listings API"
    assert summary["requests"][0]["name"] == "Search"

    again = space.load_collection(slug)
    assert again == saved
    assert json.load(open(os.path.join(space.collections_dir, slug + ".json"), encoding="utf-8"))["format"] == "riff-collection"

    space.delete_collection(slug)
    assert space.list_collections() == []
    with pytest.raises(ws.WorkspaceError):
        space.delete_collection(slug)


def test_duplicate_collection_names_get_a_suffix(space):
    assert space.create_collection("Same")[0] == "same"
    assert space.create_collection("Same")[0] == "same-2"


def test_malformed_requests_are_rejected_with_a_reason(space):
    with pytest.raises(ws.WorkspaceError, match="method"):
        space.save_collection("x", {"name": "x", "requests": [{"method": "FETCH", "url": "http://a"}]})
    with pytest.raises(ws.WorkspaceError, match="body mode"):
        space.save_collection("x", {"name": "x", "requests": [{"url": "http://a", "body": {"mode": "yaml"}}]})
    with pytest.raises(ws.WorkspaceError, match="needs a name"):
        ws.normalise_collection({"requests": []})


# ── environments and personal values ────────────────────────────────────


def test_variable_precedence_collection_env_personal(space):
    space.save_environment("dvm", {"baseUrl": "https://dvm.example", "token": "shared-token", "region": "us"})
    space.set_personal("*", {"token": "my-global-token", "user": "ada"})
    space.set_personal("dvm", {"token": "my-dvm-token"})
    collection = {"variables": {"region": "eu", "page": "1"}}

    merged = space.variables("dvm", collection)
    assert merged == {"baseUrl": "https://dvm.example", "token": "my-dvm-token", "region": "us", "user": "ada", "page": "1"}
    assert space.variables("", collection)["token"] == "my-global-token"
    assert space.variables("", collection)["region"] == "eu"


def test_personal_values_live_in_their_own_file_and_can_merge(space):
    space.set_personal("dvm", {"a": "1"})
    space.set_personal("dvm", {"b": "2"}, merge=True)
    assert space.personal("dvm") == {"a": "1", "b": "2"}
    space.set_personal("dvm", {"c": "3"})
    assert space.personal("dvm") == {"c": "3"}, "a plain set replaces"
    assert os.path.exists(space.personal_file)
    assert not os.path.exists(os.path.join(space.root, "personal-values.json")), "never in the shared workspace"
    assert space.list_environments() == []  # personal values do not invent environments


def test_environment_listing_counts(space):
    space.save_environment("prd", {"baseUrl": "https://prd", "x": "y"})
    space.set_personal("prd", {"token": "t"})
    assert space.list_environments() == [{"name": "prd", "values": 2, "personal": 1}]
    space.delete_environment("prd")
    assert space.list_environments() == []


# ── resolve and prepare ────────────────────────────────────────────────


def test_resolve_reports_missing_names_once():
    text, missing = ws.resolve("{{a}}/{{ b }}/{{a}}/{{c}}", {"a": "1", "b": "2"})
    assert text == "1/2/1/{{c}}"
    assert missing == ["c"]


def test_prepare_folds_params_auth_and_json_body():
    request = {
        "method": "post",
        "url": "{{baseUrl}}/v1/search?existing=1",
        "params": [{"name": "q", "value": "{{term}}", "enabled": True}, {"name": "off", "value": "x", "enabled": False}],
        "headers": [{"name": "X-Trace", "value": "{{trace}}", "enabled": True}],
        "body": {"mode": "json", "text": '{"term": "{{term}}"}'},
        "auth": {"type": "bearer", "token": "{{token}}"},
    }
    prepared = ws.prepare(request, {"baseUrl": "https://api.example.com", "term": "office space", "token": "T0K", "trace": "abc"})
    assert prepared.method == "POST"
    assert prepared.url == "https://api.example.com/v1/search?existing=1&q=office%20space"
    assert ("Authorization", "Bearer T0K") in prepared.headers
    assert ("Content-Type", "application/json") in prepared.headers
    assert ("X-Trace", "abc") in prepared.headers
    assert prepared.body == b'{"term": "office space"}'
    assert prepared.missing == []


def test_prepare_inherits_collection_auth_and_supports_basic_apikey_form():
    inherit = {"method": "GET", "url": "https://a.example/x", "auth": {"type": "inherit"}}
    basic = ws.prepare(inherit, {}, collection_auth={"type": "basic", "username": "u", "password": "p"})
    assert ("Authorization", "Basic dTpw") in basic.headers

    apikey_q = ws.prepare(
        {"method": "GET", "url": "https://a.example/x", "auth": {"type": "apikey", "key": "api_key", "value": "K", "in": "query"}}, {}
    )
    assert apikey_q.url.endswith("?api_key=K")

    form = ws.prepare(
        {"method": "POST", "url": "https://a.example/x", "body": {"mode": "form", "form": [{"name": "a", "value": "1 2"}, {"name": "b", "value": "&"}]}},
        {},
    )
    assert form.body == b"a=1+2&b=%26"
    assert ("Content-Type", "application/x-www-form-urlencoded") in form.headers


def test_prepare_leaves_unknown_variables_visible_and_lists_them():
    prepared = ws.prepare({"method": "GET", "url": "{{host}}/{{path}}"}, {"host": "https://h"})
    assert prepared.url == "https://h/%7B%7Bpath%7D%7D" or "{{path}}" in prepared.url
    assert prepared.missing == ["path"]


def test_an_explicit_authorization_header_beats_the_auth_helper():
    prepared = ws.prepare(
        {"method": "GET", "url": "https://a.example/", "headers": [{"name": "Authorization", "value": "Bearer mine"}],
         "auth": {"type": "bearer", "token": "theirs"}},
        {},
    )
    assert [v for k, v in prepared.headers if k.lower() == "authorization"] == ["Bearer mine"]


# ── captures ───────────────────────────────────────────────────────────


def _flow_with(body: bytes, headers=(), status=200) -> Flow:
    flow = Flow()
    flow.response = Response(status=status, headers=Headers(list(headers)), body=body)
    return flow


def test_captures_pull_json_paths_headers_and_status():
    flow = _flow_with(b'{"access_token": "abc", "data": {"items": [{"id": 7}, {"id": 8}]}, "n": 3}',
                      headers=[("X-Request-Id", "req-1")], status=201)
    got = ws.extract_captures(
        [
            {"var": "token", "from": "json", "path": "access_token"},
            {"var": "second", "from": "json", "path": "data.items[1].id"},
            {"var": "count", "from": "json", "path": "n"},
            {"var": "whole", "from": "json", "path": "data.items"},
            {"var": "rid", "from": "header", "path": "x-request-id"},
            {"var": "code", "from": "status", "path": ""},
            {"var": "nope", "from": "json", "path": "does.not.exist"},
        ],
        flow,
    )
    assert got == {"token": "abc", "second": "8", "count": "3", "whole": '[{"id":7},{"id":8}]', "rid": "req-1", "code": "201"}


def test_captures_survive_a_non_json_body_and_a_missing_response():
    assert ws.extract_captures([{"var": "t", "from": "json", "path": "a"}], _flow_with(b"<html>")) == {}
    assert ws.extract_captures([{"var": "t", "from": "status"}], Flow()) == {}


# ── Collection v2.1 and HAR interchange ────────────────────────────────────────


COLLECTION_V2 = {
    "info": {"name": "Demo API sample", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
    "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}", "type": "string"}]},
    "variable": [{"key": "baseUrl", "value": "https://api.example.com"}],
    "item": [
        {
            "name": "Search",
            "item": [
                {
                    "name": "By term",
                    "request": {
                        "method": "POST",
                        "header": [{"key": "Accept", "value": "application/json"}, {"key": "X-Off", "value": "1", "disabled": True}],
                        "url": {"raw": "{{baseUrl}}/v1/search?page=1", "host": ["{{baseUrl}}"], "path": ["v1", "search"]},
                        "body": {"mode": "raw", "raw": '{"q": "x"}', "options": {"raw": {"language": "json"}}},
                    },
                    "response": [],
                }
            ],
        },
        {
            "name": "Login",
            "request": {
                "method": "POST",
                "url": "https://login.example.com/token",
                "auth": {"type": "basic", "basic": [{"key": "username", "value": "u"}, {"key": "password", "value": "p"}]},
                "body": {"mode": "urlencoded", "urlencoded": [{"key": "grant_type", "value": "client_credentials"}]},
            },
        },
        {"name": "Ping", "request": "https://api.example.com/ping"},
    ],
}


def test_v2_import_keeps_folders_auth_variables_bodies():
    col = ws.import_collection_v2(COLLECTION_V2)
    assert col["name"] == "Demo API sample"
    assert col["auth"] == {"type": "bearer", "token": "{{token}}"}
    assert col["variables"] == {"baseUrl": "https://api.example.com"}
    names = [r["name"] for r in col["requests"]]
    assert names == ["By term", "Login", "Ping"]
    assert [f["path"] for f in col["folders"]] == ["Search"]
    assert [r["folder"] for r in col["requests"]] == ["Search", "", ""]
    search, login, ping = col["requests"]
    assert search["url"] == "{{baseUrl}}/v1/search?page=1"
    assert search["body"] == {"mode": "json", "text": '{"q": "x"}', "form": []}
    assert search["headers"] == [
        {"name": "Accept", "value": "application/json", "enabled": True},
        {"name": "X-Off", "value": "1", "enabled": False},
    ]
    assert search["auth"] == {"type": "inherit"}
    assert login["auth"] == {"type": "basic", "username": "u", "password": "p"}
    assert login["body"]["mode"] == "form" and login["body"]["form"][0]["name"] == "grant_type"
    assert ping["method"] == "GET" and ping["url"] == "https://api.example.com/ping"


def test_v2_export_reimports_to_the_same_collection():
    col = ws.import_collection_v2(COLLECTION_V2)
    exported = ws.export_collection_v2(col)
    assert exported["info"]["schema"].endswith("v2.1.0/collection.json")
    assert exported["auth"]["type"] == "bearer"
    back = ws.import_collection_v2(json.loads(json.dumps(exported)))
    strip = lambda c: [{k: v for k, v in r.items() if k != "id"} for r in c["requests"]]  # noqa: E731
    assert strip(back) == strip(col)
    assert back["variables"] == col["variables"]
    assert back["auth"] == col["auth"]


def test_folders_are_ordered_paths_with_implied_parents(space):
    col = ws.normalise_collection({
        "name": "SCIM",
        "folders": ["User tests/Garbage", {"path": " Group tests ", "description": "groups"}],
        "requests": [
            {"url": "https://a/users", "folder": "User tests"},
            {"url": "https://a/teardown", "folder": "Teardown \\ late/"},
            {"url": "https://a/", "folder": ""},
        ],
    })
    assert [f["path"] for f in col["folders"]] == ["User tests", "User tests/Garbage", "Group tests", "Teardown", "Teardown/late"]
    assert col["folders"][2]["description"] == "groups"
    assert [r["folder"] for r in col["requests"]] == ["User tests", "Teardown/late", ""]

    slug, _ = space.create_collection("SCIM")
    space.save_collection(slug, col)
    [summary] = space.list_collections()
    assert summary["folders"] == ["User tests", "User tests/Garbage", "Group tests", "Teardown", "Teardown/late"]
    assert [r["folder"] for r in summary["requests"]] == ["User tests", "Teardown/late", ""]


def test_v2_export_nests_folders_and_reimports_them():
    col = ws.normalise_collection({
        "name": "Nested",
        "folders": [{"path": "Users", "description": "everything about users"}, "Users/Garbage", "Groups"],
        "requests": [
            {"name": "List users", "url": "https://a/users", "folder": "Users"},
            {"name": "Bad user", "url": "https://a/users/bad", "folder": "Users/Garbage"},
            {"name": "Ping", "url": "https://a/ping"},
        ],
    })
    exported = ws.export_collection_v2(col)
    assert [i["name"] for i in exported["item"]] == ["Users", "Groups", "Ping"]
    users = exported["item"][0]
    assert users["description"] == "everything about users"
    assert [i["name"] for i in users["item"]] == ["Garbage", "List users"]
    assert users["item"][0]["item"][0]["name"] == "Bad user"
    assert exported["item"][1]["item"] == []

    back = ws.import_collection_v2(json.loads(json.dumps(exported)))
    assert [f["path"] for f in back["folders"]] == ["Users", "Users/Garbage", "Groups"]
    assert back["folders"][0]["description"] == "everything about users"
    assert {r["name"]: r["folder"] for r in back["requests"]} == {"List users": "Users", "Bad user": "Users/Garbage", "Ping": ""}


def test_har_becomes_a_collection_of_requests():
    har = {"log": {"entries": [
        {"request": {"method": "POST", "url": "https://api.example.com/v1/things?x=1",
                     "headers": [{"name": "Host", "value": "api.example.com"}, {"name": "Content-Type", "value": "application/json"}],
                     "postData": {"mimeType": "application/json", "text": '{"a":1}'}}},
        {"request": {"method": "GET", "url": "https://api.example.com/v1/things/1", "headers": []}},
    ]}}
    col = ws.import_har_collection(har, name="From HAR")
    assert col["name"] == "From HAR"
    assert [r["name"] for r in col["requests"]] == ["POST /v1/things", "GET /v1/things/1"]
    assert col["requests"][0]["body"]["mode"] == "json"
    assert all(h["name"].lower() != "host" for h in col["requests"][0]["headers"])


def test_detect_and_import_recognises_all_three_and_rejects_junk():
    assert ws.detect_and_import(COLLECTION_V2)["name"] == "Demo API sample"
    assert ws.detect_and_import({"log": {"entries": []}}, name="h")["name"] == "h"
    assert ws.detect_and_import({"format": "riff-collection", "name": "r", "requests": []})["name"] == "r"
    with pytest.raises(ws.WorkspaceError):
        ws.detect_and_import({"hello": "world"})
    with pytest.raises(ws.WorkspaceError):
        ws.detect_and_import([1, 2, 3])

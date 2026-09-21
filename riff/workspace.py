"""Saved requests, environments and variables behind the Composer.

Everything is plain JSON on disk so it can sit next to `rules.riff` and be
checked into a repo:

    <workspace>/collections/<slug>.json      riff-collection v1
    <workspace>/environments/<name>.json     riff-environment v1
    <personal>/personal-values.json          per-machine overrides (tokens)

Requests can sit in folders: `folder` on a request is a path such as
"Users" or "Users/Garbage" (slash-separated, any depth), and the collection's
`folders` list fixes the order and keeps empty folders alive. An imported Collection v2.1 item
tree maps onto that one to one.

Variables use `{{name}}` syntax. Resolution order, later wins:
collection variables, environment values, personal "*" values, personal
values for the selected environment. Personal values never leave the machine.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from .ca import restrict_to_owner

COLLECTION_FORMAT = "riff-collection"
ENVIRONMENT_FORMAT = "riff-environment"
FORMAT_VERSION = 1
PERSONAL_FILE = "personal-values.json"

_SLUG_OK = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SLUG_BAD = re.compile(r"[^a-z0-9._-]+")
_VAR = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\}\}")
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
BODY_MODES = ("none", "json", "text", "form")
AUTH_TYPES = ("none", "inherit", "bearer", "basic", "apikey")


class WorkspaceError(ValueError):
    """Bad name, malformed document, or a file that will not read/write."""


def slugify(name: str) -> str:
    slug = _SLUG_BAD.sub("-", (name or "").strip().lower()).strip("-.")[:64]
    if not slug or not _SLUG_OK.match(slug):
        raise WorkspaceError(f"{name!r} does not make a usable file name")
    return slug


def _check_slug(slug: str) -> str:
    if not _SLUG_OK.match(slug or ""):
        raise WorkspaceError(f"{slug!r} is not a valid name: letters, digits, dot, dash and underscore only")
    return slug


# ------------------------------------------------------------- normalising


def _kv_list(items, *, enabled_default=True) -> list[dict]:
    out = []
    for item in items or []:
        if isinstance(item, dict):
            name = str(item.get("name", item.get("key", "")) or "")
            value = str(item.get("value", "") or "")
            enabled = bool(item.get("enabled", not item.get("disabled", not enabled_default)))
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            name, value, enabled = str(item[0]), str(item[1]), True
        else:
            continue
        if name or value:
            out.append({"name": name, "value": value, "enabled": enabled})
    return out


def folder_path(value) -> str:
    """Tidy a folder path: `a / b//c` -> `a/b/c`; empty means the collection root."""
    parts = [p.strip() for p in str(value or "").replace("\\", "/").split("/")]
    return "/".join(p for p in parts if p)


def folder_parents(path: str) -> list[str]:
    """`a/b/c` -> [`a`, `a/b`]."""
    parts = path.split("/") if path else []
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def normalise_folders(folders, requests: list[dict]) -> list[dict]:
    """Ordered folder list: declared ones first (parents implied), then any a request mentions."""
    out: list[dict] = []
    seen: set[str] = set()

    def add(path: str, description: str = "") -> None:
        for parent in folder_parents(path):
            add(parent)
        if path and path not in seen:
            seen.add(path)
            out.append({"path": path, "description": description})

    for item in folders or []:
        if isinstance(item, dict):
            add(folder_path(item.get("path") or item.get("name")), str(item.get("description") or ""))
        elif isinstance(item, str):
            add(folder_path(item))
    for req in requests:
        add(req.get("folder") or "")
    return out


def normalise_auth(auth) -> dict:
    auth = auth if isinstance(auth, dict) else {}
    kind = str(auth.get("type") or "none").lower()
    if kind not in AUTH_TYPES:
        raise WorkspaceError(f"unknown auth type {kind!r}")
    out = {"type": kind}
    for key in ("token", "username", "password", "key", "value"):
        if auth.get(key):
            out[key] = str(auth[key])
    if kind == "apikey":
        out["in"] = "query" if str(auth.get("in", "header")).lower() == "query" else "header"
    return out


def normalise_request(req) -> dict:
    if not isinstance(req, dict):
        raise WorkspaceError("a request must be an object")
    method = str(req.get("method") or "GET").upper()
    if method not in METHODS:
        raise WorkspaceError(f"unsupported method {method!r}")
    body = req.get("body") if isinstance(req.get("body"), dict) else {}
    mode = str(body.get("mode") or ("none" if not body.get("text") else "text")).lower()
    if mode not in BODY_MODES:
        raise WorkspaceError(f"unknown body mode {mode!r}")
    captures = []
    for cap in req.get("capture") or []:
        if not isinstance(cap, dict) or not cap.get("var"):
            continue
        source = str(cap.get("from") or "json").lower()
        if source not in ("json", "header", "status"):
            raise WorkspaceError(f"capture source must be json, header or status, not {source!r}")
        captures.append({"var": str(cap["var"]).strip(), "from": source, "path": str(cap.get("path") or "")})
    return {
        "id": str(req.get("id") or uuid.uuid4().hex[:12]),
        "name": str(req.get("name") or "").strip() or f"{method} {str(req.get('url') or '').strip()}"[:80],
        "description": str(req.get("description") or ""),
        "folder": folder_path(req.get("folder")),
        "method": method,
        "url": str(req.get("url") or "").strip(),
        "params": _kv_list(req.get("params")),
        "headers": _kv_list(req.get("headers")),
        "body": {"mode": mode, "text": str(body.get("text") or ""), "form": _kv_list(body.get("form"))},
        "auth": normalise_auth(req.get("auth") or {"type": "inherit"}),
        "capture": captures,
    }


def normalise_collection(doc, *, fallback_name: str = "") -> dict:
    if not isinstance(doc, dict):
        raise WorkspaceError("a collection must be an object")
    name = str(doc.get("name") or fallback_name or "").strip()
    if not name:
        raise WorkspaceError("a collection needs a name")
    variables = doc.get("variables") if isinstance(doc.get("variables"), dict) else {}
    requests = doc.get("requests")
    if requests is None:
        requests = []
    if not isinstance(requests, list):
        raise WorkspaceError("`requests` must be a list")
    clean = [normalise_request(r) for r in requests]
    return {
        "format": COLLECTION_FORMAT,
        "version": FORMAT_VERSION,
        "name": name,
        "description": str(doc.get("description") or ""),
        "auth": normalise_auth(doc.get("auth") or {"type": "none"}),
        "variables": {str(k): str(v) for k, v in variables.items()},
        "folders": normalise_folders(doc.get("folders"), clean),
        "requests": clean,
    }


# --------------------------------------------------------------- variables


def resolve(text: str, variables: dict) -> tuple[str, list[str]]:
    """Substitute {{name}}; report names that had no value (left in place)."""
    missing: list[str] = []

    def sub(match):
        name = match.group(1)
        if name in variables:
            return str(variables[name])
        if name not in missing:
            missing.append(name)
        return match.group(0)

    return _VAR.sub(sub, text or ""), missing


@dataclass(slots=True)
class Prepared:
    method: str
    url: str
    headers: list[tuple[str, str]]
    body: bytes
    missing: list[str] = field(default_factory=list)


def prepare(request: dict, variables: dict, collection_auth: dict | None = None) -> Prepared:
    """Resolve variables, fold params/auth/body into a concrete request."""
    req = normalise_request(request)
    missing: list[str] = []

    def r(text: str) -> str:
        out, gone = resolve(text, variables)
        for name in gone:
            if name not in missing:
                missing.append(name)
        return out

    url = r(req["url"])
    parts = urlsplit(url if "://" in url else f"https://{url}")
    query = parse_qsl(parts.query, keep_blank_values=True)
    for p in req["params"]:
        if p["enabled"] and p["name"]:
            query.append((r(p["name"]), r(p["value"])))

    headers = [(r(h["name"]), r(h["value"])) for h in req["headers"] if h["enabled"] and h["name"]]
    lower = {k.lower() for k, _ in headers}

    auth = req["auth"]
    if auth["type"] == "inherit":
        auth = normalise_auth(collection_auth or {"type": "none"})
    if auth["type"] == "bearer" and "authorization" not in lower:
        headers.append(("Authorization", "Bearer " + r(auth.get("token", ""))))
    elif auth["type"] == "basic" and "authorization" not in lower:
        import base64

        raw = f"{r(auth.get('username', ''))}:{r(auth.get('password', ''))}".encode("utf-8")
        headers.append(("Authorization", "Basic " + base64.b64encode(raw).decode("ascii")))
    elif auth["type"] == "apikey" and auth.get("key"):
        if auth.get("in") == "query":
            query.append((r(auth["key"]), r(auth.get("value", ""))))
        elif r(auth["key"]).lower() not in lower:
            headers.append((r(auth["key"]), r(auth.get("value", ""))))

    body = req["body"]
    payload = b""
    if body["mode"] == "json":
        payload = r(body["text"]).encode("utf-8")
        if "content-type" not in lower:
            headers.append(("Content-Type", "application/json"))
    elif body["mode"] == "text":
        payload = r(body["text"]).encode("utf-8")
    elif body["mode"] == "form":
        pairs = [(r(f["name"]), r(f["value"])) for f in body["form"] if f["enabled"] and f["name"]]
        payload = urlencode(pairs).encode("utf-8")
        if "content-type" not in lower:
            headers.append(("Content-Type", "application/x-www-form-urlencoded"))

    final_url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(query, quote_via=quote), parts.fragment))
    return Prepared(method=req["method"], url=final_url, headers=headers, body=payload, missing=missing)


def _json_path(value, path: str):
    """Tiny dotted path: `data.items[0].id` or `data.items.0.id`."""
    for part in re.split(r"\.|\[|\]", path.strip().lstrip("$.")):
        if part == "":
            continue
        if isinstance(value, list):
            try:
                value = value[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(value, dict):
            if part not in value:
                return None
            value = value[part]
        else:
            return None
    return value


def extract_captures(captures: list[dict], flow) -> dict[str, str]:
    """Pull values out of a completed flow's response, per the request's capture list."""
    out: dict[str, str] = {}
    response = getattr(flow, "response", None)
    if response is None:
        return out
    parsed = None
    parsed_tried = False
    for cap in captures or []:
        source, path, var = cap.get("from", "json"), cap.get("path", ""), cap.get("var", "")
        if not var:
            continue
        if source == "status":
            out[var] = str(response.status)
        elif source == "header":
            value = response.headers.get(path)
            if value is not None:
                out[var] = value
        else:
            if not parsed_tried:
                parsed_tried = True
                try:
                    parsed = json.loads(response.body.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    parsed = None
            if parsed is None:
                continue
            value = _json_path(parsed, path) if path else parsed
            if value is not None:
                out[var] = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    return out


# ---------------------------------------------------------------- storage


class Workspace:
    def __init__(self, root: str, personal_dir: str):
        self.root = os.path.abspath(root)
        self.personal_dir = os.path.abspath(personal_dir)

    # -- paths ---------------------------------------------------------------

    @property
    def collections_dir(self) -> str:
        return os.path.join(self.root, "collections")

    @property
    def environments_dir(self) -> str:
        return os.path.join(self.root, "environments")

    @property
    def personal_file(self) -> str:
        return os.path.join(self.personal_dir, PERSONAL_FILE)

    @staticmethod
    def _read(path: str):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise WorkspaceError(f"cannot read {os.path.basename(path)}: {exc}") from None

    @staticmethod
    def _write(path: str, doc, private: bool = False) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
            os.replace(tmp, path)
            if private:
                restrict_to_owner(path)
        except OSError as exc:
            raise WorkspaceError(f"cannot write {os.path.basename(path)}: {exc}") from None

    def _listing(self, directory: str) -> list[str]:
        try:
            names = sorted(os.listdir(directory))
        except FileNotFoundError:
            return []
        return [n[:-5] for n in names if n.endswith(".json") and _SLUG_OK.match(n[:-5])]

    # -- collections --------------------------------------------------------------

    def list_collections(self) -> list[dict]:
        out = []
        for slug in self._listing(self.collections_dir):
            try:
                doc = self.load_collection(slug)
            except WorkspaceError as exc:
                out.append({"slug": slug, "name": slug, "error": str(exc), "requests": []})
                continue
            out.append(
                {
                    "slug": slug,
                    "name": doc["name"],
                    "folders": [f["path"] for f in doc["folders"]],
                    "requests": [
                        {"id": r["id"], "name": r["name"], "method": r["method"], "url": r["url"], "folder": r["folder"]}
                        for r in doc["requests"]
                    ],
                }
            )
        return out

    def load_collection(self, slug: str) -> dict:
        path = os.path.join(self.collections_dir, _check_slug(slug) + ".json")
        doc = self._read(path)
        if doc is None:
            raise WorkspaceError(f"there is no collection called {slug!r}")
        return normalise_collection(doc, fallback_name=slug)

    def save_collection(self, slug: str, doc) -> dict:
        clean = normalise_collection(doc, fallback_name=slug)
        self._write(os.path.join(self.collections_dir, _check_slug(slug) + ".json"), clean)
        return clean

    def create_collection(self, name: str) -> tuple[str, dict]:
        slug = slugify(name)
        base, n = slug, 2
        while os.path.exists(os.path.join(self.collections_dir, slug + ".json")):
            slug, n = f"{base}-{n}", n + 1
        return slug, self.save_collection(slug, {"name": name, "requests": []})

    def delete_collection(self, slug: str) -> None:
        path = os.path.join(self.collections_dir, _check_slug(slug) + ".json")
        try:
            os.remove(path)
        except FileNotFoundError:
            raise WorkspaceError(f"there is no collection called {slug!r}") from None
        except OSError as exc:
            raise WorkspaceError(f"cannot delete {slug}: {exc}") from None

    # -- environments ---------------------------------------------------------------

    def list_environments(self) -> list[dict]:
        out = []
        for name in self._listing(self.environments_dir):
            try:
                values = self.load_environment(name)["values"]
            except WorkspaceError:
                values = {}
            out.append({"name": name, "values": len(values), "personal": len(self.personal(name))})
        return out

    def load_environment(self, name: str) -> dict:
        doc = self._read(os.path.join(self.environments_dir, _check_slug(name) + ".json"))
        if doc is None:
            raise WorkspaceError(f"there is no environment called {name!r}")
        values = doc.get("values") if isinstance(doc, dict) and isinstance(doc.get("values"), dict) else {}
        return {"format": ENVIRONMENT_FORMAT, "version": FORMAT_VERSION, "name": name, "values": {str(k): str(v) for k, v in values.items()}}

    def save_environment(self, name: str, values: dict) -> dict:
        if not isinstance(values, dict):
            raise WorkspaceError("environment values must be an object of name: value")
        doc = {
            "format": ENVIRONMENT_FORMAT,
            "version": FORMAT_VERSION,
            "name": _check_slug(name),
            "values": {str(k).strip(): str(v) for k, v in values.items() if str(k).strip()},
        }
        self._write(os.path.join(self.environments_dir, name + ".json"), doc)
        return doc

    def delete_environment(self, name: str) -> None:
        try:
            os.remove(os.path.join(self.environments_dir, _check_slug(name) + ".json"))
        except FileNotFoundError:
            raise WorkspaceError(f"there is no environment called {name!r}") from None
        except OSError as exc:
            raise WorkspaceError(f"cannot delete {name}: {exc}") from None

    # -- personal values (this machine only) ------------------------------------------

    def _personal_all(self) -> dict:
        doc = self._read(self.personal_file)
        return doc if isinstance(doc, dict) else {}

    def personal(self, environment: str) -> dict:
        values = self._personal_all().get(environment or "*", {})
        return {str(k): str(v) for k, v in values.items()} if isinstance(values, dict) else {}

    def set_personal(self, environment: str, values: dict, merge: bool = False) -> dict:
        if not isinstance(values, dict):
            raise WorkspaceError("personal values must be an object of name: value")
        key = environment or "*"
        if key != "*":
            _check_slug(key)
        everything = self._personal_all()
        current = everything.get(key, {}) if merge and isinstance(everything.get(key), dict) else {}
        current.update({str(k).strip(): str(v) for k, v in values.items() if str(k).strip()})
        everything[key] = current
        self._write(self.personal_file, everything, private=True)
        return current

    # -- putting it together -------------------------------------------------------------

    def variables(self, environment: str = "", collection: dict | None = None) -> dict:
        merged: dict = {}
        if collection:
            merged.update(collection.get("variables") or {})
        if environment:
            merged.update(self.load_environment(environment)["values"])
        merged.update(self.personal("*"))
        if environment:
            merged.update(self.personal(environment))
        return merged


# --------------------------------------------------------------- interchange


def import_collection_v2(doc: dict, *, name: str = "") -> dict:
    """Collection v2.x → riff collection. The item tree becomes riff folders."""
    if not isinstance(doc, dict) or not isinstance(doc.get("item"), list):
        raise WorkspaceError("not a v2 collection (no `item` list)")
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    requests: list[dict] = []
    folders: list[dict] = []

    def walk(items, folder: str):
        for item in items:
            if not isinstance(item, dict):
                continue
            title = str(item.get("name") or "")
            if isinstance(item.get("item"), list):
                segment = title.replace("/", "-").strip() or "folder"
                path = f"{folder}/{segment}" if folder else segment
                about = item.get("description")
                folders.append({"path": path, "description": about if isinstance(about, str) else ""})
                walk(item["item"], path)
                continue
            req = item.get("request")
            if isinstance(req, str):
                req = {"method": "GET", "url": req}
            if not isinstance(req, dict):
                continue
            url = req.get("url")
            if isinstance(url, dict):
                url = url.get("raw") or ""
            body = req.get("body") if isinstance(req.get("body"), dict) else {}
            mode = str(body.get("mode") or "none")
            riff_body = {"mode": "none", "text": "", "form": []}
            if mode == "raw":
                language = str(((body.get("options") or {}).get("raw") or {}).get("language") or "").lower()
                riff_body = {"mode": "json" if language == "json" else "text", "text": str(body.get("raw") or ""), "form": []}
            elif mode in ("urlencoded", "formdata"):
                riff_body = {"mode": "form", "text": "", "form": _kv_list(body.get(mode))}
            requests.append(
                {
                    "name": title.strip() or None,
                    "folder": folder,
                    "description": str(req.get("description") or "") if not isinstance(req.get("description"), dict) else "",
                    "method": str(req.get("method") or "GET"),
                    "url": str(url or ""),
                    "headers": _kv_list(req.get("header")),
                    "body": riff_body,
                    "auth": _collection_v2_auth(req.get("auth")) if req.get("auth") else {"type": "inherit"},
                }
            )

    walk(doc["item"], "")
    variables = {}
    for var in doc.get("variable") or []:
        if isinstance(var, dict) and var.get("key"):
            variables[str(var["key"])] = str(var.get("value", ""))
    return normalise_collection(
        {
            "name": name or str(info.get("name") or "Imported collection"),
            "description": str(info.get("description") or "") if not isinstance(info.get("description"), dict) else "",
            "auth": _collection_v2_auth(doc.get("auth")) if doc.get("auth") else {"type": "none"},
            "variables": variables,
            "folders": folders,
            "requests": requests,
        }
    )


def _collection_v2_auth(auth) -> dict:
    if not isinstance(auth, dict):
        return {"type": "none"}
    kind = str(auth.get("type") or "noauth").lower()
    if kind == "noauth":
        return {"type": "none"}
    if kind not in ("bearer", "basic", "apikey"):
        return {"type": "none"}
    values = {}
    for entry in auth.get(kind) or []:
        if isinstance(entry, dict) and entry.get("key"):
            values[str(entry["key"])] = str(entry.get("value", ""))
    if kind == "bearer":
        return {"type": "bearer", "token": values.get("token", "")}
    if kind == "basic":
        return {"type": "basic", "username": values.get("username", ""), "password": values.get("password", "")}
    return {"type": "apikey", "key": values.get("key", ""), "value": values.get("value", ""), "in": values.get("in", "header")}


def _to_collection_v2_auth(auth: dict) -> dict | None:
    kind = auth.get("type", "none")
    if kind in ("none", "inherit"):
        return None if kind == "inherit" else {"type": "noauth"}
    if kind == "bearer":
        return {"type": "bearer", "bearer": [{"key": "token", "value": auth.get("token", ""), "type": "string"}]}
    if kind == "basic":
        return {
            "type": "basic",
            "basic": [
                {"key": "username", "value": auth.get("username", ""), "type": "string"},
                {"key": "password", "value": auth.get("password", ""), "type": "string"},
            ],
        }
    return {
        "type": "apikey",
        "apikey": [
            {"key": "key", "value": auth.get("key", ""), "type": "string"},
            {"key": "value", "value": auth.get("value", ""), "type": "string"},
            {"key": "in", "value": auth.get("in", "header"), "type": "string"},
        ],
    }


def export_collection_v2(collection: dict) -> dict:
    """riff collection → Collection v2.1. Folders become nested items, in the collection's order."""
    col = normalise_collection(collection)
    items: list[dict] = []
    nodes: dict[str, dict] = {}
    for folder in col["folders"]:
        node: dict = {"name": folder["path"].rsplit("/", 1)[-1], "item": []}
        if folder["description"]:
            node["description"] = folder["description"]
        nodes[folder["path"]] = node
        parent = folder["path"].rsplit("/", 1)[0] if "/" in folder["path"] else ""
        (nodes[parent]["item"] if parent else items).append(node)
    for req in col["requests"]:
        url = req["url"]
        extra = [f"{p['name']}={p['value']}" for p in req["params"] if p["enabled"] and p["name"]]
        if extra:
            url += ("&" if "?" in url else "?") + "&".join(extra)
        body = None
        if req["body"]["mode"] in ("json", "text"):
            body = {"mode": "raw", "raw": req["body"]["text"]}
            if req["body"]["mode"] == "json":
                body["options"] = {"raw": {"language": "json"}}
        elif req["body"]["mode"] == "form":
            body = {
                "mode": "urlencoded",
                "urlencoded": [
                    {"key": f["name"], "value": f["value"], "type": "text", **({} if f["enabled"] else {"disabled": True})}
                    for f in req["body"]["form"]
                ],
            }
        request: dict = {
            "method": req["method"],
            "header": [
                {"key": h["name"], "value": h["value"], "type": "text", **({} if h["enabled"] else {"disabled": True})}
                for h in req["headers"]
            ],
            "url": {"raw": url},
        }
        if req["description"]:
            request["description"] = req["description"]
        if body:
            request["body"] = body
        auth = _to_collection_v2_auth(req["auth"])
        if auth:
            request["auth"] = auth
        target = nodes[req["folder"]]["item"] if req["folder"] else items
        target.append({"name": req["name"], "request": request, "response": []})

    out = {
        "info": {
            "name": col["name"],
            "description": col["description"],
            # The v2.1 spec identifies itself by this URL; importers key off it.
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
        "variable": [{"key": k, "value": v, "type": "string"} for k, v in col["variables"].items()],
    }
    auth = _to_collection_v2_auth(col["auth"])
    if auth and auth["type"] != "noauth":
        out["auth"] = auth
    return out


def import_har_collection(har: dict, *, name: str = "") -> dict:
    """A HAR file becomes a collection of its requests (responses are dropped)."""
    from .transfer import _pairs  # same header shapes

    log = har.get("log") if isinstance(har, dict) else None
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        raise WorkspaceError("not a HAR file")
    requests = []
    for entry in log["entries"]:
        req = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(req, dict) or not req.get("url"):
            continue
        post = req.get("postData") if isinstance(req.get("postData"), dict) else {}
        text = str(post.get("text") or "")
        mime = str(post.get("mimeType") or "")
        if text and "json" in mime:
            body = {"mode": "json", "text": text}
        elif text:
            body = {"mode": "text", "text": text}
        else:
            body = {"mode": "none"}
        headers = [(k, v) for k, v in _pairs(req.get("headers")) if k.lower() not in ("host", "content-length", ":authority", ":method", ":path", ":scheme")]
        parts = urlsplit(str(req["url"]))
        requests.append(
            {
                "name": f"{req.get('method', 'GET')} {parts.path or '/'}"[:80],
                "method": str(req.get("method") or "GET"),
                "url": str(req["url"]),
                "headers": headers,
                "body": body,
            }
        )
    return normalise_collection({"name": name or "Imported from HAR", "requests": requests})


def detect_and_import(payload, *, name: str = "") -> dict:
    """Whatever the user dropped in: riff collection, v2.1 collection, or HAR."""
    if isinstance(payload, dict):
        if payload.get("format") == COLLECTION_FORMAT:
            return normalise_collection(payload, fallback_name=name)
        if isinstance(payload.get("item"), list) and isinstance(payload.get("info"), dict):
            return import_collection_v2(payload, name=name)
        if isinstance(payload.get("log"), dict):
            return import_har_collection(payload, name=name)
        if isinstance(payload.get("requests"), list) and payload.get("name"):
            return normalise_collection(payload)
    raise WorkspaceError("not a riff collection, a v2.1 collection or a HAR file")


def stamp() -> float:
    return time.time()

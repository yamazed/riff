"""Insertion points: the places in a request where the active scanner injects.

Given a base request, `insertion_points` enumerates every value an attacker
could control: each query parameter, each form or JSON body field, and each
path segment. A point knows how to rebuild the request with a payload in place
of (or appended to) its original value, so a check can probe one input at a
time without disturbing the others.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..flow import Request
from ..http import Headers, Query

# Body types we know how to take apart. Anything else is treated as opaque.
_FORM_TYPE = "application/x-www-form-urlencoded"


def _clone_request(base: Request) -> Request:
    return Request(
        method=base.method,
        scheme=base.scheme,
        host=base.host,
        port=base.port,
        path=base.path,
        query=Query([list(p) for p in base.query.pairs]),
        version=base.version,
        headers=base.headers.copy(),
        body=base.body,
    )


@dataclass
class InsertionPoint:
    kind: str      # query | body-form | body-json | path
    name: str      # parameter/field name, JSON path, or path-segment index
    original: str  # the value that is there now

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.name}"

    def inject(self, base: Request, payload: str, mode: str = "replace") -> Request:
        """A copy of `base` with `payload` placed at this point.

        mode 'replace' swaps the value; mode 'append' adds the payload onto the
        original (useful for path traversal onto a real filename).
        """
        value = payload if mode == "replace" else (self.original + payload)
        request = _clone_request(base)
        if self.kind == "query":
            request.query.set(self.name, value)
        elif self.kind == "body-form":
            form = Query.parse(base.text())
            form.set(self.name, value)
            request.body = form.encode().encode("utf-8")
        elif self.kind == "body-json":
            doc = json.loads(base.text())
            _json_set(doc, _parse_json_path(self.name), value)
            request.body = json.dumps(doc).encode("utf-8")
        elif self.kind == "path":
            segments = base.path.split("/")
            idx = int(self.name)
            if 0 <= idx < len(segments):
                segments[idx] = value
            request.path = "/".join(segments)
        return request


# ── JSON path helpers (a.b[0].c) ──────────────────────────────────

def _parse_json_path(path: str) -> list[Any]:
    steps: list[Any] = []
    for part in path.replace("]", "").split("."):
        if "[" in part:
            name, _, index = part.partition("[")
            if name:
                steps.append(name)
            steps.append(int(index))
        elif part:
            steps.append(part)
    return steps


def _json_set(doc: Any, steps: list[Any], value: str) -> None:
    cursor = doc
    for step in steps[:-1]:
        cursor = cursor[step]
    cursor[steps[-1]] = value


def _json_leaves(doc: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Every string/number/bool leaf, as (json-path, original-as-text)."""
    out: list[tuple[str, str]] = []
    if isinstance(doc, dict):
        for key, val in doc.items():
            out.extend(_json_leaves(val, f"{prefix}.{key}" if prefix else key))
    elif isinstance(doc, list):
        for i, val in enumerate(doc):
            out.extend(_json_leaves(val, f"{prefix}[{i}]"))
    elif isinstance(doc, (str, int, float, bool)) and prefix:
        out.append((prefix, str(doc)))
    return out


# ── enumeration ───────────────────────────────────────────────────

def insertion_points(base: Request, include_path: bool = True) -> list[InsertionPoint]:
    points: list[InsertionPoint] = []

    for key, value in base.query.pairs:
        points.append(InsertionPoint("query", key, value))

    ctype = (base.headers.get("content-type") or "").split(";")[0].strip().lower()
    if base.body:
        if ctype == _FORM_TYPE:
            for key, value in Query.parse(base.text()).pairs:
                points.append(InsertionPoint("body-form", key, value))
        elif ctype == "application/json" or _looks_like_json(base.text()):
            try:
                for path, value in _json_leaves(json.loads(base.text())):
                    points.append(InsertionPoint("body-json", path, value))
            except (ValueError, TypeError):
                pass

    if include_path:
        for i, segment in enumerate(base.path.split("/")):
            if segment:  # skip the empty leading segment
                points.append(InsertionPoint("path", str(i), segment))

    return points


def _looks_like_json(text: str) -> bool:
    stripped = text.strip()
    return stripped.startswith("{") or stripped.startswith("[")

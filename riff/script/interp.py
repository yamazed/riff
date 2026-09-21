"""Tree-walking evaluator: runs parsed riff rules against a live Flow."""

from __future__ import annotations

import base64
import fnmatch
import functools
import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from . import nodes as N
from .errors import RiffRuntimeError
from .parser import parse

REDACTED = "«redacted»"


@functools.lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern:
    return re.compile(pattern)


class _StopRules(Exception):
    """Internal control-flow signal: stop evaluating rules for this flow."""


# ------------------------------------------------------------------- views


class HeaderView:
    """Case-insensitive read view over a Headers instance."""

    __slots__ = ("_h",)

    def __init__(self, headers):
        self._h = headers

    def riff_index(self, key):
        return self._h.get(str(key))

    def riff_member(self, name):
        return self._h.get(name.replace("_", "-"))

    def riff_contains(self, item) -> bool:
        return str(item) in self._h

    def riff_len(self) -> int:
        return len(self._h)

    def riff_value(self):
        return {k: v for k, v in self._h.items()}

    def __str__(self) -> str:
        return json.dumps(self.riff_value(), sort_keys=True)


class QueryView:
    __slots__ = ("_q",)

    def __init__(self, query):
        self._q = query

    def riff_index(self, key):
        return self._q.get(str(key))

    riff_member = riff_index

    def riff_contains(self, item) -> bool:
        return self._q.get(str(item)) is not None

    def riff_len(self) -> int:
        return len(self._q.pairs)

    def riff_value(self):
        return self._q.as_dict()

    def __str__(self) -> str:
        return self._q.encode()


class DictView:
    __slots__ = ("_d",)

    def __init__(self, data: dict):
        self._d = data

    def riff_index(self, key):
        return self._d.get(str(key))

    riff_member = riff_index

    def riff_contains(self, item) -> bool:
        return str(item) in self._d

    def riff_len(self) -> int:
        return len(self._d)

    def riff_value(self):
        return dict(self._d)

    def __str__(self) -> str:
        return json.dumps(self._d, sort_keys=True)


class MsgView:
    """`req.` / `resp.` namespace exposed inside rules."""

    __slots__ = ("_fields",)

    def __init__(self, fields: dict[str, Callable[[], Any]]):
        self._fields = fields

    def riff_member(self, name):
        getter = self._fields.get(name)
        if getter is None:
            raise RiffRuntimeError(f"unknown field {name!r} (available: {', '.join(sorted(self._fields))})")
        return getter()

    riff_index = riff_member

    def riff_contains(self, item) -> bool:
        return str(item) in self._fields

    def __str__(self) -> str:
        return "<message>"


# ------------------------------------------------------------------ helpers


def truthy(value) -> bool:
    if value is None or value is False:
        return False
    if value is True:
        return True
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, (str, bytes, list, tuple, dict)):
        return len(value) > 0
    if hasattr(value, "riff_len"):
        return value.riff_len() > 0
    return True


def as_text(value) -> str:
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def _numeric(value):
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text)
        except ValueError:
            try:
                return float(text)
            except ValueError:
                return None
    return None


def compare(op: str, left, right, line: int) -> bool:
    if op in ("==", "!="):
        result = _equal(left, right)
        return result if op == "==" else not result
    lnum, rnum = _numeric(left), _numeric(right)
    if lnum is not None and rnum is not None:
        left, right = lnum, rnum
    else:
        left, right = as_text(left), as_text(right)
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    if op == ">":
        return left > right
    if op == ">=":
        return left >= right
    raise RiffRuntimeError(f"unsupported comparison {op!r}", line)


def _equal(left, right) -> bool:
    if left is None or right is None:
        return left is right or (left is None and right is None)
    if isinstance(left, bool) or isinstance(right, bool):
        return truthy(left) == truthy(right)
    lnum, rnum = _numeric(left), _numeric(right)
    if lnum is not None and rnum is not None:
        return lnum == rnum
    return as_text(left) == as_text(right)


def _unwrap(value):
    return value.riff_value() if hasattr(value, "riff_value") else value


# ---------------------------------------------------------------- builtins


def _json_load(text):
    try:
        return json.loads(as_text(text))
    except Exception:
        return None


BUILTINS: dict[str, Callable[..., Any]] = {
    "lower": lambda s: as_text(s).lower(),
    "upper": lambda s: as_text(s).upper(),
    "trim": lambda s: as_text(s).strip(),
    "len": lambda x: x.riff_len() if hasattr(x, "riff_len") else len(_unwrap(x) or ""),
    "int": lambda x: int(_numeric(x) or 0),
    "float": lambda x: float(_numeric(x) or 0.0),
    "str": as_text,
    "json": _json_load,
    "dumps": lambda x: json.dumps(_unwrap(x), separators=(",", ":")),
    "replace": lambda s, a, b: as_text(s).replace(as_text(a), as_text(b)),
    "split": lambda s, sep=",": as_text(s).split(as_text(sep)),
    "join": lambda items, sep=",": as_text(sep).join(as_text(i) for i in (_unwrap(items) or [])),
    "uuid": lambda: str(uuid.uuid4()),
    "now": lambda: int(time.time() * 1000),
    "env": lambda name, default="": os.environ.get(as_text(name), as_text(default)),
    "b64encode": lambda s: base64.b64encode(as_text(s).encode()).decode(),
    "b64decode": lambda s: base64.b64decode(as_text(s) + "===").decode("utf-8", "replace"),
    "sha256": lambda s: hashlib.sha256(as_text(s).encode()).hexdigest(),
    "regex_group": lambda pat, s, n=1: (
        (_compile(as_text(pat)).search(as_text(s)) or _NoMatch()).group(int(_numeric(n) or 1))
    ),
    "glob": lambda pat, s: fnmatch.fnmatch(as_text(s).lower(), as_text(pat).lower()),
}


class _NoMatch:
    def group(self, _n):
        return None


# ------------------------------------------------------------------ verdict


@dataclass(slots=True)
class Verdict:
    abort: bool = False
    delay_ms: float = 0.0
    intercepted: bool = False
    save_dirs: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)


# ------------------------------------------------------------------- engine


class Engine:
    """Holds a parsed program plus its runtime state (globals, counters)."""

    def __init__(self, program: N.Program, path: str = "", on_log: Callable[[Any, str], None] | None = None):
        self.program = program
        self.path = path
        self.on_log = on_log or (lambda flow, text: None)
        self.globals: dict[str, Any] = {}
        self.counters: dict[str, int] = {}
        self.tls_rules: list[tuple[str, str]] = []
        self.capture_rules: list[tuple[str, str]] = []
        self._default_decrypt = True
        self._default_capture = True
        self._bootstrap()

    # -- construction ------------------------------------------------------

    @classmethod
    def from_source(cls, source: str, path: str = "", **kwargs) -> "Engine":
        return cls(parse(source, path), path, **kwargs)

    @classmethod
    def from_file(cls, path: str, **kwargs) -> "Engine":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_source(fh.read(), path, **kwargs)

    @classmethod
    def empty(cls, **kwargs) -> "Engine":
        return cls(N.Program(), "<none>", **kwargs)

    def _bootstrap(self) -> None:
        """Evaluate top-level directives once, with no flow in scope."""
        ctx = _Ctx(engine=self, flow=None, phase="config", verdict=Verdict())
        for directive in self.program.directives:
            if isinstance(directive, N.SetVar):
                self.globals[directive.name] = self._eval(directive.value, ctx)
            elif isinstance(directive, N.TlsDirective):
                self.tls_rules.append((directive.mode, as_text(self._eval(directive.pattern, ctx))))
            elif isinstance(directive, N.CaptureDirective):
                self.capture_rules.append((directive.mode, as_text(self._eval(directive.pattern, ctx))))
        self._default_decrypt = not any(mode == "decrypt" for mode, _ in self.tls_rules)
        # Naming any host to capture turns the list into an allowlist:
        # once you list one host, only listed hosts are captured.
        self._default_capture = not any(mode == "capture" for mode, _ in self.capture_rules)

    # -- TLS policy --------------------------------------------------------

    def tls_policy(self, host: str) -> str:
        """Return 'decrypt' or 'passthru' for a CONNECT target host."""
        target = host.lower()
        for mode, pattern in self.tls_rules:
            if _host_matches(pattern, target):
                return mode
        return "decrypt" if self._default_decrypt else "passthru"

    def should_capture(self, host: str) -> bool:
        """Whether a flow for `host` is recorded. It is proxied either way."""
        target = (host or "").lower()
        for mode, pattern in self.capture_rules:
            if _host_matches(pattern, target):
                return mode == "capture"
        return self._default_capture

    @property
    def rule_count(self) -> int:
        return len(self.program.rules)

    # -- execution ---------------------------------------------------------

    def run(self, flow, phase: str) -> Verdict:
        verdict = Verdict()
        ctx = _Ctx(engine=self, flow=flow, phase=phase, verdict=verdict)
        try:
            for rule in self.program.rules:
                if rule.phase != phase:
                    continue
                if rule.cond is not None and not truthy(self._eval(rule.cond, ctx)):
                    continue
                self._exec_block(rule.body, ctx)
        except _StopRules:
            pass
        return verdict

    # -- statements --------------------------------------------------------

    def _exec_block(self, stmts: list[N.Node], ctx: "_Ctx") -> None:
        for stmt in stmts:
            self._exec(stmt, ctx)

    def _exec(self, stmt: N.Node, ctx: "_Ctx") -> None:
        kind = type(stmt)
        handler = _STATEMENTS.get(kind)
        if handler is None:  # pragma: no cover - parser prevents this
            raise RiffRuntimeError(f"cannot execute {kind.__name__}", stmt.line)
        handler(self, stmt, ctx)

    # -- expressions -------------------------------------------------------

    def _eval(self, node: N.Node, ctx: "_Ctx"):
        kind = type(node)
        if kind is N.Literal:
            return node.value
        if kind is N.Name:
            return ctx.lookup(node.ident, node.line)
        if kind is N.Binary:
            return self._eval_binary(node, ctx)
        if kind is N.Logical:
            left = self._eval(node.left, ctx)
            if node.op == "and":
                return self._eval(node.right, ctx) if truthy(left) else left
            return left if truthy(left) else self._eval(node.right, ctx)
        if kind is N.Unary:
            value = self._eval(node.operand, ctx)
            if node.op == "not":
                return not truthy(value)
            num = _numeric(value)
            if num is None:
                raise RiffRuntimeError(f"cannot negate {as_text(value)!r}", node.line)
            return -num
        if kind is N.Index:
            return self._index(self._eval(node.target, ctx), self._eval(node.key, ctx), node.line)
        if kind is N.Member:
            return self._member(self._eval(node.target, ctx), node.name, node.line)
        if kind is N.Call:
            return self._call(node, ctx)
        if kind is N.ListLit:
            return [self._eval(item, ctx) for item in node.items]
        raise RiffRuntimeError(f"cannot evaluate {kind.__name__}", node.line)

    def _eval_binary(self, node: N.Binary, ctx: "_Ctx"):
        op = node.op
        left = self._eval(node.left, ctx)
        right = self._eval(node.right, ctx)

        if op in ("==", "!=", "<", "<=", ">", ">="):
            return compare(op, left, right, node.line)
        if op == "~":
            return _compile(as_text(right)).search(as_text(left)) is not None
        if op == "!~":
            return _compile(as_text(right)).search(as_text(left)) is None
        if op == "startswith":
            return as_text(left).startswith(as_text(right))
        if op == "endswith":
            return as_text(left).endswith(as_text(right))
        if op == "contains":
            return self._contains(left, right)
        if op == "in":
            return self._contains(right, left)
        if op == "+":
            lnum, rnum = _numeric(left), _numeric(right)
            if isinstance(left, str) or isinstance(right, str) or lnum is None or rnum is None:
                if isinstance(left, list) and isinstance(right, list):
                    return left + right
                return as_text(left) + as_text(right)
            return lnum + rnum
        lnum, rnum = _numeric(left), _numeric(right)
        if lnum is None or rnum is None:
            raise RiffRuntimeError(f"cannot apply {op!r} to non-numeric values", node.line)
        if op == "-":
            return lnum - rnum
        if op == "*":
            return lnum * rnum
        if rnum == 0:
            raise RiffRuntimeError("division by zero", node.line)
        return lnum / rnum if op == "/" else lnum % rnum

    @staticmethod
    def _contains(haystack, needle) -> bool:
        if hasattr(haystack, "riff_contains"):
            return haystack.riff_contains(needle)
        haystack = _unwrap(haystack)
        if isinstance(haystack, (list, tuple)):
            return any(_equal(item, needle) for item in haystack)
        if isinstance(haystack, dict):
            return as_text(needle) in haystack
        return as_text(needle) in as_text(haystack)

    @staticmethod
    def _index(target, key, line: int):
        if hasattr(target, "riff_index"):
            return target.riff_index(key)
        target = _unwrap(target)
        if isinstance(target, dict):
            return target.get(as_text(key))
        if isinstance(target, (list, tuple, str)):
            index = _numeric(key)
            if index is None:
                return None
            index = int(index)
            return target[index] if -len(target) <= index < len(target) else None
        if target is None:
            return None
        raise RiffRuntimeError(f"cannot index a {type(target).__name__}", line)

    @staticmethod
    def _member(target, name: str, line: int):
        if hasattr(target, "riff_member"):
            return target.riff_member(name)
        target = _unwrap(target)
        if isinstance(target, dict):
            return target.get(name)
        if target is None:
            return None
        raise RiffRuntimeError(f"cannot read .{name} from a {type(target).__name__}", line)

    def _call(self, node: N.Call, ctx: "_Ctx"):
        func = BUILTINS.get(node.func)
        if func is None:
            raise RiffRuntimeError(
                f"unknown function {node.func}() (available: {', '.join(sorted(BUILTINS))})", node.line
            )
        args = [self._eval(a, ctx) for a in node.args]
        try:
            return func(*args)
        except RiffRuntimeError:
            raise
        except TypeError as exc:
            raise RiffRuntimeError(f"bad arguments to {node.func}(): {exc}", node.line) from None
        except Exception as exc:
            raise RiffRuntimeError(f"{node.func}() failed: {exc}", node.line) from None


def _host_matches(pattern: str, host: str) -> bool:
    pattern = pattern.strip()
    if pattern.startswith("re:"):
        return _compile(pattern[3:]).search(host) is not None
    pattern = pattern.lower()
    if pattern == host:
        return True
    if any(ch in pattern for ch in "*?["):
        return fnmatch.fnmatch(host, pattern)
    # A bare domain also covers its subdomains, which is what people expect.
    return host.endswith("." + pattern)


# --------------------------------------------------------------- evaluation ctx


@dataclass(slots=True)
class _Ctx:
    engine: Engine
    flow: Any
    phase: str
    verdict: Verdict
    locals: dict[str, Any] = field(default_factory=dict)

    @property
    def request(self):
        return self.flow.request

    @property
    def response(self):
        return self.flow.response

    def target(self):
        """The message that bare `header` / `body` refer to in this phase."""
        if self.phase == "response" and self.flow.response is not None:
            return self.flow.response
        return self.flow.request

    def lookup(self, name: str, line: int):
        if name in self.locals:
            return self.locals[name]
        if name in self.engine.globals:
            return self.engine.globals[name]
        if self.flow is None:
            raise RiffRuntimeError(f"{name!r} is not available in a top-level directive", line)
        getter = _NAMES.get(name)
        if getter is None:
            raise RiffRuntimeError(f"unknown name {name!r}", line)
        return getter(self)


def _cookies(headers, is_response: bool) -> dict[str, str]:
    out: dict[str, str] = {}
    if is_response:
        for raw in headers.get_all("set-cookie"):
            first = raw.split(";", 1)[0]
            key, sep, value = first.partition("=")
            if sep:
                out[key.strip()] = value.strip()
        return out
    for raw in headers.get_all("cookie"):
        for chunk in raw.split(";"):
            key, sep, value = chunk.partition("=")
            if sep:
                out[key.strip()] = value.strip()
    return out


def _req_view(flow) -> MsgView:
    r = flow.request
    return MsgView(
        {
            "method": lambda: r.method,
            "url": lambda: r.url,
            "host": lambda: r.host,
            "port": lambda: r.port,
            "scheme": lambda: r.scheme,
            "path": lambda: r.path,
            "query": lambda: QueryView(r.query),
            "header": lambda: HeaderView(r.headers),
            "headers": lambda: HeaderView(r.headers),
            "cookie": lambda: DictView(_cookies(r.headers, False)),
            "body": lambda: r.text(),
            "json": lambda: _json_load(r.text()),
            "size": lambda: len(r.body),
            "version": lambda: r.version,
        }
    )


def _resp_view(flow) -> MsgView:
    if flow.response is None:
        return MsgView({})
    r = flow.response
    return MsgView(
        {
            "status": lambda: r.status,
            "reason": lambda: r.reason,
            "header": lambda: HeaderView(r.headers),
            "headers": lambda: HeaderView(r.headers),
            "cookie": lambda: DictView(_cookies(r.headers, True)),
            "body": lambda: r.text(),
            "json": lambda: _json_load(r.text()),
            "size": lambda: len(r.body),
            "version": lambda: r.version,
        }
    )


# Bare names available inside rules. Request-side names stay visible in the
# response phase because a response has no host/path of its own.
_NAMES: dict[str, Callable[[_Ctx], Any]] = {
    "method": lambda c: c.request.method,
    "url": lambda c: c.request.url,
    "host": lambda c: c.request.host,
    "port": lambda c: c.request.port,
    "scheme": lambda c: c.request.scheme,
    "path": lambda c: c.request.path,
    "query": lambda c: QueryView(c.request.query),
    "version": lambda c: c.target().version,
    "header": lambda c: HeaderView(c.target().headers),
    "headers": lambda c: HeaderView(c.target().headers),
    "cookie": lambda c: DictView(_cookies(c.target().headers, c.phase == "response")),
    "body": lambda c: c.target().text(),
    "size": lambda c: len(c.target().body),
    "status": lambda c: c.response.status if c.response else 0,
    "reason": lambda c: c.response.reason if c.response else "",
    "content_type": lambda c: c.flow.content_type,
    "tags": lambda c: c.flow.tags,
    "id": lambda c: c.flow.id,
    "client": lambda c: c.flow.client,
    "tls": lambda c: c.flow.tls,
    "duration": lambda c: round(c.flow.duration_ms, 2),
    "req": lambda c: _req_view(c.flow),
    "resp": lambda c: _resp_view(c.flow),
    "phase": lambda c: c.phase,
}


# --------------------------------------------------------------- statements


def _to_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":")).encode("utf-8")
    return as_text(_unwrap(value)).encode("utf-8")


def _set_body(msg, data: bytes, ctx: _Ctx, line: int) -> None:
    if msg.body_streamed:
        ctx.verdict.messages.append("set body ignored: this body was streamed, not buffered")
        return
    msg.body = data
    msg.content_encoding = ""
    msg.headers.remove("content-encoding")
    msg.headers.remove("transfer-encoding")
    msg.headers.set("Content-Length", str(len(data)))


def _st_setmap(engine: Engine, stmt: N.SetMap, ctx: _Ctx) -> None:
    name = as_text(engine._eval(stmt.name, ctx))
    value = as_text(engine._eval(stmt.value, ctx))
    msg = ctx.target()
    if stmt.kind == "header":
        msg.headers.add(name, value) if stmt.append else msg.headers.set(name, value)
        if name.lower() == "host" and ctx.phase == "request":
            ctx.request.host = value.split(":")[0]
        return
    if stmt.kind == "query":
        if ctx.phase != "request":
            raise RiffRuntimeError("query can only be changed in an 'on request' rule", stmt.line)
        ctx.request.query.set(name, value)
        return
    # cookie
    if ctx.phase == "response":
        msg.headers.add("Set-Cookie", f"{name}={value}")
        return
    jar = _cookies(msg.headers, False)
    jar[name] = value
    msg.headers.set("Cookie", "; ".join(f"{k}={v}" for k, v in jar.items()))


def _st_removemap(engine: Engine, stmt: N.RemoveMap, ctx: _Ctx) -> None:
    name = as_text(engine._eval(stmt.name, ctx))
    msg = ctx.target()
    if stmt.kind == "header":
        msg.headers.remove(name)
        return
    if stmt.kind == "query":
        if ctx.phase != "request":
            raise RiffRuntimeError("query can only be changed in an 'on request' rule", stmt.line)
        ctx.request.query.remove(name)
        return
    if ctx.phase == "response":
        kept = [c for c in msg.headers.get_all("set-cookie") if not c.split("=", 1)[0].strip() == name]
        msg.headers.remove("set-cookie")
        for cookie in kept:
            msg.headers.add("Set-Cookie", cookie)
        return
    jar = _cookies(msg.headers, False)
    jar.pop(name, None)
    if jar:
        msg.headers.set("Cookie", "; ".join(f"{k}={v}" for k, v in jar.items()))
    else:
        msg.headers.remove("Cookie")


def _st_setfield(engine: Engine, stmt: N.SetField, ctx: _Ctx) -> None:
    value = engine._eval(stmt.value, ctx)
    name = stmt.field_name
    request = ctx.request

    if name == "body":
        _set_body(ctx.target(), _to_bytes(value), ctx, stmt.line)
        return
    if name == "status":
        if ctx.response is None:
            raise RiffRuntimeError("status can only be changed in an 'on response' rule", stmt.line)
        code = _numeric(value)
        if code is None:
            raise RiffRuntimeError(f"status must be a number, got {as_text(value)!r}", stmt.line)
        ctx.response.status = int(code)
        ctx.response.reason = ""
        return
    if name == "reason":
        if ctx.response is None:
            raise RiffRuntimeError("reason can only be changed in an 'on response' rule", stmt.line)
        ctx.response.reason = as_text(value)
        return
    if ctx.phase != "request":
        raise RiffRuntimeError(f"{name} can only be changed in an 'on request' rule", stmt.line)
    if name == "method":
        request.method = as_text(value).upper()
    elif name == "path":
        text = as_text(value)
        path, _, query = text.partition("?")
        request.path = path or "/"
        if query:
            from ..http import Query

            request.query = Query.parse(query)
    elif name == "url":
        request.set_url(as_text(value))
        if request.headers.get("host"):
            request.headers.set("Host", request.authority)
    elif name == "host":
        text = as_text(value)
        host, _, port = text.partition(":")
        request.host = host
        if port.isdigit():
            request.port = int(port)
        request.headers.set("Host", request.authority)
    elif name == "port":
        port = _numeric(value)
        if port is None:
            raise RiffRuntimeError("port must be a number", stmt.line)
        request.port = int(port)
        request.headers.set("Host", request.authority)
    elif name == "scheme":
        text = as_text(value).lower()
        if text not in ("http", "https"):
            raise RiffRuntimeError("scheme must be 'http' or 'https'", stmt.line)
        request.scheme = text
    else:  # pragma: no cover - parser restricts the field set
        raise RiffRuntimeError(f"cannot set {name!r}", stmt.line)


def _st_setvar(engine: Engine, stmt: N.SetVar, ctx: _Ctx) -> None:
    ctx.locals[stmt.name] = engine._eval(stmt.value, ctx)


def _st_if(engine: Engine, stmt: N.If, ctx: _Ctx) -> None:
    if truthy(engine._eval(stmt.cond, ctx)):
        engine._exec_block(stmt.then, ctx)
    elif stmt.orelse:
        engine._exec_block(stmt.orelse, ctx)


def _st_log(engine: Engine, stmt: N.Log, ctx: _Ctx) -> None:
    text = as_text(engine._eval(stmt.value, ctx))
    if stmt.level == "warn":
        text = "! " + text
    ctx.flow.logs.append(text)
    engine.on_log(ctx.flow, text)


def _st_respond(engine: Engine, stmt: N.Respond, ctx: _Ctx) -> None:
    from ..flow import Response
    from ..http import Headers, reason_for

    code = _numeric(engine._eval(stmt.status, ctx))
    if code is None:
        raise RiffRuntimeError("respond needs a numeric status", stmt.line)
    code = int(code)
    body = _to_bytes(engine._eval(stmt.body, ctx)) if stmt.body is not None else b""

    content_type = {
        "json": "application/json",
        "text": "text/plain; charset=utf-8",
        "html": "text/html; charset=utf-8",
    }.get(stmt.as_kind, "")
    if not content_type and body:
        stripped = body.lstrip()[:1]
        content_type = "application/json" if stripped in (b"{", b"[") else "text/plain; charset=utf-8"

    headers = Headers()
    if content_type:
        headers.set("Content-Type", content_type)
    headers.set("Content-Length", str(len(body)))
    headers.set("X-Riff", "synthetic")

    ctx.flow.response = Response(
        version=ctx.request.version if ctx.request.version.startswith("HTTP/1") else "HTTP/1.1",
        status=code,
        reason=reason_for(code),
        headers=headers,
        body=body,
    )
    ctx.flow.intercepted = True
    ctx.verdict.intercepted = True
    raise _StopRules


def _st_abort(engine: Engine, stmt: N.Abort, ctx: _Ctx) -> None:
    ctx.verdict.abort = True
    ctx.flow.aborted = True
    raise _StopRules


def _st_stop(engine: Engine, stmt: N.Stop, ctx: _Ctx) -> None:
    raise _StopRules


def _st_delay(engine: Engine, stmt: N.Delay, ctx: _Ctx) -> None:
    amount = _numeric(engine._eval(stmt.value, ctx))
    if amount is None or amount < 0:
        raise RiffRuntimeError("delay needs a non-negative number of milliseconds", stmt.line)
    ctx.verdict.delay_ms += float(amount)


def _st_save(engine: Engine, stmt: N.Save, ctx: _Ctx) -> None:
    directory = as_text(engine._eval(stmt.value, ctx))
    if directory and directory not in ctx.verdict.save_dirs:
        ctx.verdict.save_dirs.append(directory)


def _st_tag(engine: Engine, stmt: N.Tag, ctx: _Ctx) -> None:
    ctx.flow.tag(as_text(engine._eval(stmt.value, ctx)))


def _st_count(engine: Engine, stmt: N.Count, ctx: _Ctx) -> None:
    key = as_text(engine._eval(stmt.value, ctx))
    engine.counters[key] = engine.counters.get(key, 0) + 1


def _st_redact(engine: Engine, stmt: N.Redact, ctx: _Ctx) -> None:
    name = as_text(engine._eval(stmt.name, ctx))
    msg = ctx.target()
    if stmt.kind == "header":
        if msg.headers.get(name) is not None:
            msg.headers.set(name, REDACTED)
        return
    if stmt.kind == "query":
        if ctx.phase == "request" and ctx.request.query.get(name) is not None:
            ctx.request.query.set(name, REDACTED)
        return
    if stmt.kind == "cookie":
        _st_setmap(
            engine,
            N.SetMap(kind="cookie", name=N.Literal(value=name), value=N.Literal(value=REDACTED), line=stmt.line),
            ctx,
        )
        return
    # body: mask the value of `name` in JSON objects and form-encoded payloads
    if msg.body_streamed or not msg.body:
        return
    text = msg.text()
    escaped = re.escape(name)
    text = re.sub(rf'("{escaped}"\s*:\s*)"(?:\\.|[^"\\])*"', rf'\1"{REDACTED}"', text)
    text = re.sub(rf'("{escaped}"\s*:\s*)(-?\d+(?:\.\d+)?|true|false|null)', rf'\1"{REDACTED}"', text)
    text = re.sub(rf"(^|&)({escaped}=)[^&]*", rf"\1\g<2>{REDACTED}", text)
    _set_body(msg, text.encode("utf-8"), ctx, stmt.line)


_STATEMENTS: dict[type, Callable[[Engine, Any, _Ctx], None]] = {
    N.SetMap: _st_setmap,
    N.RemoveMap: _st_removemap,
    N.SetField: _st_setfield,
    N.SetVar: _st_setvar,
    N.If: _st_if,
    N.Log: _st_log,
    N.Respond: _st_respond,
    N.Abort: _st_abort,
    N.Stop: _st_stop,
    N.Delay: _st_delay,
    N.Save: _st_save,
    N.Tag: _st_tag,
    N.Count: _st_count,
    N.Redact: _st_redact,
}

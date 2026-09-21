"""AST node definitions for the riff rule language."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Node:
    line: int = field(default=0, kw_only=True)


# ---------------------------------------------------------------- expressions


@dataclass(slots=True)
class Literal(Node):
    value: Any = None


@dataclass(slots=True)
class ListLit(Node):
    items: list[Node] = field(default_factory=list)


@dataclass(slots=True)
class Name(Node):
    ident: str = ""


@dataclass(slots=True)
class Index(Node):
    target: Node = None
    key: Node = None


@dataclass(slots=True)
class Member(Node):
    target: Node = None
    name: str = ""


@dataclass(slots=True)
class Call(Node):
    func: str = ""
    args: list[Node] = field(default_factory=list)


@dataclass(slots=True)
class Unary(Node):
    op: str = ""
    operand: Node = None


@dataclass(slots=True)
class Binary(Node):
    op: str = ""
    left: Node = None
    right: Node = None


@dataclass(slots=True)
class Logical(Node):
    op: str = ""  # and | or
    left: Node = None
    right: Node = None


# ----------------------------------------------------------------- statements


@dataclass(slots=True)
class If(Node):
    cond: Node = None
    then: list[Node] = field(default_factory=list)
    orelse: list[Node] = field(default_factory=list)


@dataclass(slots=True)
class SetMap(Node):
    """set/add header|query|cookie "name" = value"""

    kind: str = "header"
    name: Node = None
    value: Node = None
    append: bool = False


@dataclass(slots=True)
class RemoveMap(Node):
    kind: str = "header"
    name: Node = None


@dataclass(slots=True)
class SetField(Node):
    """set body|status|method|path|url|host|reason = value"""

    field_name: str = ""
    value: Node = None


@dataclass(slots=True)
class SetVar(Node):
    name: str = ""
    value: Node = None


@dataclass(slots=True)
class Log(Node):
    value: Node = None
    level: str = "info"


@dataclass(slots=True)
class Respond(Node):
    status: Node = None
    body: Node = None
    as_kind: str = ""  # json | text | html | ""


@dataclass(slots=True)
class Abort(Node):
    pass


@dataclass(slots=True)
class Stop(Node):
    pass


@dataclass(slots=True)
class Delay(Node):
    value: Node = None


@dataclass(slots=True)
class Save(Node):
    value: Node = None


@dataclass(slots=True)
class Tag(Node):
    value: Node = None


@dataclass(slots=True)
class Count(Node):
    value: Node = None


@dataclass(slots=True)
class Redact(Node):
    """redact header "authorization"  /  redact body "password" """

    kind: str = "header"
    name: Node = None


# ------------------------------------------------------------ top-level forms


@dataclass(slots=True)
class TlsDirective(Node):
    mode: str = "decrypt"  # decrypt | passthru
    pattern: Node = None


@dataclass(slots=True)
class CaptureDirective(Node):
    """Which hosts get recorded. Traffic still flows either way."""

    mode: str = "capture"  # capture | ignore
    pattern: Node = None


@dataclass(slots=True)
class Rule(Node):
    phase: str = "request"  # request | response
    cond: Node | None = None
    body: list[Node] = field(default_factory=list)


@dataclass(slots=True)
class Program(Node):
    directives: list[Node] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)

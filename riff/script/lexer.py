"""Tokeniser for the riff rule language.

Newlines are significant: they terminate statements. A newline inside brackets,
or one preceded by a backslash, is swallowed so expressions can wrap.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import RiffSyntaxError

# Longest first so that ">=" wins over ">".
OPERATORS = (
    "==", "!=", "<=", ">=", "!~", "&&", "||",
    "=", "<", ">", "~", "+", "-", "*", "/", "%", "!",
)

PUNCTUATION = "{}()[],.;:"

# Suffixes turn a bare number into milliseconds (durations) or bytes (sizes).
UNITS = {
    "ms": 1, "s": 1000, "sec": 1000, "m": 60_000, "min": 60_000,
    "b": 1, "kb": 1024, "mb": 1024 * 1024, "gb": 1024 * 1024 * 1024,
}

ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "0": "\0",
    '"': '"', "'": "'", "\\": "\\", "/": "/",
}


@dataclass(frozen=True, slots=True)
class Token:
    kind: str  # num | str | name | op | punct | nl | eof
    value: object
    line: int
    col: int

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Token({self.kind}, {self.value!r}, {self.line}:{self.col})"


class Lexer:
    def __init__(self, source: str, path: str = ""):
        self.src = source
        self.path = path
        self.i = 0
        self.line = 1
        self.col = 1
        self.depth = 0  # bracket nesting; newlines inside brackets are ignored
        self.tokens: list[Token] = []

    # -- character helpers -------------------------------------------------

    def _peek(self, offset: int = 0) -> str:
        j = self.i + offset
        return self.src[j] if j < len(self.src) else ""

    def _advance(self, count: int = 1) -> str:
        chunk = self.src[self.i : self.i + count]
        for ch in chunk:
            if ch == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1
        self.i += count
        return chunk

    def _fail(self, message: str, line: int | None = None, col: int | None = None):
        raise RiffSyntaxError(message, line or self.line, col or self.col, self.src, self.path)

    def _emit(self, kind: str, value: object, line: int, col: int) -> None:
        self.tokens.append(Token(kind, value, line, col))

    # -- main loop ---------------------------------------------------------

    def tokenize(self) -> list[Token]:
        while self.i < len(self.src):
            ch = self._peek()

            if ch == "\\" and self._peek(1) in ("\n", "\r"):
                self._advance(1)
                if self._peek() == "\r":
                    self._advance(1)
                self._advance(1)
                continue

            if ch in " \t\r":
                self._advance(1)
                continue

            if ch == "\n":
                line, col = self.line, self.col
                self._advance(1)
                if self.depth == 0 and self.tokens and self.tokens[-1].kind != "nl":
                    self._emit("nl", "\n", line, col)
                continue

            if ch == "#" or (ch == "/" and self._peek(1) == "/"):
                while self.i < len(self.src) and self._peek() != "\n":
                    self._advance(1)
                continue

            if ch == "/" and self._peek(1) == "*":
                start_line, start_col = self.line, self.col
                self._advance(2)
                while self.i < len(self.src) and not (self._peek() == "*" and self._peek(1) == "/"):
                    self._advance(1)
                if self.i >= len(self.src):
                    self._fail("unterminated block comment", start_line, start_col)
                self._advance(2)
                continue

            if ch in "\"'":
                self._read_string(raw=False)
                continue

            if ch in "rR" and self._peek(1) in "\"'":
                self._advance(1)
                self._read_string(raw=True)
                continue

            if ch.isdigit() or (ch == "." and self._peek(1).isdigit()):
                self._read_number()
                continue

            if ch.isalpha() or ch == "_":
                self._read_name()
                continue

            if ch in PUNCTUATION:
                line, col = self.line, self.col
                # Braces delimit rule bodies, whose statements need their
                # newline terminators, so only ( and [ suppress newlines.
                if ch in "([":
                    self.depth += 1
                elif ch in ")]":
                    self.depth = max(0, self.depth - 1)
                self._advance(1)
                self._emit("punct", ch, line, col)
                continue

            for op in OPERATORS:
                if self.src.startswith(op, self.i):
                    line, col = self.line, self.col
                    self._advance(len(op))
                    self._emit("op", {"&&": "and", "||": "or"}.get(op, op), line, col)
                    break
            else:
                self._fail(f"unexpected character {ch!r}")

        if self.tokens and self.tokens[-1].kind != "nl":
            self._emit("nl", "\n", self.line, self.col)
        self._emit("eof", None, self.line, self.col)
        return self.tokens

    # -- token readers -----------------------------------------------------

    def _read_string(self, raw: bool) -> None:
        line, col = self.line, self.col
        quote = self._advance(1)
        parts: list[str] = []
        while True:
            if self.i >= len(self.src) or self._peek() == "\n":
                self._fail("unterminated string literal", line, col)
            ch = self._peek()
            if ch == quote:
                self._advance(1)
                break
            if ch == "\\" and not raw:
                self._advance(1)
                esc = self._peek()
                if esc == "x":
                    self._advance(1)
                    hexits = self.src[self.i : self.i + 2]
                    if len(hexits) < 2 or any(c not in "0123456789abcdefABCDEF" for c in hexits):
                        self._fail("\\x escape needs two hex digits")
                    self._advance(2)
                    parts.append(chr(int(hexits, 16)))
                elif esc in ESCAPES:
                    self._advance(1)
                    parts.append(ESCAPES[esc])
                else:
                    # Anything else keeps its backslash, so "\d+" and "\s" work
                    # in ordinary strings without reaching for r"...".
                    self._advance(1)
                    parts.append("\\" + esc)
                continue
            if ch == "\\" and raw:
                # Raw strings keep the backslash but still allow \" to close-escape.
                self._advance(1)
                nxt = self._peek()
                if nxt == quote:
                    self._advance(1)
                    parts.append(quote)
                else:
                    parts.append("\\")
                continue
            parts.append(self._advance(1))
        self._emit("str", "".join(parts), line, col)

    def _read_number(self) -> None:
        line, col = self.line, self.col
        start = self.i
        while self._peek().isdigit() or self._peek() == "_":
            self._advance(1)
        is_float = False
        if self._peek() == "." and self._peek(1).isdigit():
            is_float = True
            self._advance(1)
            while self._peek().isdigit():
                self._advance(1)
        text = self.src[start : self.i].replace("_", "")
        value: float | int = float(text) if is_float else int(text)

        unit_start = self.i
        while self._peek().isalpha():
            self._advance(1)
        unit = self.src[unit_start : self.i].lower()
        if unit:
            if unit not in UNITS:
                self._fail(f"unknown numeric unit {unit!r}", line, col)
            value = value * UNITS[unit]
            if not is_float:
                value = int(value)
        self._emit("num", value, line, col)

    def _read_name(self) -> None:
        line, col = self.line, self.col
        start = self.i
        while self._peek().isalnum() or self._peek() == "_":
            self._advance(1)
        self._emit("name", self.src[start : self.i], line, col)


def tokenize(source: str, path: str = "") -> list[Token]:
    return Lexer(source, path).tokenize()

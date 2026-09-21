"""Error types shared by the lexer, parser and interpreter."""

from __future__ import annotations


class RiffError(Exception):
    """Base class for every error raised by the riff script engine."""


class RiffSyntaxError(RiffError):
    """Raised while lexing or parsing a .riff script."""

    def __init__(self, message: str, line: int, col: int, source: str = "", path: str = ""):
        self.message = message
        self.line = line
        self.col = col
        self.source = source
        self.path = path
        super().__init__(self.render())

    def render(self) -> str:
        where = f"{self.path}:{self.line}:{self.col}" if self.path else f"line {self.line}, col {self.col}"
        out = [f"{where}: {self.message}"]
        lines = self.source.splitlines()
        if 0 < self.line <= len(lines):
            text = lines[self.line - 1]
            gutter = f"{self.line:>4} | "
            out.append(gutter + text)
            out.append(" " * len(gutter) + " " * max(self.col - 1, 0) + "^")
        return "\n".join(out)


class RiffRuntimeError(RiffError):
    """Raised while evaluating a rule against a live flow."""

    def __init__(self, message: str, line: int = 0):
        self.message = message
        self.line = line
        super().__init__(f"line {line}: {message}" if line else message)

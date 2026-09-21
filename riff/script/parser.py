"""Recursive-descent parser for the riff rule language.

    decrypt "*.example.com"
    passthru "*.bank.com"

    on request where host ~ r"api\\." and method == "POST" {
        set header "X-Debug" = "1"
        if body contains "password" { redact body "password" }
        log method + " " + url
    }

    on response where status >= 500 {
        tag "server-error"
        save "C:/tmp/riff-errors"
    }
"""

from __future__ import annotations

from . import nodes as N
from .errors import RiffSyntaxError
from .lexer import Token, tokenize

MAP_KINDS = ("header", "query", "cookie")
FIELDS = ("body", "status", "method", "path", "url", "host", "reason", "port", "scheme")

COMPARISONS = ("==", "!=", "<", "<=", ">", ">=", "~", "!~")
WORD_COMPARISONS = ("contains", "in", "matches")


class Parser:
    def __init__(self, tokens: list[Token], source: str = "", path: str = ""):
        self.toks = tokens
        self.pos = 0
        self.src = source
        self.path = path

    # -- token helpers -----------------------------------------------------

    @property
    def cur(self) -> Token:
        return self.toks[self.pos]

    def peek(self, offset: int = 1) -> Token:
        j = min(self.pos + offset, len(self.toks) - 1)
        return self.toks[j]

    def next(self) -> Token:
        tok = self.toks[self.pos]
        if tok.kind != "eof":
            self.pos += 1
        return tok

    def at_name(self, *words: str) -> bool:
        return self.cur.kind == "name" and self.cur.value in words

    def at_punct(self, *chars: str) -> bool:
        return self.cur.kind == "punct" and self.cur.value in chars

    def at_op(self, *ops: str) -> bool:
        return self.cur.kind == "op" and self.cur.value in ops

    def eat_name(self, *words: str) -> bool:
        if self.at_name(*words):
            self.next()
            return True
        return False

    def eat_punct(self, *chars: str) -> bool:
        if self.at_punct(*chars):
            self.next()
            return True
        return False

    def expect_punct(self, char: str) -> Token:
        if not self.at_punct(char):
            self.fail(f"expected {char!r}, found {self.describe(self.cur)}")
        return self.next()

    def expect_name(self, *words: str) -> str:
        if self.cur.kind != "name" or (words and self.cur.value not in words):
            wanted = " or ".join(repr(w) for w in words) if words else "a name"
            self.fail(f"expected {wanted}, found {self.describe(self.cur)}")
        return self.next().value

    def skip_newlines(self) -> None:
        while self.cur.kind == "nl" or self.at_punct(";"):
            self.next()

    def end_statement(self) -> None:
        if self.cur.kind in ("nl", "eof") or self.at_punct(";", "}"):
            if self.cur.kind == "nl" or self.at_punct(";"):
                self.next()
            return
        self.fail(f"unexpected {self.describe(self.cur)} at end of statement")

    @staticmethod
    def describe(tok: Token) -> str:
        if tok.kind == "eof":
            return "end of file"
        if tok.kind == "nl":
            return "end of line"
        return repr(tok.value)

    def fail(self, message: str, tok: Token | None = None):
        tok = tok or self.cur
        raise RiffSyntaxError(message, tok.line, tok.col, self.src, self.path)

    # -- program -----------------------------------------------------------

    def parse(self) -> N.Program:
        prog = N.Program()
        self.skip_newlines()
        while self.cur.kind != "eof":
            if self.at_name("decrypt", "passthru", "tunnel"):
                prog.directives.append(self.parse_tls_directive())
            elif self.at_name("capture", "ignore"):
                prog.directives.append(self.parse_capture_directive())
            elif self.at_name("let"):
                prog.directives.append(self.parse_let())
            elif self.at_name("on"):
                prog.rules.append(self.parse_rule())
            else:
                self.fail(
                    f"expected 'on', 'decrypt', 'passthru', 'capture', 'ignore' or 'let' "
                    f"at top level, "
                    f"found {self.describe(self.cur)}"
                )
            self.skip_newlines()
        return prog

    def parse_tls_directive(self) -> N.TlsDirective:
        tok = self.next()
        mode = "passthru" if tok.value in ("passthru", "tunnel") else "decrypt"
        pattern = self.expression()
        self.end_statement()
        return N.TlsDirective(mode=mode, pattern=pattern, line=tok.line)

    def parse_capture_directive(self) -> N.CaptureDirective:
        tok = self.next()
        pattern = self.expression()
        self.end_statement()
        return N.CaptureDirective(mode=tok.value, pattern=pattern, line=tok.line)

    def parse_let(self) -> N.SetVar:
        tok = self.next()
        name = self.expect_name()
        if not self.at_op("="):
            self.fail("expected '=' after 'let <name>'")
        self.next()
        value = self.expression()
        self.end_statement()
        return N.SetVar(name=name, value=value, line=tok.line)

    def parse_rule(self) -> N.Rule:
        tok = self.next()  # 'on'
        phase = self.expect_name("request", "response", "req", "resp")
        phase = "request" if phase.startswith("req") else "response"
        cond = None
        if self.eat_name("where", "if"):
            cond = self.expression()
        body = self.parse_block()
        return N.Rule(phase=phase, cond=cond, body=body, line=tok.line)

    def parse_block(self) -> list[N.Node]:
        self.expect_punct("{")
        stmts: list[N.Node] = []
        self.skip_newlines()
        while not self.at_punct("}"):
            if self.cur.kind == "eof":
                self.fail("unexpected end of file, missing '}'")
            stmts.append(self.statement())
            self.skip_newlines()
        self.expect_punct("}")
        return stmts

    # -- statements --------------------------------------------------------

    def statement(self) -> N.Node:
        tok = self.cur
        if tok.kind != "name":
            self.fail(f"expected a statement keyword, found {self.describe(tok)}")

        word = tok.value
        handler = getattr(self, f"_stmt_{word}", None)
        if handler is None:
            self.fail(
                f"unknown statement {word!r} (expected set, add, remove, redact, if, log, "
                f"respond, abort, stop, delay, save, tag, count or let)"
            )
        node = handler()
        if not isinstance(node, N.If):  # blocks swallow their own terminator
            self.end_statement()
        return node

    def _stmt_if(self) -> N.If:
        tok = self.next()
        cond = self.expression()
        then = self.parse_block()
        orelse: list[N.Node] = []
        # 'else' may sit on the next line
        save = self.pos
        self.skip_newlines()
        if self.at_name("else"):
            self.next()
            orelse = [self._stmt_if()] if self.at_name("if") else self.parse_block()
        else:
            self.pos = save
        return N.If(cond=cond, then=then, orelse=orelse, line=tok.line)

    def _stmt_let(self) -> N.SetVar:
        tok = self.next()
        name = self.expect_name()
        if not self.at_op("="):
            self.fail("expected '=' after 'let <name>'")
        self.next()
        return N.SetVar(name=name, value=self.expression(), line=tok.line)

    def _stmt_set(self) -> N.Node:
        return self._assignment(append=False)

    def _stmt_add(self) -> N.Node:
        return self._assignment(append=True)

    def _assignment(self, append: bool) -> N.Node:
        tok = self.next()  # set | add
        word = self.expect_name()

        if word in MAP_KINDS:
            name = self._map_key()
            if not self.at_op("="):
                self.fail(f"expected '=' after {word} name")
            self.next()
            return N.SetMap(kind=word, name=name, value=self.expression(), append=append, line=tok.line)

        if append:
            self.fail(f"'add' only applies to {', '.join(MAP_KINDS)}, not {word!r}", tok)

        if word in FIELDS:
            if not self.at_op("="):
                self.fail(f"expected '=' after 'set {word}'")
            self.next()
            return N.SetField(field_name=word, value=self.expression(), line=tok.line)

        # `set myvar = ...` assigns a script variable.
        if not self.at_op("="):
            self.fail(f"unknown assignment target {word!r}")
        self.next()
        return N.SetVar(name=word, value=self.expression(), line=tok.line)

    def _stmt_rewrite(self) -> N.SetField:
        tok = self.next()
        word = self.expect_name(*FIELDS)
        if self.at_op("="):
            self.next()
        return N.SetField(field_name=word, value=self.expression(), line=tok.line)

    def _stmt_remove(self) -> N.RemoveMap:
        tok = self.next()
        kind = self.expect_name(*MAP_KINDS)
        return N.RemoveMap(kind=kind, name=self._map_key(), line=tok.line)

    def _stmt_redact(self) -> N.Redact:
        tok = self.next()
        kind = self.expect_name(*MAP_KINDS, "body")
        return N.Redact(kind=kind, name=self._map_key(), line=tok.line)

    def _map_key(self) -> N.Node:
        """Accepts both `header "X"` and `header["X"]`."""
        if self.eat_punct("["):
            key = self.expression()
            self.expect_punct("]")
            return key
        return self.expression()

    def _stmt_log(self) -> N.Log:
        tok = self.next()
        return N.Log(value=self.expression(), line=tok.line)

    def _stmt_warn(self) -> N.Log:
        tok = self.next()
        return N.Log(value=self.expression(), level="warn", line=tok.line)

    def _stmt_respond(self) -> N.Respond:
        tok = self.next()
        status = self.expression()
        body = None
        as_kind = ""
        if self.cur.kind not in ("nl", "eof") and not self.at_punct(";", "}") and not self.at_name("as"):
            body = self.expression()
        if self.eat_name("as"):
            as_kind = self.expect_name("json", "text", "html")
        return N.Respond(status=status, body=body, as_kind=as_kind, line=tok.line)

    def _stmt_abort(self) -> N.Abort:
        return N.Abort(line=self.next().line)

    def _stmt_stop(self) -> N.Stop:
        return N.Stop(line=self.next().line)

    def _stmt_delay(self) -> N.Delay:
        tok = self.next()
        return N.Delay(value=self.expression(), line=tok.line)

    def _stmt_save(self) -> N.Save:
        tok = self.next()
        return N.Save(value=self.expression(), line=tok.line)

    def _stmt_tag(self) -> N.Tag:
        tok = self.next()
        return N.Tag(value=self.expression(), line=tok.line)

    def _stmt_count(self) -> N.Count:
        tok = self.next()
        return N.Count(value=self.expression(), line=tok.line)

    # -- expressions -------------------------------------------------------

    def expression(self) -> N.Node:
        return self.or_expr()

    def or_expr(self) -> N.Node:
        left = self.and_expr()
        while self.at_name("or") or self.at_op("or"):
            tok = self.next()
            left = N.Logical(op="or", left=left, right=self.and_expr(), line=tok.line)
        return left

    def and_expr(self) -> N.Node:
        left = self.not_expr()
        while self.at_name("and") or self.at_op("and"):
            tok = self.next()
            left = N.Logical(op="and", left=left, right=self.not_expr(), line=tok.line)
        return left

    def not_expr(self) -> N.Node:
        if self.at_name("not") or self.at_op("!"):
            tok = self.next()
            return N.Unary(op="not", operand=self.not_expr(), line=tok.line)
        return self.comparison()

    def comparison(self) -> N.Node:
        left = self.additive()
        while True:
            op = None
            tok = self.cur
            if self.cur.kind == "op" and self.cur.value in COMPARISONS:
                op = self.next().value
            elif self.at_name(*WORD_COMPARISONS):
                word = self.next().value
                op = "~" if word == "matches" else word
            elif self.at_name("starts", "ends"):
                word = self.next().value
                self.expect_name("with")
                op = f"{word}with"
            elif self.at_name("not") and self.peek().kind == "name" and self.peek().value in ("in", "contains"):
                self.next()
                word = self.next().value
                right = self.additive()
                left = N.Unary(
                    op="not",
                    operand=N.Binary(op=word, left=left, right=right, line=tok.line),
                    line=tok.line,
                )
                continue
            if op is None:
                return left
            left = N.Binary(op=op, left=left, right=self.additive(), line=tok.line)

    def additive(self) -> N.Node:
        left = self.multiplicative()
        while self.at_op("+", "-"):
            tok = self.next()
            left = N.Binary(op=tok.value, left=left, right=self.multiplicative(), line=tok.line)
        return left

    def multiplicative(self) -> N.Node:
        left = self.unary()
        while self.at_op("*", "/", "%"):
            tok = self.next()
            left = N.Binary(op=tok.value, left=left, right=self.unary(), line=tok.line)
        return left

    def unary(self) -> N.Node:
        if self.at_op("-"):
            tok = self.next()
            return N.Unary(op="-", operand=self.unary(), line=tok.line)
        return self.postfix()

    def postfix(self) -> N.Node:
        node = self.primary()
        while True:
            if self.at_punct("["):
                tok = self.next()
                key = self.expression()
                self.expect_punct("]")
                node = N.Index(target=node, key=key, line=tok.line)
            elif self.at_punct(".") and self.peek().kind == "name":
                tok = self.next()
                node = N.Member(target=node, name=self.next().value, line=tok.line)
            else:
                return node

    def primary(self) -> N.Node:
        tok = self.cur
        if tok.kind == "num" or tok.kind == "str":
            self.next()
            return N.Literal(value=tok.value, line=tok.line)
        if tok.kind == "name":
            if tok.value in ("true", "false"):
                self.next()
                return N.Literal(value=tok.value == "true", line=tok.line)
            if tok.value in ("null", "none", "nil"):
                self.next()
                return N.Literal(value=None, line=tok.line)
            self.next()
            if self.at_punct("("):
                self.next()
                args: list[N.Node] = []
                if not self.at_punct(")"):
                    args.append(self.expression())
                    while self.eat_punct(","):
                        args.append(self.expression())
                self.expect_punct(")")
                return N.Call(func=tok.value, args=args, line=tok.line)
            return N.Name(ident=tok.value, line=tok.line)
        if self.at_punct("("):
            self.next()
            inner = self.expression()
            self.expect_punct(")")
            return inner
        if self.at_punct("["):
            self.next()
            items: list[N.Node] = []
            self.skip_newlines()
            if not self.at_punct("]"):
                items.append(self.expression())
                while self.eat_punct(","):
                    self.skip_newlines()
                    if self.at_punct("]"):
                        break
                    items.append(self.expression())
            self.expect_punct("]")
            return N.ListLit(items=items, line=tok.line)
        self.fail(f"expected a value, found {self.describe(tok)}")


def parse(source: str, path: str = "") -> N.Program:
    return Parser(tokenize(source, path), source, path).parse()

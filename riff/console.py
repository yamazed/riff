"""Terminal rendering of live traffic."""

from __future__ import annotations

import os
import sys
import threading

from .flow import Flow
from .proxy import Observer, Proxy

RESET = "\x1b[0m"
DIM = "\x1b[2m"
BOLD = "\x1b[1m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
MAGENTA = "\x1b[35m"
CYAN = "\x1b[36m"
GREY = "\x1b[90m"


def enable_ansi() -> bool:
    """Turn on virtual-terminal processing so ANSI codes work in cmd.exe."""
    if os.name != "nt":
        return sys.stdout.isatty()
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def human_size(count: int) -> str:
    if count < 1024:
        return f"{count} B"
    if count < 1024 * 1024:
        return f"{count / 1024:.1f} KB"
    return f"{count / (1024 * 1024):.1f} MB"


def human_ms(ms: float) -> str:
    if ms < 1000:
        return f"{ms:.0f} ms"
    return f"{ms / 1000:.2f} s"


class ConsoleObserver(Observer):
    """One line per flow, plus optional full dumps."""

    def __init__(self, colour: bool = True, dump: bool = False, quiet: bool = False, jsonl_path: str = ""):
        self.colour = colour
        self.dump = dump
        self.quiet = quiet
        self._lock = threading.Lock()
        self._jsonl = open(jsonl_path, "a", encoding="utf-8") if jsonl_path else None

    # -- helpers -----------------------------------------------------------

    def c(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.colour else text

    def _write(self, line: str) -> None:
        with self._lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def close(self) -> None:
        if self._jsonl is not None:
            self._jsonl.close()
            self._jsonl = None

    # -- observer ----------------------------------------------------------

    def on_start(self, proxy: Proxy) -> None:
        host, port = proxy.address
        rules = proxy.engine.rule_count
        self._write("")
        self._write(self.c("  riff", BOLD + CYAN) + self.c("  intercepting proxy", GREY))
        self._write(self.c(f"  listening   http://{host}:{port}", GREEN))
        self._write(self.c(f"  root CA     {proxy.ca.ca_cert_path}", GREY))
        self._write(self.c(f"  script      {proxy.engine.path or '<none>'} ({rules} rule(s))", GREY))
        self._write("")

    def on_flow(self, flow: Flow) -> None:
        if self._jsonl is not None:
            with self._lock:
                self._jsonl.write(flow.to_json() + "\n")
                self._jsonl.flush()
        if self.quiet:
            return

        marker = self.c("●", MAGENTA) if flow.intercepted else (self.c("🔒", GREY) if flow.tls else " ")
        ident = self.c(f"{flow.id:>4}", GREY)
        method = self.c(f"{flow.request.method:<6}", BOLD)

        if flow.aborted:
            status = self.c("ABORT", RED)
            size = duration = ""
        elif flow.response is None:
            status = self.c("  ---", RED)
            size = duration = ""
        else:
            code = flow.response.status
            colour = GREEN if code < 300 else (CYAN if code < 400 else (YELLOW if code < 500 else RED))
            status = self.c(f"{code:>5}", colour)
            size = self.c(f"{human_size(len(flow.response.body)):>9}", GREY)
            duration = self.c(f"{human_ms(flow.duration_ms):>8}", GREY)

        tags = self.c("  [" + " ".join(flow.tags) + "]", MAGENTA) if flow.tags else ""
        url = flow.request.url
        if len(url) > 88:
            url = url[:85] + "..."
        self._write(f" {marker} {ident} {status} {method} {url}{size and '  ' + size}{duration and '  ' + duration}{tags}")

        for message in flow.logs:
            self._write(self.c(f"        {message}", BLUE))
        if flow.error:
            self._write(self.c(f"        {flow.error}", RED))
        if self.dump:
            self._dump(flow)

    def _dump(self, flow: Flow) -> None:
        req = flow.request
        lines = [self.c(f"        {req.method} {req.origin_form} {req.version}", DIM)]
        for key, value in req.headers.items():
            lines.append(self.c(f"        {key}: {value}", GREY))
        if req.body:
            lines.append(self._preview(req.body))
        if flow.response is not None:
            resp = flow.response
            lines.append("")
            lines.append(self.c(f"        {resp.version} {resp.status} {resp.reason}", DIM))
            for key, value in resp.headers.items():
                lines.append(self.c(f"        {key}: {value}", GREY))
            if resp.body:
                lines.append(self._preview(resp.body))
        self._write("\n".join(lines) + "\n")

    def _preview(self, body: bytes, limit: int = 2000) -> str:
        text = body[:limit].decode("utf-8", "replace")
        suffix = self.c(f"\n        ... {len(body) - limit} more bytes", GREY) if len(body) > limit else ""
        indented = "\n".join("        " + line for line in text.splitlines())
        return "\n" + indented + suffix

    def on_log(self, flow: Flow | None, text: str) -> None:
        if not self.quiet:
            self._write(self.c(f"        {text}", BLUE))

    def on_tunnel(self, host: str, port: int, sent: int, received: int, seconds: float) -> None:
        if self.quiet:
            return
        self._write(
            f" {self.c('~', GREY)} {self.c('    ', GREY)} {self.c('TUNNEL', GREY)} "
            f"{host}:{port}  {self.c(f'↑{human_size(sent)} ↓{human_size(received)}', GREY)}"
        )

    def on_error(self, text: str) -> None:
        self._write(self.c(f" !      {text}", RED))


class MultiObserver(Observer):
    """Fan a single proxy's events out to several observers."""

    def __init__(self, *observers: Observer):
        self.observers = [o for o in observers if o is not None]

    def _each(self, name: str, *args) -> None:
        for observer in self.observers:
            try:
                getattr(observer, name)(*args)
            except Exception:  # nosec B112 # pragma: no cover - an observer must never break the proxy
                continue

    def on_start(self, proxy) -> None:
        self._each("on_start", proxy)

    def on_flow(self, flow) -> None:
        self._each("on_flow", flow)

    def on_log(self, flow, text) -> None:
        self._each("on_log", flow, text)

    def on_tunnel(self, host, port, sent, received, seconds) -> None:
        self._each("on_tunnel", host, port, sent, received, seconds)

    def on_error(self, text) -> None:
        self._each("on_error", text)

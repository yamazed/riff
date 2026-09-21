"""Minimal, strict-enough HTTP/1.x message reading, writing and body codecs.

Only HTTP/1.0 and HTTP/1.1 are handled. The proxy deliberately advertises
`http/1.1` over ALPN so clients never negotiate h2 through it.
"""

from __future__ import annotations

import gzip
import zlib
from dataclasses import dataclass, field
from typing import BinaryIO, Iterable

MAX_LINE = 65536
MAX_HEADERS = 200

# Headers that describe a single hop and must not be forwarded verbatim.
HOP_BY_HOP = frozenset(
    {
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

NO_BODY_STATUS = frozenset({204, 205, 304})


class HttpError(Exception):
    """A malformed or oversized HTTP message."""


class BodyTooLarge(HttpError):
    pass


# --------------------------------------------------------------------- headers


class Headers:
    """Ordered, case-insensitive multi-map of header fields."""

    __slots__ = ("_items",)

    def __init__(self, items: Iterable[tuple[str, str]] = ()):
        self._items: list[list[str]] = [[k, v] for k, v in items]

    def __iter__(self):
        return iter(tuple(pair) for pair in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        lowered = name.lower()
        return any(k.lower() == lowered for k, _ in self._items)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Headers({[tuple(p) for p in self._items]!r})"

    def items(self) -> list[tuple[str, str]]:
        return [(k, v) for k, v in self._items]

    def get(self, name: str, default: str | None = None) -> str | None:
        lowered = name.lower()
        for k, v in self._items:
            if k.lower() == lowered:
                return v
        return default

    def get_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [v for k, v in self._items if k.lower() == lowered]

    def set(self, name: str, value: str) -> None:
        lowered = name.lower()
        value = str(value)
        for pair in self._items:
            if pair[0].lower() == lowered:
                pair[1] = value
                break
        else:
            self._items.append([name, value])
            return
        # Drop any later duplicates so `set` really means "exactly one".
        seen = False
        kept: list[list[str]] = []
        for pair in self._items:
            if pair[0].lower() == lowered:
                if seen:
                    continue
                seen = True
            kept.append(pair)
        self._items = kept

    def add(self, name: str, value: str) -> None:
        self._items.append([name, str(value)])

    def remove(self, name: str) -> int:
        lowered = name.lower()
        before = len(self._items)
        self._items = [p for p in self._items if p[0].lower() != lowered]
        return before - len(self._items)

    def copy(self) -> "Headers":
        return Headers(self.items())

    def to_bytes(self) -> bytes:
        out = bytearray()
        for k, v in self._items:
            out += k.encode("latin-1", "replace")
            out += b": "
            out += v.encode("latin-1", "replace")
            out += b"\r\n"
        return bytes(out)

    def strip_hop_by_hop(self) -> None:
        """Remove hop-by-hop fields, including those named in `Connection`."""
        named = set()
        for value in self.get_all("connection") + self.get_all("proxy-connection"):
            for token in value.split(","):
                token = token.strip().lower()
                if token and token not in ("close", "keep-alive"):
                    named.add(token)
        for name in HOP_BY_HOP | named:
            self.remove(name)


# ---------------------------------------------------------------- line reading


def read_line(rfile: BinaryIO) -> bytes:
    line = rfile.readline(MAX_LINE + 1)
    if len(line) > MAX_LINE:
        raise HttpError("header line too long")
    return line


def read_headers(rfile: BinaryIO) -> Headers:
    headers = Headers()
    while True:
        line = read_line(rfile)
        if not line:
            raise HttpError("connection closed inside header block")
        if line in (b"\r\n", b"\n"):
            return headers
        if len(headers) >= MAX_HEADERS:
            raise HttpError("too many header fields")
        text = line.rstrip(b"\r\n").decode("latin-1")
        if text[:1] in (" ", "\t"):
            if not len(headers):
                raise HttpError("continuation line before any header")
            headers._items[-1][1] += " " + text.strip()
            continue
        name, sep, value = text.partition(":")
        if not sep or not name or name.strip() != name:
            raise HttpError(f"malformed header line: {text!r}")
        headers.add(name, value.strip())


@dataclass(slots=True)
class RequestHead:
    method: str
    target: str
    version: str
    headers: Headers


@dataclass(slots=True)
class ResponseHead:
    version: str
    status: int
    reason: str
    headers: Headers


def read_request_head(rfile: BinaryIO) -> RequestHead | None:
    """Returns None on a clean end of connection."""
    line = read_line(rfile)
    while line in (b"\r\n", b"\n"):  # tolerate stray CRLF between messages
        line = read_line(rfile)
    if not line:
        return None
    parts = line.rstrip(b"\r\n").decode("latin-1").split()
    if len(parts) != 3:
        raise HttpError(f"malformed request line: {line[:120]!r}")
    method, target, version = parts
    if not version.startswith("HTTP/"):
        raise HttpError(f"unsupported protocol in request line: {version!r}")
    return RequestHead(method.upper(), target, version, read_headers(rfile))


def read_response_head(rfile: BinaryIO) -> ResponseHead:
    line = read_line(rfile)
    if not line:
        raise HttpError("upstream closed before sending a response")
    parts = line.rstrip(b"\r\n").decode("latin-1").split(None, 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise HttpError(f"malformed status line: {line[:120]!r}")
    version = parts[0]
    try:
        status = int(parts[1])
    except ValueError:
        raise HttpError(f"non-numeric status code: {parts[1]!r}") from None
    reason = parts[2] if len(parts) > 2 else ""
    return ResponseHead(version, status, reason, read_headers(rfile))


# ------------------------------------------------------------------ body I/O


class BodyMode:
    NONE = "none"
    LENGTH = "length"
    CHUNKED = "chunked"
    UNTIL_CLOSE = "close"


def body_mode(headers: Headers, *, is_response: bool, method: str = "", status: int = 0) -> tuple[str, int]:
    """Decide how the body of a message is framed. Returns (mode, length)."""
    if is_response:
        if method == "HEAD" or status in NO_BODY_STATUS or 100 <= status < 200:
            return BodyMode.NONE, 0
    encoding = (headers.get("transfer-encoding") or "").lower()
    if "chunked" in encoding:
        return BodyMode.CHUNKED, -1
    raw_length = headers.get("content-length")
    if raw_length is not None:
        try:
            length = int(raw_length.split(",")[0].strip())
        except ValueError:
            raise HttpError(f"invalid Content-Length: {raw_length!r}") from None
        if length < 0:
            raise HttpError(f"negative Content-Length: {raw_length!r}")
        return BodyMode.LENGTH, length
    if is_response:
        return BodyMode.UNTIL_CLOSE, -1
    return BodyMode.NONE, 0


def _read_exact(rfile: BinaryIO, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = rfile.read(min(remaining, 65536))
        if not chunk:
            raise HttpError(f"connection closed with {remaining} body bytes outstanding")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_chunked(rfile: BinaryIO, hard_limit: int) -> bytes:
    out = bytearray()
    while True:
        line = read_line(rfile)
        if not line:
            raise HttpError("connection closed inside chunked body")
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            raise HttpError(f"invalid chunk size: {size_text!r}") from None
        if size == 0:
            while True:  # trailer section
                trailer = read_line(rfile)
                if not trailer or trailer in (b"\r\n", b"\n"):
                    break
            return bytes(out)
        if len(out) + size > hard_limit:
            raise BodyTooLarge(f"chunked body exceeded {hard_limit} bytes")
        out += _read_exact(rfile, size)
        if _read_exact(rfile, 2) not in (b"\r\n",):
            raise HttpError("missing CRLF after chunk")


def read_body(rfile: BinaryIO, mode: str, length: int, hard_limit: int) -> bytes:
    if mode == BodyMode.NONE:
        return b""
    if mode == BodyMode.LENGTH:
        if length > hard_limit:
            raise BodyTooLarge(f"Content-Length {length} exceeds {hard_limit}")
        return _read_exact(rfile, length)
    if mode == BodyMode.CHUNKED:
        return read_chunked(rfile, hard_limit)
    out = bytearray()
    while True:
        chunk = rfile.read(65536)
        if not chunk:
            return bytes(out)
        if len(out) + len(chunk) > hard_limit:
            raise BodyTooLarge(f"body exceeded {hard_limit} bytes")
        out += chunk


def read_body_capped(rfile: BinaryIO, mode: str, length: int, cap: int) -> tuple[bytes, bool]:
    """Read up to `cap` bytes of body.

    Returns (data, truncated). When truncated is True the reader is parked
    part-way through the body and the caller must drain the rest with
    `iter_remaining`, which re-frames whatever is left.
    """
    if mode == BodyMode.NONE:
        return b"", False
    if mode == BodyMode.LENGTH:
        if length <= cap:
            return _read_exact(rfile, length), False
        return _read_exact(rfile, cap), True

    out = bytearray()
    if mode == BodyMode.CHUNKED:
        while True:
            line = read_line(rfile)
            if not line:
                raise HttpError("connection closed inside chunked body")
            size_text = line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                raise HttpError(f"invalid chunk size: {size_text!r}") from None
            if size == 0:
                while True:
                    trailer = read_line(rfile)
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        break
                return bytes(out), False
            out += _read_exact(rfile, size)
            _read_exact(rfile, 2)
            if len(out) > cap:
                return bytes(out), True

    while True:  # until close
        chunk = rfile.read(65536)
        if not chunk:
            return bytes(out), False
        out += chunk
        if len(out) > cap:
            return bytes(out), True


def _read_some(rfile: BinaryIO, limit: int) -> bytes:
    """Whatever is available right now, up to `limit` bytes.

    `read(n)` on a buffered file blocks until n bytes or EOF, which would hold a
    live stream back; `read1` returns after one read of the underlying socket.
    """
    read1 = getattr(rfile, "read1", None)
    return read1(limit) if read1 is not None else rfile.read(limit)


def iter_remaining(rfile: BinaryIO, mode: str, length: int, consumed: int):
    """Yield the rest of a partially read body as plain data blocks, as they arrive."""
    if mode == BodyMode.NONE:
        return
    if mode == BodyMode.LENGTH:
        remaining = length - consumed
        while remaining > 0:
            chunk = _read_some(rfile, min(remaining, 65536))
            if not chunk:
                raise HttpError("connection closed mid-body")
            remaining -= len(chunk)
            yield chunk
        return
    if mode == BodyMode.CHUNKED:
        while True:
            line = read_line(rfile)
            if not line:
                raise HttpError("connection closed inside chunked body")
            size_text = line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                raise HttpError(f"invalid chunk size: {size_text!r}") from None
            if size == 0:
                while True:
                    trailer = read_line(rfile)
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        break
                return
            yield _read_exact(rfile, size)
            _read_exact(rfile, 2)
        return
    while True:  # until close
        chunk = _read_some(rfile, 65536)
        if not chunk:
            return
        yield chunk


def write_chunked(wfile: BinaryIO, blocks) -> int:
    total = 0
    for block in blocks:
        if not block:
            continue
        wfile.write(f"{len(block):x}\r\n".encode("ascii"))
        wfile.write(block)
        wfile.write(b"\r\n")
        wfile.flush()  # a live stream must not wait for the next block
        total += len(block)
    wfile.write(b"0\r\n\r\n")
    wfile.flush()
    return total


def discard_body(rfile: BinaryIO, mode: str, length: int) -> None:
    for _ in iter_remaining(rfile, mode, length, 0):
        pass


def stream_body(rfile: BinaryIO, wfile: BinaryIO, mode: str, length: int) -> int:
    """Copy a body through without buffering it. Returns bytes copied."""
    total = 0
    if mode == BodyMode.NONE:
        return 0
    if mode == BodyMode.LENGTH:
        remaining = length
        while remaining > 0:
            chunk = rfile.read(min(remaining, 65536))
            if not chunk:
                raise HttpError("connection closed mid-body while streaming")
            wfile.write(chunk)
            remaining -= len(chunk)
            total += len(chunk)
        wfile.flush()
        return total
    if mode == BodyMode.CHUNKED:
        while True:
            line = read_line(rfile)
            if not line:
                raise HttpError("connection closed inside chunked body")
            wfile.write(line)
            size_text = line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                raise HttpError(f"invalid chunk size: {size_text!r}") from None
            if size == 0:
                while True:
                    trailer = read_line(rfile)
                    wfile.write(trailer)
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        break
                wfile.flush()
                return total
            data = _read_exact(rfile, size)
            wfile.write(data)
            wfile.write(_read_exact(rfile, 2))
            total += size
    while True:  # until close
        chunk = rfile.read(65536)
        if not chunk:
            wfile.flush()
            return total
        wfile.write(chunk)
        total += len(chunk)


# ------------------------------------------------------------ content codecs


def _brotli():
    try:
        import brotli  # type: ignore

        return brotli
    except ImportError:
        return None


def _zstd():
    try:
        import zstandard  # type: ignore

        return zstandard
    except ImportError:
        return None


def decode_content(data: bytes, encoding: str) -> tuple[bytes, bool]:
    """Undo Content-Encoding. Returns (data, decoded_ok)."""
    encoding = (encoding or "").strip().lower()
    if not data or encoding in ("", "identity"):
        return data, True
    try:
        if encoding == "gzip" or encoding == "x-gzip":
            return gzip.decompress(data), True
        if encoding == "deflate":
            try:
                return zlib.decompress(data), True
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS), True
        if encoding == "br":
            mod = _brotli()
            return (mod.decompress(data), True) if mod else (data, False)
        if encoding == "zstd":
            mod = _zstd()
            return (mod.ZstdDecompressor().decompress(data), True) if mod else (data, False)
    except Exception:
        return data, False
    return data, False


def encode_content(data: bytes, encoding: str) -> tuple[bytes, bool]:
    encoding = (encoding or "").strip().lower()
    if not data or encoding in ("", "identity"):
        return data, True
    try:
        if encoding in ("gzip", "x-gzip"):
            return gzip.compress(data), True
        if encoding == "deflate":
            return zlib.compress(data), True
        if encoding == "br":
            mod = _brotli()
            return (mod.compress(data), True) if mod else (data, False)
        if encoding == "zstd":
            mod = _zstd()
            return (mod.ZstdCompressor().compress(data), True) if mod else (data, False)
    except Exception:
        return data, False
    return data, False


# ------------------------------------------------------------------- writing


def build_request(method: str, target: str, version: str, headers: Headers, body: bytes) -> bytes:
    head = f"{method} {target} {version}\r\n".encode("latin-1")
    return head + headers.to_bytes() + b"\r\n" + body


def build_response(version: str, status: int, reason: str, headers: Headers, body: bytes) -> bytes:
    head = f"{version} {status} {reason}".rstrip().encode("latin-1") + b"\r\n"
    return head + headers.to_bytes() + b"\r\n" + body


REASONS = {
    200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 304: "Not Modified", 307: "Temporary Redirect",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    405: "Method Not Allowed", 408: "Request Timeout", 409: "Conflict", 418: "I'm a teapot",
    429: "Too Many Requests", 451: "Unavailable For Legal Reasons",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
    504: "Gateway Timeout",
}


def reason_for(status: int) -> str:
    return REASONS.get(status, "OK" if 200 <= status < 300 else "Error")


def drain_buffer(rfile) -> bytes:
    """Pull whatever the buffered reader has already read off the socket."""
    try:
        pending = rfile.peek(0)
    except Exception:
        return b""
    return rfile.read(len(pending)) if pending else b""


@dataclass(slots=True)
class Query:
    """Order-preserving parse of a query string."""

    pairs: list[list[str]] = field(default_factory=list)

    @classmethod
    def parse(cls, raw: str) -> "Query":
        from urllib.parse import unquote_plus

        pairs: list[list[str]] = []
        for chunk in raw.split("&"):
            if not chunk:
                continue
            key, sep, value = chunk.partition("=")
            pairs.append([unquote_plus(key), unquote_plus(value) if sep else ""])
        return cls(pairs)

    def get(self, key: str, default=None):
        for k, v in self.pairs:
            if k == key:
                return v
        return default

    def set(self, key: str, value: str) -> None:
        for pair in self.pairs:
            if pair[0] == key:
                pair[1] = value
                return
        self.pairs.append([key, value])

    def remove(self, key: str) -> None:
        self.pairs = [p for p in self.pairs if p[0] != key]

    def as_dict(self) -> dict[str, str]:
        return {k: v for k, v in self.pairs}

    def encode(self) -> str:
        from urllib.parse import quote_plus

        return "&".join(f"{quote_plus(k)}={quote_plus(v)}" if v != "" else quote_plus(k) for k, v in self.pairs)

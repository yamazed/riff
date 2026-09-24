"""Claiming a TCP port, exclusively, with an error you can act on.

Windows and POSIX disagree about what `SO_REUSEADDR` means, and the difference
matters here. On POSIX it only lets you rebind a port still in `TIME_WAIT`,
which is what you want when restarting a server. On Windows it lets a *second
live listener* bind an address another socket is already listening on; the
kernel then hands new connections to one of them, arbitrarily.

For riff that failure is silent and very confusing: start a second riff while
one is already running and traffic lands on whichever instance the kernel
picked, so the UI you are watching shows nothing while capture "works". The fix
is `SO_EXCLUSIVEADDRUSE`, which is Windows' way of saying what `SO_REUSEADDR`
means everywhere else.

So: `SO_EXCLUSIVEADDRUSE` on Windows, `SO_REUSEADDR` elsewhere, and a clear
error instead of a silent steal.
"""

from __future__ import annotations

import errno
import socket
import sys
from http.server import ThreadingHTTPServer

IS_WINDOWS = sys.platform == "win32"

# WSAEADDRINUSE. Python usually maps it onto errno.EADDRINUSE, but not always.
_WSAEADDRINUSE = 10048


class AddressInUse(OSError):
    """The port is already taken, and we refuse to share it."""


def _in_use(exc: OSError) -> bool:
    return exc.errno in (errno.EADDRINUSE, errno.EACCES) or getattr(exc, "winerror", None) == _WSAEADDRINUSE


def _explain(host: str, port: int, what: str) -> str:
    return (
        f"{what} cannot start: {host}:{port} is already in use.\n"
        f"       Another riff is probably still running. Close it, or pick a free port."
    )


def set_exclusive(sock: socket.socket) -> None:
    """Ask the OS for sole ownership of whatever this socket binds next."""
    if IS_WINDOWS:
        # Mutually exclusive with SO_REUSEADDR; setting both is an error.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def bind_exclusive(sock: socket.socket, address: tuple[str, int], *, what: str = "riff") -> None:
    """Bind `sock`, failing loudly rather than sharing the port with another process."""
    set_exclusive(sock)
    try:
        sock.bind(address)
    except OSError as exc:
        if _in_use(exc):
            raise AddressInUse(_explain(address[0], address[1], what)) from None
        raise


class ExclusiveHTTPServer(ThreadingHTTPServer):
    """A ThreadingHTTPServer that will not quietly share its port.

    `http.server.HTTPServer` sets `allow_reuse_address = True`, which on Windows
    is the port-stealing behaviour described above.
    """

    allow_reuse_address = not IS_WINDOWS
    what = "riff"

    def server_bind(self) -> None:
        if IS_WINDOWS:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            super().server_bind()
        except OSError as exc:
            if _in_use(exc):
                host, port = self.server_address[:2]
                raise AddressInUse(_explain(str(host), int(port), self.what)) from None
            raise

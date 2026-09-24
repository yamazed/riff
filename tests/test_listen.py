"""Ports are claimed exclusively, so two riffs cannot silently share one.

On Windows, `SO_REUSEADDR` lets a second live listener bind a port that is
already being listened on, and the kernel then hands connections to an
arbitrary one. That produced a genuinely baffling failure: a second riff would
appear to start fine while its UI showed no traffic at all, because the first
instance was getting the connections.
"""

from __future__ import annotations

import socket

import pytest

from riff.ca import CertAuthority
from riff.listen import AddressInUse, ExclusiveHTTPServer, bind_exclusive
from riff.proxy import Options, Proxy
from riff.script import Engine
from riff.webui import UiOptions, UiServer


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_a_second_bind_on_the_same_port_is_refused():
    port = free_port()
    first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        bind_exclusive(first, ("127.0.0.1", port), what="the first")
        first.listen(1)

        second = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(AddressInUse) as info:
                bind_exclusive(second, ("127.0.0.1", port), what="the second")
            assert str(port) in str(info.value)
            assert "already in use" in str(info.value)
        finally:
            second.close()
    finally:
        first.close()


def test_the_error_says_what_to_do_about_it():
    port = free_port()
    held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        bind_exclusive(held, ("127.0.0.1", port))
        held.listen(1)
        other = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(AddressInUse) as info:
                bind_exclusive(other, ("127.0.0.1", port), what="the proxy")
            message = str(info.value)
            assert "the proxy cannot start" in message
            assert "Another riff" in message
            assert "free port" in message
        finally:
            other.close()
    finally:
        held.close()


def test_port_zero_still_gets_an_ephemeral_port():
    """Binding 0 must keep working — the tests rely on it everywhere."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        bind_exclusive(sock, ("127.0.0.1", 0))
        assert sock.getsockname()[1] != 0
    finally:
        sock.close()


def test_two_proxies_cannot_share_a_port(ca):
    """The real bug: the second proxy must fail, not quietly steal traffic."""
    port = free_port()
    engine = Engine.empty()
    first = Proxy(Options(listen_host="127.0.0.1", listen_port=port), engine=engine, ca=ca)
    first.bind()
    try:
        second = Proxy(Options(listen_host="127.0.0.1", listen_port=port), engine=engine, ca=ca)
        with pytest.raises(AddressInUse):
            second.bind()
    finally:
        first.shutdown()


def test_two_web_uis_cannot_share_a_port(ca, tmp_path):
    script = tmp_path / "rules.riff"
    script.write_text('on request { tag "seen" }\n', encoding="utf-8")
    engine = Engine.from_file(str(script))

    proxy = Proxy(Options(listen_host="127.0.0.1", listen_port=0), engine=engine, ca=ca)
    proxy.bind()
    from riff.hub import Hub

    hub = Hub()
    port = free_port()
    first = UiServer(UiOptions(host="127.0.0.1", port=port), proxy, hub, str(script))
    first.start()
    try:
        second = UiServer(UiOptions(host="127.0.0.1", port=port), proxy, hub, str(script))
        with pytest.raises(AddressInUse):
            second.start()
    finally:
        first.stop()
        proxy.shutdown()


def test_the_http_server_subclass_reports_which_server_clashed():
    port = free_port()
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        bind_exclusive(holder, ("127.0.0.1", port))
        holder.listen(1)

        from http.server import BaseHTTPRequestHandler

        server_cls = type("Named", (ExclusiveHTTPServer,), {"what": "the collaborator"})
        with pytest.raises(AddressInUse) as info:
            server_cls(("127.0.0.1", port), BaseHTTPRequestHandler)
        assert "the collaborator cannot start" in str(info.value)
    finally:
        holder.close()

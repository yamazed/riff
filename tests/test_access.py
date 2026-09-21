"""Proxy credentials, address allowlists, and bring-your-own CA."""

from __future__ import annotations

import base64
import http.client
import socket

import pytest

from riff.access import AccessError, AccessPolicy
from riff.ca import CaError, CertAuthority


# ── policy unit behaviour ───────────────────────────────────────────────


def test_no_policy_allows_everything():
    policy = AccessPolicy()
    assert policy.allows_address("203.0.113.9")
    assert policy.check_credentials(None)


def test_auth_needs_user_and_password():
    for spec in ("nouser", ":secret", "user:"):
        with pytest.raises(AccessError):
            AccessPolicy.build(auth=spec)


def test_bad_cidr_is_rejected_rather_than_ignored():
    with pytest.raises(AccessError):
        AccessPolicy.build(allow_from="10.0.0.0/33")
    with pytest.raises(AccessError):
        AccessPolicy.build(allow_from="not-an-address")


@pytest.mark.parametrize(
    "address,expected",
    [
        ("10.4.1.9", True),
        ("10.4.255.255", True),
        ("10.5.0.1", False),
        ("192.168.1.7", True),
        ("192.168.2.7", False),
        ("203.0.113.9", False),
        ("::ffff:10.4.1.9", True),  # IPv4 arriving on a dual-stack socket
        ("garbage", False),
    ],
)
def test_address_allowlist(address, expected):
    policy = AccessPolicy.build(allow_from="10.4.0.0/16, 192.168.1.0/24")
    assert policy.allows_address(address) is expected


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def test_credentials_are_checked_exactly():
    policy = AccessPolicy.build(auth="ada:hunter2")
    assert policy.check_credentials(_basic("ada", "hunter2"))
    assert not policy.check_credentials(_basic("ada", "wrong"))
    assert not policy.check_credentials(_basic("eve", "hunter2"))
    assert not policy.check_credentials(None)
    assert not policy.check_credentials("Bearer sometoken")
    assert not policy.check_credentials("Basic !!!not-base64!!!")
    assert not policy.check_credentials("Basic " + base64.b64encode(b"no-colon").decode())


# ── over the wire ───────────────────────────────────────────────────────


def test_proxy_demands_credentials_and_accepts_the_right_ones(make_proxy, origin):
    harness = make_proxy(auth="ada:hunter2")
    host, port = harness.address

    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", origin.url("/json"))
    response = conn.getresponse()
    body = response.read()
    conn.close()
    assert response.status == 407
    assert response.getheader("Proxy-Authenticate").startswith("Basic realm=")
    assert b"credentials" in body

    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", origin.url("/json"), headers={"Proxy-Authorization": _basic("ada", "hunter2")})
    response = conn.getresponse()
    assert response.status == 200
    response.read()
    conn.close()


def test_wrong_credentials_never_reach_the_origin(make_proxy, origin):
    harness = make_proxy(auth="ada:hunter2")
    host, port = harness.address
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", origin.url("/json"), headers={"Proxy-Authorization": _basic("eve", "guess")})
    assert conn.getresponse().status == 407
    conn.close()
    assert harness.hub.list() == []


def test_credentials_are_not_forwarded_upstream(make_proxy, origin):
    import json

    harness = make_proxy(auth="ada:hunter2")
    host, port = harness.address
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", origin.url("/echo"), headers={"Proxy-Authorization": _basic("ada", "hunter2")})
    seen = json.loads(conn.getresponse().read())["headers"]
    conn.close()
    assert "proxy-authorization" not in seen


def test_connect_also_requires_credentials(make_proxy, tls_origin, client_ssl_context):
    harness = make_proxy(auth="ada:hunter2")
    host, port = harness.address
    conn = http.client.HTTPSConnection(host, port, timeout=10, context=client_ssl_context)
    conn.set_tunnel(tls_origin.host, tls_origin.port)
    with pytest.raises(OSError):
        conn.request("GET", "/json")
        conn.getresponse()
    conn.close()

    conn = http.client.HTTPSConnection(host, port, timeout=10, context=client_ssl_context)
    conn.set_tunnel(tls_origin.host, tls_origin.port, headers={"Proxy-Authorization": _basic("ada", "hunter2")})
    conn.request("GET", "/json")
    assert conn.getresponse().status == 200
    conn.close()


def test_disallowed_address_is_dropped_at_accept(make_proxy, origin):
    # Loopback is deliberately excluded, so our own connection must be refused.
    harness = make_proxy(allow_from="10.99.0.0/16")
    host, port = harness.address
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(f"GET {origin.url('/json')} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        try:
            # Windows reports an abortive close as an error rather than EOF;
            # either way the point is that no HTTP response comes back.
            assert sock.recv(100) == b""
        except ConnectionResetError:
            pass
        except OSError as exc:
            assert exc.winerror in (10053, 10054), exc
    assert harness.hub.list() == []


def test_allowed_address_passes(make_proxy, origin):
    harness = make_proxy(allow_from="127.0.0.0/8")
    host, port = harness.address
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", origin.url("/json"))
    assert conn.getresponse().status == 200
    conn.close()


# ── bring your own CA ───────────────────────────────────────────────────


def test_supplied_ca_is_used_for_minting(tmp_path, ca):
    """A caller-supplied CA signs the leaves instead of a generated one."""
    borrowed = CertAuthority(str(tmp_path / "home"), cert_path=ca.ca_cert_path, key_path=ca.ca_key_path)
    assert borrowed.byo
    borrowed.context_for("example.test")

    from cryptography import x509

    data = (tmp_path / "home" / "certs" / "example.test.pem").read_bytes()
    start = data.index(b"-----BEGIN CERTIFICATE-----")
    stop = data.index(b"-----END CERTIFICATE-----") + 25
    leaf = x509.load_pem_x509_certificate(data[start:stop] + b"\n")
    original, _ = ca.load_or_create()
    assert leaf.issuer == original.subject


def test_a_missing_supplied_ca_is_a_clear_error(tmp_path):
    authority = CertAuthority(str(tmp_path), cert_path=str(tmp_path / "nope.pem"), key_path=str(tmp_path / "nope.key"))
    with pytest.raises(CaError) as info:
        authority.load_or_create()
    assert "does not exist" in str(info.value)


def test_a_server_certificate_is_refused_as_a_ca(tmp_path, ca):
    """A leaf cert cannot sign, and riff must say so instead of failing later."""
    leaf_bundle = ca.leaf_path("plain.test")
    ca.context_for("plain.test")
    data = open(leaf_bundle, "rb").read()

    cert_start = data.index(b"-----BEGIN CERTIFICATE-----")
    cert_stop = data.index(b"-----END CERTIFICATE-----") + 25
    key_stop = data.index(b"-----END PRIVATE KEY-----") + 25

    cert_file = tmp_path / "leaf.pem"
    key_file = tmp_path / "leaf.key"
    cert_file.write_bytes(data[cert_start:cert_stop] + b"\n")
    key_file.write_bytes(data[:key_stop] + b"\n")

    authority = CertAuthority(str(tmp_path / "home"), cert_path=str(cert_file), key_path=str(key_file))
    with pytest.raises(CaError) as info:
        authority.load_or_create()
    assert "not a CA" in str(info.value)


def test_a_corrupt_ca_file_is_a_clear_error(tmp_path):
    cert_file = tmp_path / "bad.pem"
    key_file = tmp_path / "bad.key"
    cert_file.write_text("this is not a certificate")
    key_file.write_text("nor is this a key")
    authority = CertAuthority(str(tmp_path / "home"), cert_path=str(cert_file), key_path=str(key_file))
    with pytest.raises(CaError) as info:
        authority.load_or_create()
    assert "unencrypted PEM" in str(info.value)

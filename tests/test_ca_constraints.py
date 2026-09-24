"""A name-constrained CA cannot sign outside its subtrees.

The point of RFC 5280 name constraints here is that the limit is carried in the
signed root certificate, so it is enforced by whatever validates the chain — not
by riff choosing to behave. These tests check both halves: that riff refuses to
mint, and that a validator rejects the certificate even when riff is bypassed
and the leaf is signed with the CA key directly.
"""

from __future__ import annotations

import datetime as dt
import tempfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from riff.ca import (
    CaError,
    CertAuthority,
    host_permitted,
    name_constraints,
    parse_constraints,
    permitted_patterns,
)


@pytest.fixture
def constrained() -> CertAuthority:
    authority = CertAuthority(
        tempfile.mkdtemp(prefix="riff-nc-"), constrain_to=["*.example.com", "localhost"]
    )
    authority.load_or_create()
    return authority


# ── parsing ──────────────────────────────────────────────────────────────


def test_a_glob_becomes_a_dns_subtree():
    dns, ips = parse_constraints(["*.example.com"])
    assert [d.value for d in dns] == ["example.com"]
    assert ips == []


def test_addresses_and_blocks_become_ip_subtrees():
    dns, ips = parse_constraints(["127.0.0.1", "10.0.0.0/8"])
    assert dns == []
    assert [str(i.value) for i in ips] == ["127.0.0.1/32", "10.0.0.0/8"]


def test_no_patterns_means_no_extension():
    assert name_constraints([]) is None
    assert name_constraints(["   "]) is None


def test_constraining_dns_still_pins_ip_so_there_is_no_gap():
    """A name type absent from permittedSubtrees is unconstrained, so an
    IP-only leaf would slip past a DNS-only constraint."""
    extension = name_constraints(["example.com"])
    kinds = {type(entry) for entry in extension.permitted_subtrees}
    assert x509.IPAddress in kinds


# ── matching ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "host,allowed",
    [
        ("example.com", True),
        ("api.example.com", True),
        ("deep.nested.example.com", True),
        ("localhost", True),
        ("notexample.com", False),
        ("example.com.attacker.net", False),
        ("chase.com", False),
        ("", False),
    ],
)
def test_host_permitted(host, allowed):
    assert host_permitted(host, ["*.example.com", "localhost"]) is allowed


def test_no_constraints_permits_everything():
    assert host_permitted("anything.test", []) is True


# ── the certificate ──────────────────────────────────────────────────────


def test_the_root_carries_the_constraint(constrained):
    cert, _ = constrained.load_or_create()
    extension = cert.extensions.get_extension_for_class(x509.NameConstraints)
    assert extension.critical, "RFC 5280 wants this critical, so it cannot be ignored"
    assert "example.com" in permitted_patterns(cert)


def test_an_unconstrained_root_has_no_extension():
    authority = CertAuthority(tempfile.mkdtemp(prefix="riff-open-"))
    cert, _ = authority.load_or_create()
    assert permitted_patterns(cert) == ()
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.NameConstraints)


def test_riff_mints_for_an_in_scope_host(constrained):
    assert constrained.context_for("api.example.com") is not None


def test_riff_refuses_to_mint_out_of_scope(constrained):
    with pytest.raises(CaError) as info:
        constrained.context_for("chase.com")
    message = str(info.value)
    assert "name-constrained" in message
    assert "chase.com" in message
    assert "passthru" in message, "the error should say what to do instead"


# ── enforcement by something other than riff ─────────────────────────────


def _forge(ca_cert, ca_key, host: str) -> x509.Certificate:
    """Sign a leaf for `host` directly, bypassing riff's own refusal."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )


def _verifies(ca_cert, leaf, host: str) -> bool:
    verification = pytest.importorskip(
        "cryptography.x509.verification", reason="needs a cryptography with the verifier API"
    )
    builder = verification.PolicyBuilder().store(verification.Store([ca_cert]))
    verifier = builder.build_server_verifier(x509.DNSName(host))
    try:
        verifier.verify(leaf, [])
        return True
    except Exception:
        return False


def test_a_validator_accepts_an_in_scope_leaf(constrained):
    ca_cert, ca_key = constrained.load_or_create()
    leaf = _forge(ca_cert, ca_key, "api.example.com")
    assert _verifies(ca_cert, leaf, "api.example.com")


def test_a_validator_rejects_an_out_of_scope_leaf_even_though_the_ca_signed_it(constrained):
    """The constraint is cryptographic: bypassing riff does not help."""
    ca_cert, ca_key = constrained.load_or_create()
    leaf = _forge(ca_cert, ca_key, "chase.com")
    assert leaf.issuer == ca_cert.subject, "it really was signed by this CA"
    assert not _verifies(ca_cert, leaf, "chase.com")

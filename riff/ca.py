"""On-the-fly certificate minting.

A long-lived root CA lives in the riff home directory. Leaf certificates are
signed for each intercepted host as it is first seen, cached on disk, and fed
to Python's ssl module (which can only load key material from files).

The root CA is only useful once *you* choose to trust it — riff never touches
the system trust store on its own. See `riff ca install`.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT_VALID_DAYS = 3 * 365
LEAF_VALID_DAYS = 397  # browsers reject leaves valid for longer than 398 days
CLOCK_SKEW = dt.timedelta(days=1)

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


def default_home() -> str:
    return os.environ.get("RIFF_HOME") or os.path.join(os.path.expanduser("~"), ".riff")


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _serial() -> int:
    return x509.random_serial_number()


class CaError(Exception):
    """The configured certificate authority cannot be used for signing."""


def expires_at(cert: x509.Certificate) -> dt.datetime:
    """`not_valid_after`, tolerating both the old and new cryptography APIs."""
    value = getattr(cert, "not_valid_after_utc", None)
    if value is None:  # pragma: no cover - cryptography < 42
        value = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    return value


def _write_private(path: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    restrict_to_owner(path)


def system_tool(name: str) -> str:
    """Absolute path of a Windows system tool, so a hostile PATH cannot substitute it."""
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    candidate = os.path.join(root, "System32", name + ".exe")
    if os.path.isfile(candidate):
        return candidate
    import shutil

    return shutil.which(name) or candidate


def restrict_to_owner(path: str) -> None:
    """Best-effort: make sure nobody but this user can read the key.

    The mode passed to os.open is close to meaningless on Windows, so drop
    inherited ACEs and grant only the current user. Failure is not fatal —
    the key is still inside the user profile.
    """
    if os.name != "nt":
        return
    import contextlib
    import subprocess  # nosec B404 - fixed argument list, absolute path, no shell

    user = os.environ.get("USERNAME")
    if not user:
        return
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(  # nosec B603 - arguments are not user-controlled
            [system_tool("icacls"), path, "/inheritance:r", "/grant:r", f"{user}:F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )


class CertAuthority:
    """Owns the root CA and mints/caches leaf certificates per host."""

    def __init__(
        self,
        home: str | None = None,
        organisation: str = "riff proxy",
        cert_path: str = "",
        key_path: str = "",
    ):
        self.home = home or default_home()
        self.certs_dir = os.path.join(self.home, "certs")
        # A caller-supplied CA (--ca-cert/--ca-key) is used as-is and never
        # regenerated; otherwise riff owns a CA inside its own home directory.
        self.byo = bool(cert_path or key_path)
        self.ca_cert_path = cert_path or os.path.join(self.home, "riff-ca.crt")
        self.ca_key_path = key_path or os.path.join(self.home, "riff-ca.key")
        self.leaf_key_path = os.path.join(self.home, "riff-leaf.key")
        self.organisation = organisation
        # Reentrant: context_for() holds the lock while _mint() calls load_or_create().
        self._lock = threading.RLock()
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._ca_cert: x509.Certificate | None = None
        self._ca_key: rsa.RSAPrivateKey | None = None
        self._leaf_key: rsa.RSAPrivateKey | None = None

    # -- root ---------------------------------------------------------------

    @property
    def exists(self) -> bool:
        return os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path)

    def load_or_create(self) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        with self._lock:
            if self._ca_cert is not None and self._ca_key is not None:
                return self._ca_cert, self._ca_key
            os.makedirs(self.certs_dir, exist_ok=True)
            if self.exists:
                self._ca_cert, self._ca_key = self._load_root()
                self._verify_can_sign(self._ca_cert)
            elif self.byo:
                missing = [p for p in (self.ca_cert_path, self.ca_key_path) if not os.path.exists(p)]
                raise CaError("cannot read the supplied CA: " + ", ".join(missing) + " does not exist")
            else:
                self._ca_cert, self._ca_key = self._create_root()
            self._leaf_key = self._load_or_create_leaf_key()
            return self._ca_cert, self._ca_key

    def _load_root(self):
        try:
            with open(self.ca_cert_path, "rb") as fh:
                cert = x509.load_pem_x509_certificate(fh.read())
            with open(self.ca_key_path, "rb") as fh:
                key = serialization.load_pem_private_key(fh.read(), password=None)
        except (OSError, ValueError, TypeError) as exc:
            raise CaError(
                f"could not load the CA from {self.ca_cert_path} / {self.ca_key_path}: {exc}. "
                f"Both must be unencrypted PEM."
            ) from None
        return cert, key

    @staticmethod
    def _verify_can_sign(cert: x509.Certificate) -> None:
        """A leaf certificate cannot mint other certificates — say so early.

        Without this the failure surfaces much later as an opaque TLS error in
        whatever client happens to be talking to the proxy.
        """
        try:
            constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            raise CaError(
                "the supplied certificate has no basicConstraints extension, so it is not a CA. "
                "riff needs a signing CA, not a server certificate."
            ) from None
        if not constraints.ca:
            raise CaError(
                "the supplied certificate is not a CA (basicConstraints CA:FALSE). A normal TLS "
                "server certificate cannot sign the per-host certificates riff mints — you need a "
                "CA certificate and its private key."
            )
        try:
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            return
        if not usage.key_cert_sign:
            raise CaError("the supplied CA does not allow certificate signing (keyUsage keyCertSign is off).")

    def _create_root(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "riff Root CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organisation),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "local interception"),
            ]
        )
        now = _utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(_serial())
            .not_valid_before(now - CLOCK_SKEW)
            .not_valid_after(now + dt.timedelta(days=ROOT_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        os.makedirs(self.home, exist_ok=True)
        with open(self.ca_cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        _write_private(
            self.ca_key_path,
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
        return cert, key

    def _load_or_create_leaf_key(self) -> rsa.RSAPrivateKey:
        """One key shared by every leaf — minting a fresh RSA key per host is slow."""
        if os.path.exists(self.leaf_key_path):
            with open(self.leaf_key_path, "rb") as fh:
                return serialization.load_pem_private_key(fh.read(), password=None)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _write_private(
            self.leaf_key_path,
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
        return key

    def fingerprint(self) -> str:
        cert, _ = self.load_or_create()
        digest = cert.fingerprint(hashes.SHA256())
        return ":".join(f"{b:02X}" for b in digest)

    # -- leaves -------------------------------------------------------------

    @staticmethod
    def _san_for(host: str) -> x509.SubjectAlternativeName:
        try:
            return x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host))])
        except ValueError:
            pass
        names: list[x509.GeneralName] = [x509.DNSName(host)]
        labels = host.split(".")
        if len(labels) > 2 and not host.startswith("*."):
            names.append(x509.DNSName("*." + ".".join(labels[1:])))
        return x509.SubjectAlternativeName(names)

    def leaf_path(self, host: str) -> str:
        return os.path.join(self.certs_dir, _SAFE_NAME.sub("_", host) + ".pem")

    def _mint(self, host: str) -> str:
        """Write key+cert+chain for `host` to a PEM bundle and return the path."""
        ca_cert, ca_key = self.load_or_create()
        if self._leaf_key is None:  # load_or_create() always sets it; guard rather than assert
            raise CaError("the leaf key was not initialised")
        leaf_key = self._leaf_key
        now = _utcnow()

        subject_host = host if len(host) <= 64 else host[-64:]
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_host)]))
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(_serial())
            .not_valid_before(now - CLOCK_SKEW)
            .not_valid_after(now + dt.timedelta(days=LEAF_VALID_DAYS))
            .add_extension(self._san_for(host), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )

        bundle = (
            leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            + cert.public_bytes(serialization.Encoding.PEM)
            + ca_cert.public_bytes(serialization.Encoding.PEM)
        )
        path = self.leaf_path(host)
        os.makedirs(self.certs_dir, exist_ok=True)
        _write_private(path, bundle)
        return path

    def context_for(self, host: str) -> ssl.SSLContext:
        """A server-side SSLContext presenting a certificate valid for `host`."""
        host = (host or "unknown.invalid").strip("[]").lower()
        cached = self._contexts.get(host)
        if cached is not None:
            return cached
        with self._lock:
            cached = self._contexts.get(host)
            if cached is not None:
                return cached
            path = self.leaf_path(host)
            if not os.path.exists(path) or self._expiring_soon(path):
                path = self._mint(host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            # Never offer h2: riff speaks HTTP/1.1 only.
            ctx.set_alpn_protocols(["http/1.1"])
            ctx.load_cert_chain(path)
            self._contexts[host] = ctx
            return ctx

    @staticmethod
    def _expiring_soon(path: str) -> bool:
        begin, end = b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            start = data.index(begin)
            stop = data.index(end, start) + len(end)
            cert = x509.load_pem_x509_certificate(data[start:stop] + b"\n")
        except Exception:
            return True
        return expires_at(cert) - _utcnow() < dt.timedelta(days=14)

    def sni_callback(self, sslsock, servername, _ctx):
        """Swap in the right certificate once the client tells us the hostname."""
        if servername:
            try:
                sslsock.context = self.context_for(servername)
            except Exception:
                return ssl.ALERT_DESCRIPTION_INTERNAL_ERROR
        return None

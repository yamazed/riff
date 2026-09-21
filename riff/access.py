"""Who is allowed to use this proxy.

An interception proxy reachable from the network is a credential firehose and a
pivot into whatever it can route to, so both controls here fail closed: an
unparsable allowlist entry is dropped rather than widened, and a missing or
malformed Proxy-Authorization is a 407 rather than a pass.
"""

from __future__ import annotations

import base64
import ipaddress
import secrets
from dataclasses import dataclass, field

PROXY_AUTH_REALM = "riff"


class AccessError(ValueError):
    """A malformed --auth or --allow-from value."""


def parse_credentials(spec: str) -> tuple[str, str]:
    user, sep, password = spec.partition(":")
    if not sep or not user or not password:
        raise AccessError(f"--auth needs user:password, got {spec!r}")
    return user, password


def parse_networks(spec: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a comma-separated list of addresses or CIDR blocks."""
    networks = []
    for chunk in spec.split(","):
        text = chunk.strip()
        if not text:
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError as exc:
            raise AccessError(f"{text!r} is not an address or CIDR block: {exc}") from None
    return networks


@dataclass(slots=True)
class AccessPolicy:
    """Network-level and credential-level admission control."""

    username: str = ""
    password: str = ""
    networks: list = field(default_factory=list)

    @classmethod
    def build(cls, auth: str = "", allow_from: str = "") -> "AccessPolicy":
        username, password = parse_credentials(auth) if auth else ("", "")
        return cls(username=username, password=password, networks=parse_networks(allow_from))

    @property
    def requires_auth(self) -> bool:
        return bool(self.username)

    @property
    def restricts_addresses(self) -> bool:
        return bool(self.networks)

    def allows_address(self, address: str) -> bool:
        if not self.networks:
            return True
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return False
        # An IPv4 client arriving on a dual-stack socket looks like ::ffff:a.b.c.d.
        mapped = getattr(parsed, "ipv4_mapped", None)
        candidates = [parsed] + ([mapped] if mapped else [])
        return any(c in net for c in candidates for net in self.networks if c.version == net.version)

    def check_credentials(self, header: str | None) -> bool:
        if not self.requires_auth:
            return True
        if not header:
            return False
        scheme, _, encoded = header.strip().partition(" ")
        if scheme.lower() != "basic" or not encoded:
            return False
        try:
            decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
        except Exception:
            return False
        user, sep, password = decoded.partition(":")
        if not sep:
            return False
        # Compare both halves regardless of the first result, so a wrong
        # username costs the same as a wrong password.
        user_ok = secrets.compare_digest(user, self.username)
        password_ok = secrets.compare_digest(password, self.password)
        return user_ok and password_ok

    def describe(self) -> str:
        parts = []
        parts.append(f"auth {self.username!r}" if self.requires_auth else "no auth")
        if self.networks:
            parts.append("from " + ", ".join(str(n) for n in self.networks))
        return ", ".join(parts)

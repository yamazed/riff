"""The Finding model and an in-memory, deduplicating store.

A Finding is one thing a check noticed about one flow: a severity, a short
human title, the evidence that triggered it, and the flow it came from so the
UI can click through. The store keeps the most recent findings, bounded like
the flow buffer, and collapses repeats: a site missing a security header
produces one finding for that host, not one per request.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

# Severity ranks, high to low. `info` is a hardening note, not a vulnerability.
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
CONFIDENCE = ("firm", "tentative")


@dataclass(slots=True)
class Finding:
    check: str  # stable id of the check that raised it, e.g. "missing-csp"
    title: str  # one line a human reads in the list
    severity: str  # high | medium | low | info
    flow_id: int
    url: str
    evidence: str = ""  # the concrete thing seen (a header value, a cookie name)
    detail: str = ""  # why it matters and what to do about it
    confidence: str = "firm"  # firm | tentative
    where: str = ""  # dedup scope within a check (host, host+cookie, ...); defaults to the URL
    at: float = field(default_factory=time.time)

    @property
    def key(self) -> str:
        """Two findings with the same key are the same issue seen again."""
        return f"{self.check}|{self.where or self.url}"

    def public(self) -> dict[str, Any]:
        row = asdict(self)
        row.pop("where", None)
        row["key"] = self.key
        row["rank"] = SEVERITY_RANK.get(self.severity, 99)
        return row


class FindingStore:
    """Deduplicating, capacity-bounded, thread-safe. First flow to show an issue wins."""

    def __init__(self, capacity: int = 2000):
        self.capacity = capacity
        self._by_key: "dict[str, Finding]" = {}
        self._lock = threading.Lock()

    def add(self, finding: Finding) -> bool:
        """Store it. Returns True only when the issue is new (so callers broadcast once)."""
        with self._lock:
            if finding.key in self._by_key:
                return False
            self._by_key[finding.key] = finding
            while len(self._by_key) > self.capacity:
                oldest = min(self._by_key.values(), key=lambda f: f.at)
                self._by_key.pop(oldest.key, None)
            return True

    def add_all(self, findings) -> list[Finding]:
        return [f for f in findings if self.add(f)]

    def list(self) -> list[dict]:
        with self._lock:
            items = list(self._by_key.values())
        items.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 99), -f.at))
        return [f.public() for f in items]

    def counts(self) -> dict[str, int]:
        out = {level: 0 for level in SEVERITY_RANK}
        with self._lock:
            for f in self._by_key.values():
                out[f.severity] = out.get(f.severity, 0) + 1
        out["total"] = sum(out[level] for level in SEVERITY_RANK)
        return out

    def clear(self) -> None:
        with self._lock:
            self._by_key.clear()

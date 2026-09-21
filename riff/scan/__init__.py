"""riff's built-in scanner.

Phase 1 is passive: `scan_flow` reads a captured `Flow` and returns `Finding`s
without sending any traffic. The `Hub` runs it as flows arrive and keeps the
results in a `FindingStore`, which the web UI reads through `/api/findings`.
"""

from __future__ import annotations

from .active import ACTIVE_CHECKS, DEFAULT_CHECK_NAMES
from .collaborator import Collaborator
from .engine import ScanConfig, ScanJob, Scanner, ScanTarget, ScopeError, host_in_scope, targets_from_details
from .findings import CONFIDENCE, SEVERITY_RANK, Finding, FindingStore
from .passive import PASSIVE_CHECKS, scan_flow

__all__ = [
    "CONFIDENCE",
    "SEVERITY_RANK",
    "Finding",
    "FindingStore",
    "PASSIVE_CHECKS",
    "scan_flow",
    "ACTIVE_CHECKS",
    "DEFAULT_CHECK_NAMES",
    "ScanConfig",
    "ScanJob",
    "Scanner",
    "ScanTarget",
    "ScopeError",
    "host_in_scope",
    "targets_from_details",
    "Collaborator",
]

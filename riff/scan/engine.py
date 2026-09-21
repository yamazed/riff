"""The active-scan job runner.

Given base flows and a scope, it enumerates insertion points, runs the selected
active checks against each, and collects findings. Two safety rules are enforced
here, not left to the checks:

* **Scope.** A flow is only scanned if its host is in the operator's allowlist,
  and every probe's target host is re-checked before the socket opens. A probe
  to an out-of-scope host is refused.
* **Budget.** Points per flow, worker count, and an inter-probe delay are all
  capped, so a scan cannot melt a target or run away.

The runner is cancellable and reports progress through the Hub's event stream.
"""

from __future__ import annotations

import fnmatch
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from itertools import count
from typing import Any

from .. import replay
from ..flow import Request, Response
from .active import ACTIVE_CHECKS, ActiveCheck, ProbeContext, select_checks
from .findings import Finding
from .points import insertion_points


class ScopeError(ValueError):
    """A scan was asked to touch a host outside the allowlist."""


def host_in_scope(host: str, allowed: "set[str] | tuple[str, ...]") -> bool:
    """Case-insensitive exact or glob match, e.g. 'api.example.com' or '*.example.com'."""
    h = (host or "").lower()
    for pattern in allowed:
        p = pattern.lower()
        if h == p or fnmatch.fnmatch(h, p):
            return True
    return False


@dataclass
class ScanTarget:
    flow_id: int
    request: Request
    baseline: Response | None


@dataclass
class ScanConfig:
    allowed_hosts: tuple[str, ...]
    check_names: tuple[str, ...] | None = None  # None -> the default-on checks
    max_points_per_flow: int = 40
    max_workers: int = 6
    delay_ms: int = 0          # pause between probes, per worker (rate limit)
    time_delay_s: float = 3.0  # target delay for the time-based check
    collaborator: Any = None   # a Collaborator to enable out-of-band checks, else None
    oob_grace_s: float = 5.0   # how long to wait for out-of-band callbacks after probing

    @property
    def checks(self) -> list[ActiveCheck]:
        checks = select_checks(self.check_names)
        # The out-of-band check is only meaningful with a collaborator; whenever one is
        # configured, ensure it runs (it is inert without a collaborator, so it is never
        # in the default set).
        if self.collaborator is not None:
            oob = next((c for c in ACTIVE_CHECKS if c.name == "oob-interaction"), None)
            if oob and oob not in checks:
                checks.append(oob)
        return checks


@dataclass
class ScanJob:
    id: int
    status: str = "running"  # running | done | cancelled | error
    error: str = ""
    started: float = field(default_factory=time.time)
    ended: float = 0.0
    units_total: int = 0
    units_done: int = 0
    probes_sent: int = 0
    findings_new: int = 0
    hosts: tuple[str, ...] = ()
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id, "status": self.status, "error": self.error,
            "started": self.started, "ended": self.ended,
            "units_total": self.units_total, "units_done": self.units_done,
            "probes_sent": self.probes_sent, "findings_new": self.findings_new,
            "hosts": list(self.hosts),
        }


class Scanner:
    """Owns active-scan jobs. One Scanner per proxy; the Hub holds the findings."""

    def __init__(self, proxy, hub):
        self.proxy = proxy
        self.hub = hub
        self._ids = count(1)
        self._jobs: "dict[int, ScanJob]" = {}
        self._threads: "dict[int, threading.Thread]" = {}
        self._lock = threading.Lock()

    # -- public API --------------------------------------------------------

    def start(self, targets: list[ScanTarget], config: ScanConfig) -> ScanJob:
        if not config.allowed_hosts:
            raise ScopeError("a scan needs at least one in-scope host")
        in_scope = [t for t in targets if host_in_scope(t.request.host, config.allowed_hosts)]
        job = ScanJob(id=next(self._ids), hosts=config.allowed_hosts)
        plan = self._plan(in_scope, config)
        job.units_total = len(plan)
        with self._lock:
            self._jobs[job.id] = job
        thread = threading.Thread(target=self._run, args=(job, plan, config), name=f"scan-{job.id}", daemon=True)
        with self._lock:
            self._threads[job.id] = thread
        self.hub.broadcast_scan(job.public())
        if not plan:
            self._finish(job, "done")
            return job
        thread.start()
        return job

    def job(self, job_id: int) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def jobs(self) -> list[dict]:
        with self._lock:
            return [j.public() for j in self._jobs.values()]

    def cancel(self, job_id: int) -> bool:
        job = self.job(job_id)
        if job and job.status == "running":
            job.cancel()
            return True
        return False

    # -- the run -----------------------------------------------------------

    def _plan(self, targets: list[ScanTarget], config: ScanConfig) -> list[tuple[ScanTarget, Any]]:
        units: list[tuple[ScanTarget, Any]] = []
        for target in targets:
            points = insertion_points(target.request)[: config.max_points_per_flow]
            for point in points:
                units.append((target, point))
        return units

    def _bound_exchange(self, allowed_hosts: tuple[str, ...], delay_ms: int, job: ScanJob):
        def exchange(request: Request):
            if not host_in_scope(request.host, allowed_hosts):
                # Defence in depth: never let a probe leave scope.
                return None, f"host {request.host!r} is out of scope", 0.0
            result = replay.exchange(self.proxy, request)
            with job._lock:
                job.probes_sent += 1
            if delay_ms:
                time.sleep(delay_ms / 1000.0)
            return result
        return exchange

    def _run(self, job: ScanJob, plan: list[tuple[ScanTarget, Any]], config: ScanConfig) -> None:
        checks = config.checks
        exchange = self._bound_exchange(config.allowed_hosts, config.delay_ms, job)
        oob_registry: dict = {} if config.collaborator is not None else None

        def do_unit(unit) -> None:
            target, point = unit
            if job.cancelled:
                return
            ctx = ProbeContext(
                base_flow_id=target.flow_id, base_url=target.request.url,
                base_request=target.request, baseline=target.baseline,
                exchange=exchange, time_delay_s=config.time_delay_s,
                collaborator=config.collaborator, oob_registry=oob_registry,
            )
            for check in checks:
                if job.cancelled:
                    break
                for finding in check.run(point, ctx):
                    self._record(job, finding)
            with job._lock:
                job.units_done += 1
            if job.units_done % 5 == 0 or job.units_done == job.units_total:
                self.hub.broadcast_scan(job.public())

        try:
            with ThreadPoolExecutor(max_workers=max(1, config.max_workers)) as pool:
                list(pool.map(do_unit, plan))
            if oob_registry and not job.cancelled:
                self._collect_oob(job, config, oob_registry)
        except Exception as exc:  # pragma: no cover - defensive
            self._finish(job, "error", str(exc))
            return
        self._finish(job, "cancelled" if job.cancelled else "done")

    def _collect_oob(self, job: ScanJob, config: ScanConfig, registry: dict) -> None:
        """After probing, wait a grace period and raise a finding for each token that called home."""
        deadline = time.time() + config.oob_grace_s
        seen: set[str] = set()
        while time.time() < deadline and len(seen) < len(registry) and not job.cancelled:
            for token, hits in config.collaborator.any_hits().items():
                if token in registry and token not in seen and hits:
                    seen.add(token)
                    self._record(job, registry[token])
            time.sleep(0.25)

    def _record(self, job: ScanJob, finding: Finding) -> None:
        if self.hub.findings.add(finding):
            with job._lock:
                job.findings_new += 1
            self.hub._broadcast("finding", finding.public())

    def _finish(self, job: ScanJob, status: str, error: str = "") -> None:
        job.status = status
        job.error = error
        job.ended = time.time()
        self.hub.broadcast_scan(job.public())


def targets_from_details(details: list[dict]) -> list[ScanTarget]:
    """Rebuild scan targets from Hub detail dicts (Flow.to_dict shape)."""
    from .. import transfer

    out: list[ScanTarget] = []
    for detail in details:
        try:
            flow = transfer._from_riff(detail)
        except Exception:
            continue
        out.append(ScanTarget(flow_id=int(detail.get("id") or 0), request=flow.request, baseline=flow.response))
    return out


def targets_from_flows(flows) -> list[ScanTarget]:
    """Scan targets straight from Flow objects (the headless CLI path)."""
    return [ScanTarget(flow_id=f.id, request=f.request, baseline=f.response) for f in flows]

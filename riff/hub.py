"""In-memory flow store with fan-out to live UI subscribers."""

from __future__ import annotations

import itertools
import queue
import threading
import time
from collections import OrderedDict
from typing import Any

from .flow import Flow
from .proxy import Observer
from .scan import Finding, FindingStore, scan_flow

MAX_STORED_BODY = 512 * 1024


def _findings_from_detail(detail: dict) -> list[Finding]:
    """Rebuild a Flow from a stored detail dict and run the passive checks over it."""
    from . import transfer  # local import: transfer is heavier and only needed for a rescan

    try:
        flow = transfer._from_riff(detail)
    except Exception:
        return []
    flow.id = int(detail.get("id") or 0)
    return scan_flow(flow)


def summarise(flow: Flow) -> dict[str, Any]:
    response = flow.response
    return {
        "id": flow.id,
        "started": flow.started,
        "method": flow.request.method,
        "scheme": flow.request.scheme,
        "host": flow.request.host,
        "port": flow.request.port,
        "path": flow.request.origin_form,
        "url": flow.request.url,
        "tls": flow.tls,
        "status": response.status if response else 0,
        "reason": (response.reason if response else "") or "",
        "content_type": flow.content_type,
        "size": len(response.body) if response else 0,
        "request_size": len(flow.request.body),
        "duration_ms": round(flow.duration_ms, 1),
        "tags": list(flow.tags),
        "intercepted": flow.intercepted,
        "aborted": flow.aborted,
        "error": flow.error,
        "client": flow.client,
        "logs": list(flow.logs),
    }


class Hub(Observer):
    """Keeps the last N flows and pushes events to every attached subscriber."""

    def __init__(self, capacity: int = 5000, scan: bool = True):
        self.capacity = capacity
        self._flows: "OrderedDict[int, dict]" = OrderedDict()
        self._details: "OrderedDict[int, dict]" = OrderedDict()
        self._lock = threading.Lock()
        self._subscribers: set[queue.Queue] = set()
        self._events = itertools.count(1)
        self.started = time.time()
        self.tunnels = 0
        self.tunnel_bytes = 0
        # Passive scanning: safe by default (it sends nothing), toggleable per run.
        self.scan_enabled = scan
        self.findings = FindingStore()

    # -- subscription ------------------------------------------------------

    def subscribe(self) -> queue.Queue:
        channel: queue.Queue = queue.Queue(maxsize=1000)
        with self._lock:
            self._subscribers.add(channel)
        return channel

    def unsubscribe(self, channel: queue.Queue) -> None:
        with self._lock:
            self._subscribers.discard(channel)

    def _broadcast(self, kind: str, payload: Any) -> None:
        message = {"seq": next(self._events), "type": kind, "data": payload}
        with self._lock:
            targets = list(self._subscribers)
        for channel in targets:
            try:
                channel.put_nowait(message)
            except queue.Full:
                # A stalled browser tab must not back up the proxy.
                with self._lock:
                    self._subscribers.discard(channel)

    # -- storage -----------------------------------------------------------

    def on_flow(self, flow: Flow) -> None:
        summary = summarise(flow)
        detail = flow.to_dict(include_bodies=True, body_limit=MAX_STORED_BODY)
        with self._lock:
            self._flows[flow.id] = summary
            self._details[flow.id] = detail
            while len(self._flows) > self.capacity:
                oldest, _ = self._flows.popitem(last=False)
                self._details.pop(oldest, None)
        self._broadcast("flow", summary)
        self._scan(flow)

    def _scan(self, flow: Flow) -> None:
        """Run passive checks and broadcast any new finding. Never blocks capture."""
        if not self.scan_enabled:
            return
        try:
            fresh = self.findings.add_all(scan_flow(flow))
        except Exception:
            return
        for finding in fresh:
            self._broadcast("finding", finding.public())

    def on_tunnel(self, host: str, port: int, sent: int, received: int, seconds: float) -> None:
        self.tunnels += 1
        self.tunnel_bytes += sent + received
        self._broadcast(
            "tunnel",
            {"host": host, "port": port, "sent": sent, "received": received, "seconds": round(seconds, 2)},
        )

    def on_error(self, text: str) -> None:
        self._broadcast("error", {"text": text, "at": time.time()})

    def on_log(self, flow: Flow | None, text: str) -> None:
        self._broadcast("log", {"flow": flow.id if flow else 0, "text": text, "at": time.time()})

    # -- queries -----------------------------------------------------------

    def list(self, since: int = 0, limit: int = 2000) -> list[dict]:
        with self._lock:
            rows = [row for fid, row in self._flows.items() if fid > since]
        return rows[-limit:]

    def detail(self, flow_id: int) -> dict | None:
        with self._lock:
            return self._details.get(flow_id)

    def clear(self) -> None:
        with self._lock:
            self._flows.clear()
            self._details.clear()
        self.findings.clear()
        self._broadcast("cleared", {})

    # -- findings ----------------------------------------------------------

    def finding_rows(self) -> list[dict]:
        return self.findings.list()

    def finding_counts(self) -> dict[str, int]:
        return self.findings.counts()

    def clear_findings(self) -> None:
        self.findings.clear()
        self._broadcast("findings_cleared", {})

    def broadcast_scan(self, payload: dict) -> None:
        """Push an active-scan progress update to the live UI."""
        self._broadcast("scan", payload)

    def rescan(self) -> int:
        """Re-run passive checks over every buffered flow. Returns findings held after."""
        self.findings.clear()
        with self._lock:
            details = list(self._details.values())
        for detail in details:
            for finding in _findings_from_detail(detail):
                self.findings.add(finding)
        return self.finding_counts()["total"]

    def stats(self) -> dict:
        with self._lock:
            rows = list(self._flows.values())
        total_bytes = sum(r["size"] + r["request_size"] for r in rows)
        return {
            "flows": len(rows),
            "bytes": total_bytes,
            "tunnels": self.tunnels,
            "tunnel_bytes": self.tunnel_bytes,
            "uptime": round(time.time() - self.started, 1),
            "subscribers": len(self._subscribers),
        }

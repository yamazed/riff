"""Turn findings into a report: JSON for machines, Markdown for people.

The Markdown report leads with a severity summary, then a table, then a detail
section grouped by OWASP category, each finding carrying its evidence and a
remediation line. The JSON report is the raw finding rows plus metadata, for a
pipeline to consume.
"""

from __future__ import annotations

import json
import time
from typing import Any

_SEVERITY_ORDER = ("high", "medium", "low", "info")

# check id -> (OWASP-ish category, one-line remediation headline)
_CATEGORY = {
    "xss-reflected": ("Cross-site scripting (A03 Injection)", "Encode output; validate and reject markup in input."),
    "sqli-error": ("SQL injection (A03 Injection)", "Use parameterised queries everywhere."),
    "sqli-boolean": ("SQL injection (A03 Injection)", "Use parameterised queries everywhere."),
    "sqli-time": ("SQL injection (A03 Injection)", "Use parameterised queries everywhere."),
    "cmd-injection": ("OS command injection (A03 Injection)", "Never build shell commands from input; use safe APIs."),
    "open-redirect": ("Open redirect (A01 Broken Access Control)", "Allow only vetted redirect destinations."),
    "path-traversal": ("Path traversal (A01 Broken Access Control)", "Canonicalise paths; confine to a safe root."),
    "ssrf": ("Server-side request forgery (A10)", "Allowlist outbound hosts; block link-local and internal ranges."),
    "oob-interaction": ("Server-side request forgery (A10)", "Allowlist outbound hosts; never pass input to a shell."),
    # passive families
    "missing-csp": ("Security misconfiguration (A05)", "Set a Content-Security-Policy."),
    "missing-hsts": ("Security misconfiguration (A05)", "Set Strict-Transport-Security."),
    "missing-nosniff": ("Security misconfiguration (A05)", "Set X-Content-Type-Options: nosniff."),
    "missing-frame-options": ("Security misconfiguration (A05)", "Set X-Frame-Options or frame-ancestors."),
    "cookie-no-secure": ("Security misconfiguration (A05)", "Add Secure to cookies set over HTTPS."),
    "cookie-no-httponly": ("Security misconfiguration (A05)", "Add HttpOnly to session cookies."),
    "cookie-no-samesite": ("Security misconfiguration (A05)", "Add SameSite to cookies."),
    "credential-cleartext": ("Cryptographic failure (A02)", "Serve the endpoint over HTTPS only."),
    "cors-wildcard-credentials": ("Security misconfiguration (A05)", "Reflect a vetted origin, not '*', with credentials."),
    "version-banner": ("Security misconfiguration (A05)", "Remove version banners from responses."),
}


def _category(check: str) -> tuple[str, str]:
    if check in _CATEGORY:
        return _CATEGORY[check]
    if check.startswith("secret-"):
        return ("Sensitive data exposure (A02)", "Rotate the exposed secret and stop serving it.")
    return ("Other", "")


def to_json(rows: list[dict], meta: dict[str, Any] | None = None) -> str:
    enriched = []
    for r in rows:
        category, remediation = _category(r["check"])
        enriched.append(dict(r, category=category, remediation=remediation))
    return json.dumps({"generated": time.time(), "meta": meta or {}, "findings": enriched}, indent=2)


def to_markdown(rows: list[dict], meta: dict[str, Any] | None = None) -> str:
    meta = meta or {}
    counts = {level: sum(1 for r in rows if r["severity"] == level) for level in _SEVERITY_ORDER}
    lines: list[str] = ["# riff scan report", ""]
    if meta.get("hosts"):
        lines.append(f"**Scope:** {', '.join(meta['hosts'])}  ")
    if meta.get("source"):
        lines.append(f"**Source:** {meta['source']}  ")
    lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}  ")
    if meta.get("probes") is not None:
        lines.append(f"**Probes sent:** {meta['probes']}  ")
    lines.append(
        f"**Findings:** {len(rows)} "
        f"({counts['high']} high, {counts['medium']} medium, {counts['low']} low, {counts['info']} info)"
    )
    lines.append("")
    if not rows:
        lines.append("No findings. Either the target is clean for these checks, or the inputs were out of scope.")
        return "\n".join(lines)

    lines += ["| Severity | Check | Finding | Flow | Confidence |", "|---|---|---|---|---|"]
    for r in rows:
        where = r.get("title", r["check"]).replace("|", "\\|")
        lines.append(f"| {r['severity']} | {r['check']} | {where} | #{r['flow_id']} | {r.get('confidence', '')} |")
    lines.append("")

    # Detail grouped by OWASP category, categories ordered by their worst finding.
    groups: dict[str, list[dict]] = {}
    for r in rows:
        groups.setdefault(_category(r["check"])[0], []).append(r)

    def group_rank(item):
        _, members = item
        return min(_SEVERITY_ORDER.index(m["severity"]) for m in members)

    lines.append("## Detail")
    lines.append("")
    for category, members in sorted(groups.items(), key=group_rank):
        lines.append(f"### {category}")
        lines.append("")
        remediation = _category(members[0]["check"])[1]
        if remediation:
            lines.append(f"**Fix:** {remediation}")
            lines.append("")
        for r in members:
            title = r.get("title", r["check"])
            lines.append(f"- **[{r['severity'].upper()}] {title}** - {r['url']} (flow #{r['flow_id']})")
            if r.get("evidence"):
                lines.append(f"  - Evidence: {r['evidence']}")
            if r.get("confidence") == "tentative":
                lines.append("  - Confidence: tentative - confirm by hand.")
        lines.append("")
    return "\n".join(lines)

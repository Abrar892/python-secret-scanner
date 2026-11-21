"""Reporters: human-readable text and machine-readable JSON."""

from __future__ import annotations

import json

from .scanner import Finding, ScanResult

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def findings_to_json(findings: list[Finding], *, show_secrets: bool = False) -> str:
    """Serialize findings as a JSON array, sorted by severity then path."""
    ordered = sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 3), f.path, f.line, f.column),
    )
    payload = [
        {
            "path": f.path,
            "line": f.line,
            "column": f.column,
            "rule_id": f.rule_id,
            "rule": f.rule_name,
            "severity": f.severity,
            "value": f.display_value(show_secrets),
            "fingerprint": f.fingerprint,
            **({"entropy": f.entropy} if f.entropy is not None else {}),
        }
        for f in ordered
    ]
    return json.dumps(payload, indent=2) + "\n"


def render_text(result: ScanResult, *, show_secrets: bool = False) -> str:
    """Render a grouped, human-readable report (empty string when clean)."""
    if not result.findings:
        return ""
    lines: list[str] = []
    for severity in ("high", "medium", "low"):
        group = [f for f in result.findings if f.severity == severity]
        if not group:
            continue
        lines.append(f"{severity.upper()} ({len(group)})")
        lines.append("-" * len(lines[-1]))
        for finding in sorted(group, key=lambda f: (f.path, f.line)):
            extra = f" entropy={finding.entropy}" if finding.entropy is not None else ""
            lines.append(
                f"{finding.path}:{finding.line}:{finding.column} "
                f"[{finding.rule_id}] {finding.rule_name} — "
                f"{finding.display_value(show_secrets)}{extra}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"

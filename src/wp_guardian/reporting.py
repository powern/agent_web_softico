from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .models import SiteAudit

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def build_report(audits: list[SiteAudit]) -> dict:
    severities = Counter(
        finding.severity for audit in audits for finding in audit.findings
    )
    worst = "INFO"
    for severity in SEVERITY_ORDER:
        if severities[severity] and SEVERITY_ORDER[severity] > SEVERITY_ORDER[worst]:
            worst = severity
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "sites": len(audits),
            "findings": sum(severities.values()),
            "severities": dict(severities),
            "worst_severity": worst,
        },
        "sites": [audit.to_dict() for audit in audits],
    }


def update_label(item: dict) -> str:
    name = str(item.get("name") or item.get("slug") or "unknown")
    current = str(item.get("version") or "?")
    target = str(item.get("update_version") or item.get("new_version") or "?")
    return f"{name} {current} -> {target}"


def render_text(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "SOFTICO WORDPRESS GUARDIAN",
        f"Generated: {report['generated_at']}",
        f"Sites: {summary['sites']}",
        f"Findings: {summary['findings']}",
        f"Worst severity: {summary['worst_severity']}",
        "",
    ]
    for site in report["sites"]:
        lines.append(f"[{site['domain']}]")
        lines.append(f"Path: {site['path']}")
        facts = site["facts"]
        http = facts.get("http", {})
        if http:
            lines.append(
                f"HTTP: {http.get('code', 'n/a')} {http.get('url', '')} ({http.get('time', 'n/a')}s)"
            )
        core = facts.get("core_version")
        if core:
            lines.append(f"Core: {core}")
        updates = facts.get("updates", {})
        if updates:
            plugins = updates.get("plugins", [])
            themes = updates.get("themes", [])
            lines.append(f"Updates: plugins={len(plugins)}, themes={len(themes)}")
            for item in plugins:
                lines.append(f"  plugin: {update_label(item)}")
            for item in themes:
                lines.append(f"  theme: {update_label(item)}")
        uploads = facts.get("uploads_php", {})
        if uploads:
            lines.append(
                "Uploads scan: "
                f"scanned={uploads.get('scanned_files', 0)}, "
                f"php={uploads.get('php_files', 0)}, "
                f"suspicious={uploads.get('suspicious', 0)}, "
                f"complete={uploads.get('complete', False)}"
            )
        plugin_checksums = facts.get("plugin_checksums", {})
        if plugin_checksums:
            lines.append(
                "Plugin checksums: "
                f"checked={plugin_checksums.get('checked', 0)}, "
                f"skipped_private={plugin_checksums.get('skipped_private', 0)}, "
                f"failed={plugin_checksums.get('failed', 0)}, "
                f"timeouts={plugin_checksums.get('timeouts', 0)}"
            )
        if site["findings"]:
            for finding in site["findings"]:
                lines.append(
                    f"- {finding['severity']} {finding['check']}: {finding['message']}"
                )
        else:
            lines.append("- OK: no findings")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_report(report_dir: Path, report: dict) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = report_dir / f"audit-{stamp}.json"
    text_path = report_dir / f"audit-{stamp}.txt"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    text_path.write_text(render_text(report), encoding="utf-8")
    (report_dir / "latest.json").write_text(json_path.read_text(encoding="utf-8"), encoding="utf-8")
    (report_dir / "latest.txt").write_text(text_path.read_text(encoding="utf-8"), encoding="utf-8")
    return json_path, text_path

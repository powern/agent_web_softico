from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .audit import audit_all
from .backup import BackupError
from .config import GuardianConfig, load_config
from .discovery import discover_sites
from .reporting import build_report, render_text
from .retention import business_day_cutoff, prune_report_files
from .runner import CommandRunner
from .storage import Storage
from .update_apply import UpdateApplyError, apply_prepared_plugin_update
from .update_prepare import UpdatePreparationError, prepare_component_update
from .wordpress import WordPress

DEFAULT_CONFIG = Path("/etc/wp-guardian/guardian.toml")
MAX_AUTOMATIC_UPDATES = 25


class MaintenanceError(RuntimeError):
    pass


class MaintenanceAlreadyRunning(MaintenanceError):
    pass


@dataclass(slots=True)
class MaintenanceItem:
    kind: str
    name: str
    status: str
    current_version: str
    target_version: str | None
    action: str
    message: str = ""
    preparation_id: str | None = None
    checkpoint_directory: str | None = None
    record_path: str | None = None


@dataclass(slots=True)
class SiteMaintenance:
    domain: str
    items: list[MaintenanceItem] = field(default_factory=list)
    detection_error: str | None = None


@dataclass(slots=True)
class MaintenanceResult:
    generated_at: str
    sites: list[SiteMaintenance]
    audit_report: dict[str, Any]
    report_json: Path
    report_text: Path
    reports_removed: int
    runs_removed: int

    @property
    def updated(self) -> int:
        return sum(
            item.action == "updated"
            for site in self.sites
            for item in site.items
        )

    @property
    def skipped(self) -> int:
        return sum(
            item.action == "skipped"
            for site in self.sites
            for item in site.items
        )

    @property
    def failed(self) -> int:
        return sum(
            item.action in {"failed", "rolled_back"}
            for site in self.sites
            for item in site.items
        ) + sum(site.detection_error is not None for site in self.sites)

    @property
    def rolled_back(self) -> int:
        return sum(
            item.action == "rolled_back"
            for site in self.sites
            for item in site.items
        )


@contextmanager
def maintenance_lock(state_dir: Path) -> Iterator[None]:
    state_dir.mkdir(parents=True, exist_ok=True)
    lock_path = state_dir / "maintenance.lock"
    with lock_path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MaintenanceAlreadyRunning(
                f"Another maintenance run holds {lock_path}"
            ) from exc
        handle.seek(0)
        handle.truncate()
        handle.write(f"pid={os.getpid()}\n")
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _checked_updates(
    wordpress: WordPress,
    site_path: Path,
    kind: str,
) -> list[dict[str, Any]]:
    result = wordpress.wp(
        site_path,
        kind,
        "list",
        "--update=available",
        "--fields=name,status,version,update_version",
        "--format=json",
    )
    if not result.ok:
        output = "\n".join(filter(None, [result.stdout, result.stderr]))
        raise MaintenanceError(
            f"Could not list {kind} updates"
            + (f": {output}" if output else "")
        )
    try:
        payload = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise MaintenanceError(f"Could not parse {kind} update list") from exc
    if not isinstance(payload, list):
        raise MaintenanceError(f"Unexpected {kind} update-list format")
    return [item for item in payload if isinstance(item, dict)]


def _item_from_row(kind: str, row: dict[str, Any], action: str, message: str) -> MaintenanceItem:
    target_raw = row.get("update_version")
    target = str(target_raw).strip() if target_raw not in (None, "") else None
    return MaintenanceItem(
        kind=kind,
        name=str(row.get("name", "unknown")),
        status=str(row.get("status", "unknown")),
        current_version=str(row.get("version", "unknown")),
        target_version=target,
        action=action,
        message=message,
    )


def _detect_site_updates(
    wordpress: WordPress,
    site_path: Path,
) -> tuple[list[dict[str, Any]], list[MaintenanceItem]]:
    plugins = _checked_updates(wordpress, site_path, "plugin")
    themes = _checked_updates(wordpress, site_path, "theme")

    candidates: list[dict[str, Any]] = []
    skipped: list[MaintenanceItem] = []

    for row in sorted(plugins, key=lambda item: str(item.get("name", ""))):
        status = str(row.get("status", ""))
        target = str(row.get("update_version", "")).strip()
        name = str(row.get("name", "")).strip()
        if status == "inactive" and name and target:
            candidates.append(row)
        elif status != "inactive":
            skipped.append(
                _item_from_row(
                    "plugin",
                    row,
                    "skipped",
                    "Automatic maintenance currently permits only inactive plugins",
                )
            )
        else:
            skipped.append(
                _item_from_row(
                    "plugin",
                    row,
                    "skipped",
                    "The update source did not provide an exact target version",
                )
            )

    for row in sorted(themes, key=lambda item: str(item.get("name", ""))):
        skipped.append(
            _item_from_row(
                "theme",
                row,
                "skipped",
                "Automatic theme updates are not enabled",
            )
        )

    return candidates, skipped


def _write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(content, encoding="utf-8")
    os.chmod(temporary, 0o640)
    os.replace(temporary, path)


def _report_payload(
    generated_at: str,
    site_results: list[SiteMaintenance],
    audit_report: dict[str, Any],
) -> dict[str, Any]:
    items = [item for site in site_results for item in site.items]
    updated = sum(item.action == "updated" for item in items)
    skipped = sum(item.action == "skipped" for item in items)
    rolled_back = sum(item.action == "rolled_back" for item in items)
    failed = sum(item.action in {"failed", "rolled_back"} for item in items)
    failed += sum(site.detection_error is not None for site in site_results)
    return {
        "schema_version": 1,
        "kind": "maintenance",
        "generated_at": generated_at,
        "summary": {
            "sites": len(site_results),
            "updated": updated,
            "skipped": skipped,
            "failed": failed,
            "rolled_back": rolled_back,
            "audit_findings": audit_report.get("summary", {}).get("findings", 0),
            "audit_worst_severity": audit_report.get("summary", {}).get(
                "worst_severity", "INFO"
            ),
        },
        "maintenance_sites": [
            {
                "domain": site.domain,
                "detection_error": site.detection_error,
                "items": [asdict(item) for item in site.items],
            }
            for site in site_results
        ],
        "final_audit": audit_report,
    }


def render_maintenance_text(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "SOFTICO WORDPRESS GUARDIAN MAINTENANCE",
        f"Generated: {payload['generated_at']}",
        f"Sites: {summary['sites']}",
        f"Updated: {summary['updated']}",
        f"Skipped: {summary['skipped']}",
        f"Failed: {summary['failed']}",
        f"Rolled back: {summary['rolled_back']}",
        "",
    ]
    for site in payload["maintenance_sites"]:
        lines.append(f"[{site['domain']}]")
        if site.get("detection_error"):
            lines.append(f"- FAILED update detection: {site['detection_error']}")
        items = site.get("items", [])
        if not items and not site.get("detection_error"):
            lines.append("- No available updates")
        for item in items:
            target = item.get("target_version") or "unknown"
            label = (
                f"{item['kind']} {item['name']} "
                f"{item['current_version']} -> {target}"
            )
            lines.append(f"- {item['action'].upper()}: {label}")
            if item.get("message"):
                lines.append(f"  {item['message']}")
            if item.get("preparation_id"):
                lines.append(f"  Preparation ID: {item['preparation_id']}")
            if item.get("record_path"):
                lines.append(f"  Record: {item['record_path']}")
        lines.append("")

    lines.extend(
        [
            "FINAL SECURITY AUDIT",
            "",
            render_text(payload["final_audit"]).rstrip(),
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def write_maintenance_report(
    report_dir: Path,
    payload: dict[str, Any],
    *,
    stamp: str | None = None,
) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    report_stamp = stamp or datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = report_dir / f"maintenance-{report_stamp}.json"
    text_path = report_dir / f"maintenance-{report_stamp}.txt"
    json_text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    text = render_maintenance_text(payload)
    _write_atomic(json_path, json_text)
    _write_atomic(text_path, text)
    _write_atomic(report_dir / "latest.json", json_text)
    _write_atomic(report_dir / "latest.txt", text)
    return json_path, text_path


def run_maintenance(
    config: GuardianConfig,
    *,
    now: datetime | None = None,
) -> MaintenanceResult:
    started = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    generated_at = started.isoformat()
    runner = CommandRunner(config.backup_timeout)
    wordpress = WordPress(config, runner)
    sites = discover_sites(config)
    site_results: list[SiteMaintenance] = []
    updates_attempted = 0

    for site in sites:
        site_result = SiteMaintenance(domain=site.domain)
        site_results.append(site_result)
        try:
            candidates, skipped = _detect_site_updates(wordpress, site.path)
            site_result.items.extend(skipped)
        except Exception as exc:
            site_result.detection_error = str(exc)
            continue

        for row in candidates:
            name = str(row.get("name", "")).strip()
            current = str(row.get("version", "unknown")).strip()
            target = str(row.get("update_version", "")).strip()
            status = str(row.get("status", "unknown")).strip()
            if updates_attempted >= MAX_AUTOMATIC_UPDATES:
                site_result.items.append(
                    MaintenanceItem(
                        kind="plugin",
                        name=name,
                        status=status,
                        current_version=current,
                        target_version=target,
                        action="skipped",
                        message=(
                            "Per-run automatic update safety limit reached: "
                            f"{MAX_AUTOMATIC_UPDATES}"
                        ),
                    )
                )
                continue

            updates_attempted += 1
            item = MaintenanceItem(
                kind="plugin",
                name=name,
                status=status,
                current_version=current,
                target_version=target,
                action="failed",
            )
            site_result.items.append(item)
            preparation = None
            try:
                preparation = prepare_component_update(
                    config,
                    site,
                    wordpress,
                    runner,
                    kind="plugin",
                    name=name,
                    target_version=target,
                )
                item.preparation_id = preparation.preparation_id
                item.checkpoint_directory = str(preparation.directory)
                applied = apply_prepared_plugin_update(
                    config,
                    site,
                    wordpress,
                    runner,
                    preparation_id=preparation.preparation_id,
                    kind="plugin",
                    name=name,
                    target_version=target,
                )
                item.action = "updated"
                item.message = "Update completed and all guarded post-checks passed"
                item.record_path = str(applied.record_path)
            except (UpdatePreparationError, UpdateApplyError, BackupError, OSError) as exc:
                item.message = str(exc)
                if preparation is not None:
                    rollback = preparation.directory / "update-rollback.json"
                    if rollback.is_file():
                        item.action = "rolled_back"
                        item.record_path = str(rollback)
                # Stop changing this site after the first failed/rolled-back item.
                break

    audits = audit_all(config)
    audit_report = build_report(audits)
    payload = _report_payload(generated_at, site_results, audit_report)
    json_path, text_path = write_maintenance_report(config.report_dir, payload)

    storage = Storage(config.state_dir / "guardian.sqlite3")
    run_id = storage.start_run(generated_at, "maintenance-run")
    for audit in audits:
        storage.save_site_audit(run_id, audit)
    storage.finish_run(
        run_id,
        datetime.now(timezone.utc).isoformat(),
        str(json_path),
    )

    cutoff = business_day_cutoff(config.retention_business_days)
    reports_removed = prune_report_files(config.report_dir, cutoff)
    runs_removed = storage.prune_runs_before(cutoff.isoformat())

    return MaintenanceResult(
        generated_at=generated_at,
        sites=site_results,
        audit_report=audit_report,
        report_json=json_path,
        report_text=text_path,
        reports_removed=reports_removed,
        runs_removed=runs_removed,
    )


def _write_failure_report(config: GuardianConfig, exc: Exception) -> tuple[Path, Path]:
    generated_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "schema_version": 1,
        "kind": "maintenance",
        "generated_at": generated_at,
        "summary": {
            "sites": 0,
            "updated": 0,
            "skipped": 0,
            "failed": 1,
            "rolled_back": 0,
            "audit_findings": 0,
            "audit_worst_severity": "CRITICAL",
        },
        "maintenance_sites": [
            {
                "domain": "guardian-runtime",
                "detection_error": str(exc),
                "items": [],
            }
        ],
        "final_audit": {
            "generated_at": generated_at,
            "summary": {
                "sites": 0,
                "findings": 1,
                "severities": {"CRITICAL": 1},
                "worst_severity": "CRITICAL",
            },
            "sites": [],
        },
    }
    return write_maintenance_report(config.report_dir, payload)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="wp-guardian-maintenance")
    root.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        config = load_config(args.config)
    except (OSError, ValueError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    try:
        with maintenance_lock(config.state_dir):
            result = run_maintenance(config)
    except MaintenanceAlreadyRunning as exc:
        print(f"Maintenance not started: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        try:
            _, text_path = _write_failure_report(config, exc)
            print(f"Maintenance failed; fresh failure report saved: {text_path}")
        except Exception as report_exc:
            print(
                f"Maintenance failed: {exc}; failure report also failed: {report_exc}",
                file=sys.stderr,
            )
            return 1
        return 2

    print(result.report_text.read_text(encoding="utf-8"), end="")
    print(f"Saved: {result.report_text}", file=sys.stderr)
    print(
        "Retention cleanup: "
        f"business_days={config.retention_business_days}, "
        f"reports_removed={result.reports_removed}, runs_removed={result.runs_removed}",
        file=sys.stderr,
    )
    worst = result.audit_report.get("summary", {}).get("worst_severity", "INFO")
    return 2 if result.failed or worst in {"HIGH", "CRITICAL"} else 0


if __name__ == "__main__":
    raise SystemExit(main())

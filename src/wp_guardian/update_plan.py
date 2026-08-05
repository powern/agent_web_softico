from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from .backup import BackupError
from .backup_verify import BackupVerificationResult, verify_database_backup
from .config import GuardianConfig
from .models import Site
from .runner import CommandRunner
from .wordpress import WordPress


@dataclass(slots=True)
class PlannedUpdate:
    kind: str
    name: str
    status: str
    current_version: str
    target_version: str | None


@dataclass(slots=True)
class UpdatePlanResult:
    domain: str
    generated_at: str
    site_path: str
    http_status: int | None
    http_url: str | None
    http_time: float | None
    core_version: str | None
    core_checksum_ok: bool
    backup_directory: str | None
    backup_created_at: str | None
    backup_age_seconds: int | None
    updates: list[PlannedUpdate]
    blockers: list[str]
    warnings: list[str]
    ready: bool

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["updates"] = [asdict(item) for item in self.updates]
        return payload


def _http_preflight(
    config: GuardianConfig,
    site: Site,
    runner: CommandRunner,
) -> tuple[int | None, str | None, float | None, str | None]:
    result = runner.run(
        [
            config.curl,
            "-kLsS",
            "-o",
            "/dev/null",
            "-w",
            '{"code":%{http_code},"time":%{time_total},"url":"%{url_effective}"}',
            "--max-time",
            str(config.http_timeout),
            f"https://{site.domain}/",
        ],
        timeout=config.http_timeout + 5,
    )
    if not result.ok:
        output = "\n".join(filter(None, [result.stdout, result.stderr]))
        return None, None, None, f"HTTPS preflight failed{': ' + output if output else ''}"

    try:
        payload = json.loads(result.stdout)
        code = int(payload.get("code", 0))
        elapsed = float(payload.get("time", 0.0))
        url = str(payload.get("url", "")) or None
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        return None, None, None, f"Could not parse HTTPS preflight result: {exc}"

    if code < 200 or code >= 400:
        return code, url, elapsed, f"HTTPS preflight returned status {code}"
    return code, url, elapsed, None


def _normalize_updates(kind: str, rows: list[dict[str, Any]]) -> list[PlannedUpdate]:
    updates: list[PlannedUpdate] = []
    for row in rows:
        name = str(row.get("name", "")).strip()
        current = str(row.get("version", "")).strip()
        target_raw = row.get("update_version")
        target = str(target_raw).strip() if target_raw not in (None, "") else None
        if not name:
            continue
        updates.append(
            PlannedUpdate(
                kind=kind,
                name=name,
                status=str(row.get("status", "unknown")),
                current_version=current or "unknown",
                target_version=target,
            )
        )
    return updates


def build_update_plan(
    config: GuardianConfig,
    site: Site,
    wordpress: WordPress,
    runner: CommandRunner,
    *,
    now: datetime | None = None,
) -> UpdatePlanResult:
    generated_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    blockers: list[str] = []
    warnings: list[str] = []

    http_status, http_url, http_time, http_error = _http_preflight(config, site, runner)
    if http_error:
        blockers.append(http_error)

    core_version = wordpress.core_version(site.path)
    if not core_version:
        blockers.append("Could not read the current WordPress core version")

    core_checksum = wordpress.verify_core(site.path)
    core_checksum_ok = core_checksum.ok
    if not core_checksum_ok:
        output = "\n".join(filter(None, [core_checksum.stdout, core_checksum.stderr]))
        blockers.append(
            "WordPress core checksum verification failed"
            + (f": {output}" if output else "")
        )

    backup: BackupVerificationResult | None = None
    try:
        backup = verify_database_backup(config, site, wordpress)
    except (BackupError, OSError) as exc:
        blockers.append(f"Latest database backup is not verified: {exc}")

    backup_age_seconds: int | None = None
    if backup is not None:
        backup_time = datetime.fromisoformat(backup.created_at.replace("Z", "+00:00"))
        backup_age_seconds = max(0, int((generated_at - backup_time).total_seconds()))

    updates = [
        *_normalize_updates("plugin", wordpress.list_updates(site.path, "plugin")),
        *_normalize_updates("theme", wordpress.list_updates(site.path, "theme")),
    ]
    updates.sort(key=lambda item: (item.kind, item.name.lower()))

    for item in updates:
        if not item.target_version:
            blockers.append(
                f"Target version is unavailable for {item.kind} {item.name} "
                f"(current {item.current_version})"
            )

    if not updates:
        warnings.append("No plugin or theme updates are currently available")

    # Ready describes the safety preflight, not whether there is work to perform.
    # A fully healthy site with zero updates is ready and simply has no update actions.
    ready = not blockers
    return UpdatePlanResult(
        domain=site.domain,
        generated_at=generated_at.isoformat(),
        site_path=str(site.path),
        http_status=http_status,
        http_url=http_url,
        http_time=http_time,
        core_version=core_version,
        core_checksum_ok=core_checksum_ok,
        backup_directory=str(backup.directory) if backup else None,
        backup_created_at=backup.created_at if backup else None,
        backup_age_seconds=backup_age_seconds,
        updates=updates,
        blockers=blockers,
        warnings=warnings,
        ready=ready,
    )

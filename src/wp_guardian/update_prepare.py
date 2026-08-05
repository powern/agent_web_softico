from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .backup import BackupError, create_database_backup, prune_completed_backups
from .backup_verify import verify_database_backup
from .config import GuardianConfig
from .models import Site
from .runner import CommandRunner
from .update_plan import PlannedUpdate, build_update_plan
from .wordpress import WordPress


COMPONENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
VALID_KINDS = {"plugin", "theme"}


class UpdatePreparationError(BackupError):
    pass


@dataclass(slots=True)
class UpdatePreparationResult:
    domain: str
    directory: Path
    manifest_path: Path
    preparation_id: str
    component_kind: str
    component_name: str
    current_version: str
    target_version: str
    component_archive: Path
    component_archive_size: int
    component_archive_sha256: str
    database_path: Path
    database_sha256: str
    backups_removed: int


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _find_update(
    rows: list[dict[str, Any]],
    kind: str,
    name: str,
    target_version: str,
) -> PlannedUpdate:
    matches: list[PlannedUpdate] = []
    for row in rows:
        row_name = str(row.get("name", "")).strip()
        if row_name != name:
            continue
        current = str(row.get("version", "")).strip() or "unknown"
        target_raw = row.get("update_version")
        target = str(target_raw).strip() if target_raw not in (None, "") else ""
        matches.append(
            PlannedUpdate(
                kind=kind,
                name=row_name,
                status=str(row.get("status", "unknown")),
                current_version=current,
                target_version=target or None,
            )
        )

    if len(matches) != 1:
        raise UpdatePreparationError(
            f"Exactly one available {kind} update is required for {name}; found {len(matches)}"
        )
    update = matches[0]
    if update.target_version != target_version:
        raise UpdatePreparationError(
            f"Target version mismatch for {kind} {name}: "
            f"requested {target_version}, available {update.target_version or 'unknown'}"
        )
    return update


def _component_path(site: Site, kind: str, name: str) -> Path:
    content_root = site.path / "wp-content"
    if kind == "theme":
        candidate = content_root / "themes" / name
        if not candidate.is_dir():
            raise UpdatePreparationError(f"Theme directory does not exist: {candidate}")
    else:
        plugin_root = content_root / "plugins"
        directory = plugin_root / name
        single_file = plugin_root / f"{name}.php"
        if directory.is_dir():
            candidate = directory
        elif single_file.is_file():
            candidate = single_file
        else:
            raise UpdatePreparationError(
                f"Plugin files do not exist as {directory} or {single_file}"
            )

    if candidate.is_symlink():
        raise UpdatePreparationError(f"Component path must not be a symlink: {candidate}")

    expected_root = (content_root / ("plugins" if kind == "plugin" else "themes")).resolve()
    resolved = candidate.resolve()
    try:
        resolved.relative_to(expected_root)
    except ValueError as exc:
        raise UpdatePreparationError(
            f"Component path escapes the expected {kind} directory: {candidate}"
        ) from exc

    paths = [candidate]
    if candidate.is_dir():
        paths.extend(candidate.rglob("*"))
    for path in paths:
        if path.is_symlink():
            raise UpdatePreparationError(
                f"Component snapshot refuses symlink entries: {path}"
            )
        if not path.is_dir() and not path.is_file():
            raise UpdatePreparationError(
                f"Component snapshot refuses special filesystem entries: {path}"
            )
    return candidate


def _archive_component(component_path: Path, target: Path) -> tuple[int, str]:
    def normalize(member: tarfile.TarInfo) -> tarfile.TarInfo:
        member.uid = 0
        member.gid = 0
        member.uname = ""
        member.gname = ""
        return member

    with tarfile.open(target, mode="w:gz", compresslevel=6) as archive:
        archive.add(
            component_path,
            arcname=component_path.name,
            recursive=True,
            filter=normalize,
        )
    os.chmod(target, 0o600)
    size = target.stat().st_size
    if size <= 0:
        raise UpdatePreparationError("Component snapshot archive is empty")
    return size, _sha256(target)


def _canonical_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def prepare_component_update(
    config: GuardianConfig,
    site: Site,
    wordpress: WordPress,
    runner: CommandRunner,
    *,
    kind: str,
    name: str,
    target_version: str,
    now: datetime | None = None,
) -> UpdatePreparationResult:
    if kind not in VALID_KINDS:
        raise UpdatePreparationError(f"Unsupported component kind: {kind}")
    if not COMPONENT_NAME.fullmatch(name):
        raise UpdatePreparationError(f"Invalid component name: {name}")
    if not target_version.strip() or len(target_version) > 100:
        raise UpdatePreparationError("Target version must be a non-empty exact version")

    initial_update = _find_update(
        wordpress.list_updates(site.path, kind),
        kind,
        name,
        target_version,
    )
    component_path = _component_path(site, kind, name)

    backup = None
    finalized = False
    generated_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    try:
        backup = create_database_backup(
            config,
            site,
            wordpress,
            now=generated_at,
            apply_retention=False,
        )
        verified = verify_database_backup(
            config,
            site,
            wordpress,
            backup_name=backup.directory.name,
        )

        plan = build_update_plan(
            config,
            site,
            wordpress,
            runner,
            now=generated_at,
        )
        if plan.blockers:
            raise UpdatePreparationError(
                "Update preflight has blockers: " + "; ".join(plan.blockers)
            )
        if plan.backup_directory != str(backup.directory):
            raise UpdatePreparationError(
                "Fresh database backup was not selected by the update preflight"
            )

        planned = [
            item
            for item in plan.updates
            if item.kind == kind and item.name == name
        ]
        if len(planned) != 1 or planned[0].target_version != target_version:
            raise UpdatePreparationError(
                f"Available update changed during preparation for {kind} {name}"
            )
        if planned[0].current_version != initial_update.current_version:
            raise UpdatePreparationError(
                f"Current version changed during preparation for {kind} {name}"
            )

        archive_path = backup.directory / f"component-{kind}-{name}.tar.gz"
        archive_size, archive_sha = _archive_component(component_path, archive_path)

        manifest_payload: dict[str, Any] = {
            "schema_version": 1,
            "created_at": generated_at.isoformat(),
            "domain": site.domain,
            "site_path": str(site.path),
            "component": {
                "kind": kind,
                "name": name,
                "status": planned[0].status,
                "current_version": planned[0].current_version,
                "target_version": target_version,
                "source_path": str(component_path),
                "archive": {
                    "filename": archive_path.name,
                    "size": archive_size,
                    "sha256": archive_sha,
                },
            },
            "database": {
                "backup_directory": backup.directory.name,
                "filename": backup.database_path.name,
                "size": verified.compressed_size,
                "sha256": verified.sha256,
                "table_prefix": verified.table_prefix,
                "matching_tables": verified.matching_tables,
            },
            "preflight": {
                "https_status": plan.http_status,
                "https_url": plan.http_url,
                "https_time": plan.http_time,
                "core_version": plan.core_version,
                "core_checksum_ok": plan.core_checksum_ok,
            },
        }
        preparation_id = _canonical_digest(manifest_payload)
        manifest_payload["preparation_id"] = preparation_id
        manifest_path = backup.directory / "update-preparation.json"
        manifest_path.write_text(
            json.dumps(manifest_payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(manifest_path, 0o600)
        finalized = True

        removed = prune_completed_backups(
            backup.directory.parent,
            site.domain,
            config.backup_keep_last,
            protect=backup.directory,
        )
        return UpdatePreparationResult(
            domain=site.domain,
            directory=backup.directory,
            manifest_path=manifest_path,
            preparation_id=preparation_id,
            component_kind=kind,
            component_name=name,
            current_version=planned[0].current_version,
            target_version=target_version,
            component_archive=archive_path,
            component_archive_size=archive_size,
            component_archive_sha256=archive_sha,
            database_path=backup.database_path,
            database_sha256=verified.sha256,
            backups_removed=removed,
        )
    except Exception:
        if backup is not None and not finalized:
            shutil.rmtree(backup.directory, ignore_errors=True)
        raise

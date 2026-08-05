from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .backup import BackupError
from .backup_verify import BACKUP_DIRECTORY_NAME, verify_database_backup
from .config import GuardianConfig
from .models import Site
from .runner import CommandRunner
from .update_plan import build_update_plan
from .wordpress import WordPress


COMPONENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
MAX_PREPARATION_AGE_SECONDS = 3600


class UpdateApplyError(BackupError):
    pass


@dataclass(slots=True)
class UpdateApplyResult:
    domain: str
    preparation_id: str
    directory: Path
    record_path: Path
    component_name: str
    previous_version: str
    target_version: str
    status: str
    https_status: int | None
    core_version: str | None
    plugin_checksum_verified: bool
    update_output: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UpdateApplyError(f"Could not read update preparation manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise UpdateApplyError(f"Update preparation manifest must contain a JSON object: {path}")
    return payload


def _find_preparation_directory(
    config: GuardianConfig,
    domain: str,
    preparation_id: str,
) -> tuple[Path, dict[str, Any]]:
    if not SHA256_HEX.fullmatch(preparation_id):
        raise UpdateApplyError("Preparation ID must be exactly 64 lowercase hexadecimal characters")

    domain_root = config.backup_dir / domain
    if domain_root.is_symlink() or not domain_root.is_dir():
        raise UpdateApplyError(f"No private backup directory exists for {domain}")

    matches: list[tuple[Path, dict[str, Any]]] = []
    for directory in domain_root.iterdir():
        if (
            not BACKUP_DIRECTORY_NAME.fullmatch(directory.name)
            or directory.is_symlink()
            or not directory.is_dir()
        ):
            continue
        manifest_path = directory / "update-preparation.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            continue
        payload = _load_json(manifest_path)
        if payload.get("preparation_id") == preparation_id:
            matches.append((directory, payload))

    if len(matches) != 1:
        raise UpdateApplyError(
            f"Exactly one update preparation must match ID {preparation_id}; found {len(matches)}"
        )
    return matches[0]


def _require_private_mode(path: Path, *, directory: bool = False) -> None:
    if path.is_symlink():
        raise UpdateApplyError(f"Checkpoint path must not be a symlink: {path}")
    if directory and not path.is_dir():
        raise UpdateApplyError(f"Checkpoint directory is missing: {path}")
    if not directory and not path.is_file():
        raise UpdateApplyError(f"Checkpoint file is missing: {path}")
    if path.stat().st_mode & 0o077:
        raise UpdateApplyError(f"Checkpoint permissions are too broad: {path}")


def _safe_int(value: Any, label: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise UpdateApplyError(f"Invalid integer value for {label}") from exc
    if result < 0:
        raise UpdateApplyError(f"Invalid negative value for {label}")
    return result


def _validate_archive_members(archive_path: Path, expected_top: str) -> None:
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if not members:
                raise UpdateApplyError("Component snapshot archive is empty")
            for member in members:
                member_path = Path(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise UpdateApplyError(
                        f"Component snapshot contains an unsafe path: {member.name}"
                    )
                if not member_path.parts or member_path.parts[0] != expected_top:
                    raise UpdateApplyError(
                        f"Component snapshot contains an unexpected top-level entry: {member.name}"
                    )
                if not member.isdir() and not member.isfile():
                    raise UpdateApplyError(
                        f"Component snapshot contains an unsupported entry type: {member.name}"
                    )
    except (OSError, tarfile.TarError) as exc:
        raise UpdateApplyError(f"Component snapshot is not a valid tar.gz archive: {exc}") from exc


def _validate_preparation(
    config: GuardianConfig,
    site: Site,
    wordpress: WordPress,
    *,
    preparation_id: str,
    kind: str,
    name: str,
    target_version: str,
    now: datetime,
) -> tuple[Path, dict[str, Any], Path, Path, str, str]:
    if kind != "plugin":
        raise UpdateApplyError("Initial guarded apply supports only kind=plugin")
    if not COMPONENT_NAME.fullmatch(name):
        raise UpdateApplyError(f"Invalid plugin name: {name}")
    if not target_version.strip() or len(target_version) > 100:
        raise UpdateApplyError("Target version must be a non-empty exact version")

    directory, payload = _find_preparation_directory(config, site.domain, preparation_id)
    manifest_path = directory / "update-preparation.json"
    _require_private_mode(directory, directory=True)
    _require_private_mode(manifest_path)

    if payload.get("schema_version") != 1:
        raise UpdateApplyError("Unsupported update preparation schema_version")
    if payload.get("domain") != site.domain:
        raise UpdateApplyError("Update preparation domain does not match")
    if payload.get("site_path") != str(site.path):
        raise UpdateApplyError("Update preparation site path does not match")

    canonical = dict(payload)
    recorded_id = canonical.pop("preparation_id", None)
    if recorded_id != preparation_id or _canonical_digest(canonical) != preparation_id:
        raise UpdateApplyError("Update preparation ID does not match the manifest contents")

    try:
        created_at = datetime.fromisoformat(
            str(payload["created_at"]).replace("Z", "+00:00")
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise UpdateApplyError("Update preparation has an invalid created_at value") from exc
    if created_at.tzinfo is None:
        raise UpdateApplyError("Update preparation created_at must include a timezone")
    age = int((now - created_at.astimezone(timezone.utc)).total_seconds())
    if age < -300:
        raise UpdateApplyError("Update preparation timestamp is unexpectedly in the future")
    if age > MAX_PREPARATION_AGE_SECONDS:
        raise UpdateApplyError(
            f"Update preparation is too old: {age} seconds; maximum is "
            f"{MAX_PREPARATION_AGE_SECONDS}"
        )

    component = payload.get("component")
    if not isinstance(component, dict):
        raise UpdateApplyError("Update preparation component section is missing")
    if component.get("kind") != kind or component.get("name") != name:
        raise UpdateApplyError("Requested component does not match the preparation")
    if component.get("status") != "inactive":
        raise UpdateApplyError("Initial guarded apply permits only an inactive plugin")
    previous_version = str(component.get("current_version", "")).strip()
    recorded_target = str(component.get("target_version", "")).strip()
    if not previous_version or recorded_target != target_version:
        raise UpdateApplyError("Requested target version does not match the preparation")

    plugin_root = (site.path / "wp-content" / "plugins").resolve()
    source_path = Path(str(component.get("source_path", "")))
    if source_path.is_symlink() or not source_path.exists():
        raise UpdateApplyError(f"Prepared plugin path is missing or unsafe: {source_path}")
    try:
        source_path.resolve().relative_to(plugin_root)
    except ValueError as exc:
        raise UpdateApplyError("Prepared plugin path escapes wp-content/plugins") from exc
    expected_paths = {
        plugin_root / name,
        plugin_root / f"{name}.php",
    }
    if source_path.resolve() not in expected_paths:
        raise UpdateApplyError("Prepared plugin source path does not match the exact plugin slug")

    archive = component.get("archive")
    if not isinstance(archive, dict):
        raise UpdateApplyError("Update preparation component archive section is missing")
    archive_filename = str(archive.get("filename", ""))
    if archive_filename != f"component-plugin-{name}.tar.gz":
        raise UpdateApplyError("Unexpected component snapshot filename")
    archive_path = directory / archive_filename
    _require_private_mode(archive_path)
    expected_archive_size = _safe_int(archive.get("size"), "component archive size")
    expected_archive_sha = str(archive.get("sha256", "")).lower()
    if not SHA256_HEX.fullmatch(expected_archive_sha):
        raise UpdateApplyError("Invalid component snapshot SHA-256 in preparation")
    if archive_path.stat().st_size != expected_archive_size:
        raise UpdateApplyError("Component snapshot size does not match the preparation")
    if _sha256(archive_path) != expected_archive_sha:
        raise UpdateApplyError("Component snapshot SHA-256 does not match the preparation")
    _validate_archive_members(archive_path, source_path.name)

    database = payload.get("database")
    if not isinstance(database, dict):
        raise UpdateApplyError("Update preparation database section is missing")
    if database.get("backup_directory") != directory.name:
        raise UpdateApplyError("Prepared database backup directory does not match")
    verified = verify_database_backup(
        config,
        site,
        wordpress,
        backup_name=directory.name,
    )
    expected_db_sha = str(database.get("sha256", "")).lower()
    if verified.sha256 != expected_db_sha:
        raise UpdateApplyError("Verified database SHA-256 does not match the preparation")
    if verified.compressed_size != _safe_int(database.get("size"), "database size"):
        raise UpdateApplyError("Verified database size does not match the preparation")

    applied_record = directory / "update-applied.json"
    rollback_record = directory / "update-rollback.json"
    if applied_record.exists() or rollback_record.exists():
        raise UpdateApplyError("This preparation already has an apply or rollback record")

    return directory, payload, source_path, archive_path, previous_version, recorded_target


def _component_state(wordpress: WordPress, site: Site, name: str) -> tuple[str, str]:
    info = wordpress.component_info(site.path, "plugin", name)
    if not info:
        raise UpdateApplyError(f"Could not read current plugin state for {name}")
    status = str(info.get("status", "")).strip()
    version = str(info.get("version", "")).strip()
    if not status or not version:
        raise UpdateApplyError(f"Plugin state is incomplete for {name}")
    return status, version


def _require_preflight(
    config: GuardianConfig,
    site: Site,
    wordpress: WordPress,
    runner: CommandRunner,
    *,
    directory: Path,
    name: str,
    current_version: str,
    target_version: str,
    now: datetime,
) -> tuple[int | None, str | None]:
    plan = build_update_plan(config, site, wordpress, runner, now=now)
    if plan.blockers:
        raise UpdateApplyError("Update preflight has blockers: " + "; ".join(plan.blockers))
    if plan.backup_directory != str(directory):
        raise UpdateApplyError("Prepared checkpoint is no longer the newest verified backup")
    matches = [
        item
        for item in plan.updates
        if item.kind == "plugin" and item.name == name
    ]
    if len(matches) != 1:
        raise UpdateApplyError(f"Prepared plugin update is no longer uniquely available: {name}")
    item = matches[0]
    if (
        item.status != "inactive"
        or item.current_version != current_version
        or item.target_version != target_version
    ):
        raise UpdateApplyError("Current plugin update no longer matches the preparation")
    return plan.http_status, plan.core_version


def _restore_component(source_path: Path, archive_path: Path) -> None:
    parent = source_path.parent
    temporary = parent / f".wp-guardian-restore-{secrets.token_hex(8)}"
    displaced = parent / f".{source_path.name}.failed-{secrets.token_hex(8)}"
    temporary.mkdir(mode=0o700)
    moved_current = False
    try:
        _validate_archive_members(archive_path, source_path.name)
        with tarfile.open(archive_path, mode="r:gz") as archive:
            archive.extractall(temporary)
        restored = temporary / source_path.name
        if restored.is_symlink() or not restored.exists():
            raise UpdateApplyError("Restored component is missing or unsafe")
        paths = [restored]
        if restored.is_dir():
            paths.extend(restored.rglob("*"))
        for path in paths:
            if path.is_symlink() or (not path.is_dir() and not path.is_file()):
                raise UpdateApplyError(f"Restored component contains an unsafe entry: {path}")

        if source_path.exists() or source_path.is_symlink():
            os.replace(source_path, displaced)
            moved_current = True
        try:
            os.replace(restored, source_path)
        except Exception:
            if moved_current:
                os.replace(displaced, source_path)
                moved_current = False
            raise
        if moved_current:
            if displaced.is_dir():
                shutil.rmtree(displaced)
            else:
                displaced.unlink()
            moved_current = False
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
        if moved_current and displaced.exists() and not source_path.exists():
            os.replace(displaced, source_path)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o600)


def apply_prepared_plugin_update(
    config: GuardianConfig,
    site: Site,
    wordpress: WordPress,
    runner: CommandRunner,
    *,
    preparation_id: str,
    kind: str,
    name: str,
    target_version: str,
    now: datetime | None = None,
) -> UpdateApplyResult:
    applied_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    (
        directory,
        _payload,
        source_path,
        archive_path,
        previous_version,
        recorded_target,
    ) = _validate_preparation(
        config,
        site,
        wordpress,
        preparation_id=preparation_id,
        kind=kind,
        name=name,
        target_version=target_version,
        now=applied_at,
    )

    status, version = _component_state(wordpress, site, name)
    if status != "inactive" or version != previous_version:
        raise UpdateApplyError(
            f"Plugin state changed after preparation: status={status}, version={version}"
        )
    _require_preflight(
        config,
        site,
        wordpress,
        runner,
        directory=directory,
        name=name,
        current_version=previous_version,
        target_version=recorded_target,
        now=applied_at,
    )

    update_attempted = False
    update_output = ""
    try:
        update_attempted = True
        update_result = wordpress.update_plugin(
            site.path,
            name,
            recorded_target,
            timeout=config.backup_timeout,
        )
        update_output = "\n".join(filter(None, [update_result.stdout, update_result.stderr]))
        if not update_result.ok:
            raise UpdateApplyError(
                f"WP-CLI plugin update failed{': ' + update_output if update_output else ''}"
            )

        post_status, post_version = _component_state(wordpress, site, name)
        if post_status != "inactive" or post_version != recorded_target:
            raise UpdateApplyError(
                "Post-update plugin state mismatch: "
                f"status={post_status}, version={post_version}, expected inactive/{recorded_target}"
            )

        post_plan = build_update_plan(config, site, wordpress, runner, now=applied_at)
        if post_plan.blockers:
            raise UpdateApplyError(
                "Post-update checks have blockers: " + "; ".join(post_plan.blockers)
            )
        if post_plan.backup_directory != str(directory):
            raise UpdateApplyError("Prepared checkpoint changed during the update")

        checksum_verified = False
        if wordpress.has_checksum_manifest(name, recorded_target):
            checksum = wordpress.verify_plugin_checksum(
                site.path,
                name,
                timeout=max(config.command_timeout, 45),
            )
            if not checksum.ok:
                output = "\n".join(filter(None, [checksum.stdout, checksum.stderr]))
                raise UpdateApplyError(
                    "Updated plugin checksum verification failed"
                    + (f": {output}" if output else "")
                )
            checksum_verified = True

        record_path = directory / "update-applied.json"
        _write_json(
            record_path,
            {
                "schema_version": 1,
                "applied_at": applied_at.isoformat(),
                "domain": site.domain,
                "preparation_id": preparation_id,
                "component": {
                    "kind": "plugin",
                    "name": name,
                    "status": post_status,
                    "previous_version": previous_version,
                    "target_version": recorded_target,
                },
                "postflight": {
                    "https_status": post_plan.http_status,
                    "https_url": post_plan.http_url,
                    "https_time": post_plan.http_time,
                    "core_version": post_plan.core_version,
                    "core_checksum_ok": post_plan.core_checksum_ok,
                    "plugin_checksum_verified": checksum_verified,
                },
                "wp_cli_output": update_output,
                "rolled_back": False,
            },
        )
        return UpdateApplyResult(
            domain=site.domain,
            preparation_id=preparation_id,
            directory=directory,
            record_path=record_path,
            component_name=name,
            previous_version=previous_version,
            target_version=recorded_target,
            status=post_status,
            https_status=post_plan.http_status,
            core_version=post_plan.core_version,
            plugin_checksum_verified=checksum_verified,
            update_output=update_output,
        )
    except Exception as exc:
        if not update_attempted:
            raise
        rollback_error: Exception | None = None
        try:
            _restore_component(source_path, archive_path)
            rollback_status, rollback_version = _component_state(wordpress, site, name)
            if rollback_status != "inactive" or rollback_version != previous_version:
                raise UpdateApplyError(
                    "Automatic rollback restored unexpected plugin state: "
                    f"status={rollback_status}, version={rollback_version}"
                )
            core = wordpress.verify_core(site.path)
            if not core.ok:
                raise UpdateApplyError("WordPress core checksum failed after automatic rollback")
            rollback_plan = build_update_plan(config, site, wordpress, runner, now=applied_at)
            if rollback_plan.blockers:
                raise UpdateApplyError(
                    "Post-rollback checks have blockers: " + "; ".join(rollback_plan.blockers)
                )
            _write_json(
                directory / "update-rollback.json",
                {
                    "schema_version": 1,
                    "rolled_back_at": datetime.now(timezone.utc).isoformat(),
                    "domain": site.domain,
                    "preparation_id": preparation_id,
                    "component": {
                        "kind": "plugin",
                        "name": name,
                        "restored_version": rollback_version,
                        "status": rollback_status,
                    },
                    "failure": str(exc),
                    "wp_cli_output": update_output,
                    "rolled_back": True,
                },
            )
        except Exception as rollback_exc:
            rollback_error = rollback_exc

        if rollback_error is not None:
            raise UpdateApplyError(
                f"Update failed: {exc}. Automatic file rollback also failed: {rollback_error}"
            ) from rollback_error
        raise UpdateApplyError(
            f"Update failed and the plugin snapshot was restored automatically: {exc}"
        ) from exc

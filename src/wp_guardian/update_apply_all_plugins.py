from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .backup_verify import verify_database_backup
from .config import GuardianConfig
from .models import Site
from .runner import CommandRunner
from .update_apply import (
    COMPONENT_NAME,
    MAX_PREPARATION_AGE_SECONDS,
    SHA256_HEX,
    UpdateApplyError,
    UpdateApplyResult,
    _canonical_digest,
    _component_state,
    _find_preparation_directory,
    _require_private_mode,
    _restore_component,
    _safe_int,
    _sha256,
    _validate_archive_members,
    _write_json,
)
from .update_plan import build_update_plan
from .wordpress import WordPress

ALLOWED_PLUGIN_STATUSES = {"active", "inactive"}


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
) -> tuple[Path, dict[str, Any], Path, Path, str, str, str]:
    if kind != "plugin":
        raise UpdateApplyError("Guarded apply supports only kind=plugin")
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

    expected_status = str(component.get("status", "")).strip()
    if expected_status not in ALLOWED_PLUGIN_STATUSES:
        raise UpdateApplyError(
            "Automatic plugin apply requires status active or inactive; "
            f"prepared status is {expected_status or 'missing'}"
        )

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
    expected_paths = {plugin_root / name, plugin_root / f"{name}.php"}
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

    if (directory / "update-applied.json").exists() or (
        directory / "update-rollback.json"
    ).exists():
        raise UpdateApplyError("This preparation already has an apply or rollback record")

    return (
        directory,
        payload,
        source_path,
        archive_path,
        previous_version,
        recorded_target,
        expected_status,
    )


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
    expected_status: str,
    now: datetime,
) -> tuple[int | None, str | None]:
    plan = build_update_plan(config, site, wordpress, runner, now=now)
    if plan.blockers:
        raise UpdateApplyError("Update preflight has blockers: " + "; ".join(plan.blockers))
    if plan.backup_directory != str(directory):
        raise UpdateApplyError("Prepared checkpoint is no longer the newest verified backup")
    matches = [
        item for item in plan.updates if item.kind == "plugin" and item.name == name
    ]
    if len(matches) != 1:
        raise UpdateApplyError(f"Prepared plugin update is no longer uniquely available: {name}")
    item = matches[0]
    if (
        item.status != expected_status
        or item.current_version != current_version
        or item.target_version != target_version
    ):
        raise UpdateApplyError("Current plugin update no longer matches the preparation")
    return plan.http_status, plan.core_version


def _restore_status(
    wordpress: WordPress,
    site: Site,
    name: str,
    expected_status: str,
) -> None:
    current_status, _ = _component_state(wordpress, site, name)
    if current_status == expected_status:
        return
    if expected_status == "active":
        result = wordpress.wp(site.path, "plugin", "activate", name)
    elif expected_status == "inactive":
        result = wordpress.wp(site.path, "plugin", "deactivate", name)
    else:
        raise UpdateApplyError(f"Unsupported plugin status restoration: {expected_status}")
    if not result.ok:
        output = "\n".join(filter(None, [result.stdout, result.stderr]))
        raise UpdateApplyError(
            f"Could not restore plugin status {expected_status} for {name}"
            + (f": {output}" if output else "")
        )


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
        expected_status,
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
    if status != expected_status or version != previous_version:
        raise UpdateApplyError(
            "Plugin state changed after preparation: "
            f"status={status}, version={version}, expected={expected_status}/{previous_version}"
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
        expected_status=expected_status,
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
        if post_status != expected_status or post_version != recorded_target:
            raise UpdateApplyError(
                "Post-update plugin state mismatch: "
                f"status={post_status}, version={post_version}, "
                f"expected {expected_status}/{recorded_target}"
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
            _restore_status(wordpress, site, name, expected_status)
            rollback_status, rollback_version = _component_state(wordpress, site, name)
            if rollback_status != expected_status or rollback_version != previous_version:
                raise UpdateApplyError(
                    "Automatic rollback restored unexpected plugin state: "
                    f"status={rollback_status}, version={rollback_version}, "
                    f"expected {expected_status}/{previous_version}"
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
                f"Update failed: {exc}. Automatic file/status rollback also failed: "
                f"{rollback_error}"
            ) from rollback_error
        raise UpdateApplyError(
            f"Update failed and the plugin snapshot/status were restored automatically: {exc}"
        ) from exc

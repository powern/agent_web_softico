from __future__ import annotations

import gzip
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .backup import BackupError
from .config import GuardianConfig
from .models import Site
from .wordpress import WordPress


BACKUP_DIRECTORY_NAME = re.compile(r"^\d{8}T\d{6}Z(?:-[0-9a-f]{8})?$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
CREATE_TABLE = re.compile(
    rb"(?:^|\n)\s*CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+`([^`]+)`",
    re.I,
)
INSERT_INTO = re.compile(rb"(?:^|\n)\s*INSERT\s+INTO\s+`([^`]+)`", re.I)
SQL_SCAN_TAIL = 4096


@dataclass(slots=True)
class BackupVerificationResult:
    domain: str
    directory: Path
    database_path: Path
    manifest_path: Path
    created_at: str
    compressed_size: int
    decompressed_size: int
    sha256: str
    table_prefix: str
    create_table_statements: int
    matching_tables: int
    insert_statements: int


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _validated_backup_root(config: GuardianConfig) -> Path:
    root = config.backup_dir
    if root.exists() and root.is_symlink():
        raise BackupError(f"Backup directory must not be a symlink: {root}")

    resolved_root = root.resolve(strict=False)
    resolved_sites = config.sites_root.resolve(strict=False)
    if resolved_root == resolved_sites or _is_within(resolved_root, resolved_sites):
        raise BackupError("Backup directory must be outside the public sites tree")
    if not root.is_dir():
        raise BackupError(f"Backup directory does not exist: {root}")
    return root


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError(f"Could not read backup manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise BackupError(f"Backup manifest must contain a JSON object: {path}")
    return payload


def select_backup_directory(
    config: GuardianConfig,
    domain: str,
    backup_name: str | None = None,
) -> Path:
    root = _validated_backup_root(config)
    domain_root = root / domain
    if domain_root.is_symlink():
        raise BackupError(f"Domain backup directory must not be a symlink: {domain_root}")
    if not domain_root.is_dir():
        raise BackupError(f"No backups exist for {domain}")

    if backup_name is not None:
        if not BACKUP_DIRECTORY_NAME.fullmatch(backup_name):
            raise BackupError(f"Invalid backup directory name: {backup_name}")
        selected = domain_root / backup_name
        if selected.is_symlink() or not selected.is_dir():
            raise BackupError(f"Backup does not exist for {domain}: {backup_name}")
        return selected

    candidates = sorted(
        (
            path
            for path in domain_root.iterdir()
            if BACKUP_DIRECTORY_NAME.fullmatch(path.name)
            and path.is_dir()
            and not path.is_symlink()
        ),
        key=lambda path: path.name,
        reverse=True,
    )
    if not candidates:
        raise BackupError(f"No completed backup directories exist for {domain}")
    return candidates[0]


def _validate_private_modes(
    directory: Path,
    manifest_path: Path,
    database_path: Path,
) -> None:
    if directory.stat().st_mode & 0o077:
        raise BackupError(f"Backup directory permissions are too broad: {directory}")
    for path in (manifest_path, database_path):
        if path.stat().st_mode & 0o077:
            raise BackupError(f"Backup file permissions are too broad: {path}")


def _count_sql_structure(
    database_path: Path,
    table_prefix: str,
) -> tuple[int, int, int, int]:
    decompressed_size = 0
    create_count = 0
    matching_tables = 0
    insert_count = 0
    tail = b""
    prefix = table_prefix.encode("utf-8")

    try:
        with gzip.open(database_path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                decompressed_size += len(chunk)
                data = tail + chunk
                prior = len(tail)

                for match in CREATE_TABLE.finditer(data):
                    if match.end() <= prior:
                        continue
                    create_count += 1
                    if match.group(1).startswith(prefix):
                        matching_tables += 1

                for match in INSERT_INTO.finditer(data):
                    if match.end() > prior:
                        insert_count += 1

                tail = data[-SQL_SCAN_TAIL:]
    except (OSError, EOFError) as exc:
        raise BackupError(
            f"Database archive is not a valid complete gzip stream: {exc}"
        ) from exc

    return decompressed_size, create_count, matching_tables, insert_count


def verify_database_backup(
    config: GuardianConfig,
    site: Site,
    wordpress: WordPress,
    *,
    backup_name: str | None = None,
) -> BackupVerificationResult:
    directory = select_backup_directory(config, site.domain, backup_name)
    manifest_path = directory / "manifest.json"
    database_path = directory / "database.sql.gz"

    if directory.is_symlink():
        raise BackupError(f"Backup directory must not be a symlink: {directory}")
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise BackupError(f"Backup manifest is missing or unsafe: {manifest_path}")
    if database_path.is_symlink() or not database_path.is_file():
        raise BackupError(f"Database archive is missing or unsafe: {database_path}")

    _validate_private_modes(directory, manifest_path, database_path)
    manifest = _load_manifest(manifest_path)

    if manifest.get("schema_version") != 1:
        raise BackupError("Unsupported or missing backup manifest schema_version")
    if manifest.get("domain") != site.domain:
        raise BackupError(
            f"Backup domain mismatch: expected {site.domain}, got {manifest.get('domain')}"
        )
    if manifest.get("site_path") != str(site.path):
        raise BackupError(
            f"Backup site path mismatch: expected {site.path}, "
            f"got {manifest.get('site_path')}"
        )

    try:
        created_at = datetime.fromisoformat(
            str(manifest["created_at"]).replace("Z", "+00:00")
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise BackupError("Backup manifest has an invalid created_at value") from exc
    if created_at.tzinfo is None:
        raise BackupError("Backup manifest created_at must include a timezone")

    database = manifest.get("database")
    if not isinstance(database, dict):
        raise BackupError("Backup manifest database section is missing")
    if database.get("filename") != database_path.name:
        raise BackupError("Backup manifest database filename does not match")
    if database.get("compression") != "gzip":
        raise BackupError("Backup manifest database compression must be gzip")

    expected_sha = str(database.get("sha256", "")).lower()
    if not SHA256_HEX.fullmatch(expected_sha):
        raise BackupError("Backup manifest contains an invalid SHA-256 checksum")
    try:
        expected_size = int(database["size"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BackupError("Backup manifest contains an invalid database size") from exc

    compressed_size = database_path.stat().st_size
    if compressed_size != expected_size:
        raise BackupError(
            "Database archive size does not match manifest: "
            f"expected {expected_size}, got {compressed_size}"
        )

    actual_sha = _sha256(database_path)
    if actual_sha != expected_sha:
        raise BackupError(
            "Database archive SHA-256 does not match manifest: "
            f"expected {expected_sha}, got {actual_sha}"
        )

    table_prefix = wordpress.table_prefix(site.path)
    if not table_prefix:
        raise BackupError(f"Could not read WordPress table prefix for {site.domain}")
    if re.fullmatch(r"[A-Za-z0-9_]+", table_prefix) is None:
        raise BackupError(f"WordPress table prefix is invalid: {table_prefix!r}")

    (
        decompressed_size,
        create_count,
        matching_tables,
        insert_count,
    ) = _count_sql_structure(database_path, table_prefix)

    if decompressed_size <= 0:
        raise BackupError("Database archive decompresses to an empty SQL file")
    if create_count <= 0:
        raise BackupError("Database SQL does not contain any CREATE TABLE statements")
    if matching_tables <= 0:
        raise BackupError(
            f"Database SQL contains no tables with WordPress prefix {table_prefix!r}"
        )

    return BackupVerificationResult(
        domain=site.domain,
        directory=directory,
        database_path=database_path,
        manifest_path=manifest_path,
        created_at=created_at.astimezone(timezone.utc).isoformat(),
        compressed_size=compressed_size,
        decompressed_size=decompressed_size,
        sha256=actual_sha,
        table_prefix=table_prefix,
        create_table_statements=create_count,
        matching_tables=matching_tables,
        insert_statements=insert_count,
    )

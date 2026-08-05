from __future__ import annotations

import gzip
import hashlib
import json
import os
import secrets
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import GuardianConfig
from .models import Site
from .wordpress import WordPress


class BackupError(RuntimeError):
    pass


@dataclass(slots=True)
class BackupResult:
    domain: str
    directory: Path
    database_path: Path
    manifest_path: Path
    size: int
    sha256: str
    backups_removed: int = 0


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_backup_root(config: GuardianConfig) -> Path:
    root = config.backup_dir
    if root.exists() and root.is_symlink():
        raise BackupError(f"Backup directory must not be a symlink: {root}")

    resolved_root = root.resolve(strict=False)
    resolved_sites = config.sites_root.resolve(strict=False)
    if resolved_root == resolved_sites or _is_within(resolved_root, resolved_sites):
        raise BackupError("Backup directory must be outside the public sites tree")

    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    return root


def _completed_backup_created_at(path: Path, domain: str) -> datetime | None:
    """Return the creation time only for a complete Guardian backup directory."""
    if path.name.startswith(".") or path.is_symlink() or not path.is_dir():
        return None

    manifest_path = path / "manifest.json"
    database_path = path / "database.sql.gz"
    if (
        manifest_path.is_symlink()
        or database_path.is_symlink()
        or not manifest_path.is_file()
        or not database_path.is_file()
    ):
        return None

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema_version") != 1 or manifest.get("domain") != domain:
            return None
        database = manifest.get("database")
        if not isinstance(database, dict) or database.get("filename") != database_path.name:
            return None
        created_at = datetime.fromisoformat(str(manifest["created_at"]).replace("Z", "+00:00"))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None

    if created_at.tzinfo is None:
        return None
    return created_at.astimezone(timezone.utc)


def prune_completed_backups(
    domain_root: Path,
    domain: str,
    keep_last: int,
    *,
    protect: Path | None = None,
) -> int:
    """Keep only the newest completed Guardian backups for one domain.

    Temporary directories, symlinks, incomplete directories and unrelated files
    are ignored. The optional protected directory is never removed even if its
    manifest timestamp is unusual.
    """
    if keep_last < 1:
        raise BackupError("backup.keep_last must be at least 1")

    candidates: list[tuple[datetime, str, Path]] = []
    for path in domain_root.iterdir():
        created_at = _completed_backup_created_at(path, domain)
        if created_at is not None:
            candidates.append((created_at, path.name, path))

    candidates.sort(reverse=True)
    keep: set[Path] = {item[2] for item in candidates[:keep_last]}
    if protect is not None:
        keep.add(protect)

    removed = 0
    failures: list[str] = []
    for _, _, path in candidates:
        if path in keep:
            continue
        try:
            if path.is_symlink():
                continue
            shutil.rmtree(path)
            removed += 1
        except OSError as exc:
            failures.append(f"{path}: {exc}")

    if failures:
        raise BackupError("Backup retention cleanup failed: " + "; ".join(failures))
    return removed


def create_database_backup(
    config: GuardianConfig,
    site: Site,
    wordpress: WordPress,
    *,
    now: datetime | None = None,
    apply_retention: bool = True,
) -> BackupResult:
    root = prepare_backup_root(config)
    domain_root = root / site.domain
    if domain_root.exists() and domain_root.is_symlink():
        raise BackupError(f"Domain backup directory must not be a symlink: {domain_root}")
    domain_root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(domain_root, 0o700)

    created_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    stamp = created_at.strftime("%Y%m%dT%H%M%SZ")
    final_dir = domain_root / stamp
    if final_dir.exists():
        final_dir = domain_root / f"{stamp}-{secrets.token_hex(4)}"

    staging = domain_root / f".{final_dir.name}.tmp-{secrets.token_hex(4)}"
    staging.mkdir(mode=0o700)
    sql_path = staging / "database.sql"
    compressed_path = staging / "database.sql.gz"
    manifest_path = staging / "manifest.json"

    try:
        result = wordpress.export_database(
            site.path,
            sql_path,
            timeout=config.backup_timeout,
        )
        if not result.ok:
            output = "\n".join(filter(None, [result.stdout, result.stderr]))
            raise BackupError(
                f"Database export failed for {site.domain}"
                + (f": {output}" if output else "")
            )
        if not sql_path.is_file() or sql_path.stat().st_size <= 0:
            raise BackupError(f"Database export is missing or empty for {site.domain}")

        os.chmod(sql_path, 0o600)
        with sql_path.open("rb") as source, gzip.open(compressed_path, "wb", compresslevel=6) as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
        os.chmod(compressed_path, 0o600)
        sql_path.unlink()

        size = compressed_path.stat().st_size
        digest = _sha256(compressed_path)
        core_version = wordpress.core_version(site.path)
        manifest = {
            "schema_version": 1,
            "created_at": created_at.isoformat(),
            "domain": site.domain,
            "site_path": str(site.path),
            "wordpress_core_version": core_version,
            "guardian_version": __version__,
            "database": {
                "filename": compressed_path.name,
                "compression": "gzip",
                "size": size,
                "sha256": digest,
            },
        }
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(manifest_path, 0o600)

        os.replace(staging, final_dir)
        removed = 0
        if apply_retention:
            removed = prune_completed_backups(
                domain_root,
                site.domain,
                config.backup_keep_last,
                protect=final_dir,
            )
        return BackupResult(
            domain=site.domain,
            directory=final_dir,
            database_path=final_dir / compressed_path.name,
            manifest_path=final_dir / manifest_path.name,
            size=size,
            sha256=digest,
            backups_removed=removed,
        )
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

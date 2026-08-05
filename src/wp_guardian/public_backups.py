from __future__ import annotations

import os
import re
from pathlib import Path

from .config import GuardianConfig
from .models import SiteAudit

DATABASE_SUFFIXES = (
    ".sql",
    ".sql.gz",
    ".sql.bz2",
    ".sql.xz",
    ".sql.zip",
    ".sqlite",
    ".sqlite3",
    ".dump",
)
BACKUP_ARCHIVE_SUFFIXES = (
    ".jpa",
    ".wpress",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
)
CONTEXT_ARCHIVE_SUFFIXES = (".zip", ".gz", ".bz2", ".xz", ".7z", ".rar")
BACKUP_DIR_MARKERS = {
    "backup",
    "backups",
    "archive",
    "archives",
    "dump",
    "dumps",
    "migration",
    "migrations",
    "snapshot",
    "snapshots",
    "updraft",
    "ai1wm-backups",
    "wp-snapshots",
}
BACKUP_NAME_MARKER = re.compile(
    r"(?:^|[-_.])(backup|back-up|dump|snapshot|archive|migration)(?:[-_.]|$)",
    re.I,
)
DATABASE_NAME_MARKER = re.compile(
    r"(?:^|[-_.])(database|db|export|production|prod)(?:[-_.]|$)",
    re.I,
)
SENSITIVE_CONFIG_COPY = re.compile(
    r"^(?:wp-config\.php(?:\.(?:bak|backup|old|orig|save|copy|dist|txt)|~)|"
    r"wp-config\.(?:bak|backup|old|orig|save|copy)|"
    r"\.env(?:\.(?:bak|backup|old|orig|save|copy|local|production|prod))?)$",
    re.I,
)
COMPONENT_DATABASE_SIZE_THRESHOLD = 1024 * 1024


def normalize_relative(relative: str) -> str:
    return relative.replace(os.sep, "/").lstrip("/").lower()


def component_tail(relative: str) -> list[str] | None:
    """Return path parts below a plugin/theme slug, or None outside components."""
    normalized = normalize_relative(relative)
    parts = normalized.split("/")
    if len(parts) >= 3 and parts[:2] == ["wp-content", "plugins"]:
        return parts[3:]
    if len(parts) >= 3 and parts[:2] == ["wp-content", "themes"]:
        return parts[3:]
    return None


def backup_context(relative: str) -> bool:
    normalized = normalize_relative(relative)
    parts = normalized.split("/")
    tail = component_tail(normalized)

    # For installed components, ignore the plugin/theme slug itself. A plugin
    # may legitimately be named after backup or migration functionality. Only
    # storage directories below the component or an explicit backup filename
    # count as backup context.
    context_parts = tail if tail is not None else parts
    directories = context_parts[:-1]
    filename = context_parts[-1] if context_parts else ""
    return bool(BACKUP_DIR_MARKERS.intersection(directories)) or (
        BACKUP_NAME_MARKER.search(filename) is not None
    )


def allowed_public_backup(relative: str, config: GuardianConfig) -> bool:
    normalized = relative.replace(os.sep, "/")
    for entry in config.allow_public_backup_paths:
        clean = entry.replace(os.sep, "/")
        if clean.endswith("/") and normalized.startswith(clean):
            return True
        if normalized == clean:
            return True
    return False


def classify_public_backup(
    relative: str,
    size: int | None = None,
) -> tuple[str, str, str] | None:
    normalized = normalize_relative(relative)
    name = Path(normalized).name
    inside_component = component_tail(normalized) is not None
    has_backup_context = backup_context(normalized)

    if SENSITIVE_CONFIG_COPY.fullmatch(name):
        return (
            "sensitive_config",
            "CRITICAL",
            "Sensitive configuration file or backup is inside the public web root",
        )

    if name.endswith(DATABASE_SUFFIXES):
        # Plugins commonly ship small SQL schema or migration resources. They
        # are application assets, not database exports. Still flag component
        # SQL files when their path/name clearly says backup/database/export,
        # or when the file is large enough to plausibly contain real site data.
        component_database_signal = (
            has_backup_context
            or DATABASE_NAME_MARKER.search(name) is not None
            or (size is not None and size >= COMPONENT_DATABASE_SIZE_THRESHOLD)
        )
        if inside_component and not component_database_signal:
            return None
        return (
            "database_dump",
            "CRITICAL",
            "Potential database dump is inside the public web root",
        )

    if name.endswith(BACKUP_ARCHIVE_SUFFIXES):
        # Source packages and bundled assets such as plugin-name.tar.gz are
        # legitimate inside installed plugins/themes unless their path or file
        # name explicitly identifies backup storage.
        if inside_component and not has_backup_context:
            return None
        return (
            "site_backup",
            "HIGH",
            "Potential site backup archive is inside the public web root",
        )

    if name.endswith(CONTEXT_ARCHIVE_SUFFIXES) and has_backup_context:
        return (
            "backup_archive",
            "HIGH",
            "Potential backup archive is inside the public web root",
        )

    return None


def scan_public_backups(site_path: Path, config: GuardianConfig, audit: SiteAudit) -> None:
    scanned = found = 0
    complete = True

    for path in site_path.rglob("*"):
        if not path.is_file():
            continue
        if scanned >= config.max_scan_files:
            complete = False
            audit.add(
                "public_backups",
                "LOW",
                "Public backup scan stopped at configured file limit",
                limit=config.max_scan_files,
                scanned_files=scanned,
            )
            break

        scanned += 1
        relative = str(path.relative_to(site_path)).replace(os.sep, "/")
        if allowed_public_backup(relative, config):
            continue

        try:
            info = path.stat()
            size = info.st_size
            mode = oct(info.st_mode & 0o777)
        except OSError:
            size = -1
            mode = "unknown"

        classification = classify_public_backup(
            relative,
            size=None if size < 0 else size,
        )
        if classification is None:
            continue

        kind, severity, message = classification
        found += 1
        audit.add(
            "public_backups",
            severity,
            message,
            path=str(path),
            relative=relative,
            kind=kind,
            size=size,
            mode=mode,
        )

    audit.facts["public_backups"] = {
        "scanned": scanned,
        "found": found,
        "complete": complete,
    }

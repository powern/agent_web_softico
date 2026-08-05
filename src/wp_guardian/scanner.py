from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from .config import GuardianConfig
from .models import SiteAudit

PHP_SUFFIXES = {".php", ".phtml", ".phar", ".inc"}
SUSPICIOUS_PATTERNS = {
    "eval": re.compile(rb"\beval\s*\(", re.I),
    "assert": re.compile(rb"\bassert\s*\(", re.I),
    "base64_decode": re.compile(rb"\bbase64_decode\s*\(", re.I),
    "gzinflate": re.compile(rb"\bgzinflate\s*\(", re.I),
    "shell_exec": re.compile(rb"\bshell_exec\s*\(", re.I),
    "system": re.compile(rb"\bsystem\s*\(", re.I),
    "passthru": re.compile(rb"\bpassthru\s*\(", re.I),
}

# WPForms places tiny index.php guards in cache directories. They only emit a
# 404 response and contain no application logic. Keep this recognizer strict:
# exactly the two expected header calls, with an optional exit/die statement.
HTTP_404_GUARD = re.compile(
    rb"""
    ^\s*<\?php\s*
    header\s*\(\s*\$_server\s*\[\s*['\"]server_protocol['\"]\s*\]
        \s*\.\s*['\"]\s*404\s+not\s+found['\"]\s*\)\s*;\s*
    header\s*\(\s*['\"]status\s*:\s*404\s+not\s+found['\"]\s*\)\s*;\s*
    (?:(?:exit|die)\s*(?:\(\s*\))?\s*;\s*)?
    (?:\?>\s*)?$
    """,
    re.I | re.X,
)

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
SENSITIVE_CONFIG_COPY = re.compile(
    r"^(?:wp-config\.php(?:\.(?:bak|backup|old|orig|save|copy|dist|txt)|~)|"
    r"wp-config\.(?:bak|backup|old|orig|save|copy)|"
    r"\.env(?:\.(?:bak|backup|old|orig|save|copy|local|production|prod))?)$",
    re.I,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_php_like(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix.lower() in PHP_SUFFIXES or re.search(r"\.php\d+$", name) is not None


def looks_like_guard_file(path: Path) -> bool:
    try:
        payload = path.read_bytes()[:1024].strip()
    except OSError:
        return False
    if not payload:
        return True

    normalized = re.sub(rb"\s+", b" ", payload.lower())
    safe_fragments = (
        b"<?php exit(0); ?>",
        b"<?php exit; ?>",
        b"<?php // silence is golden",
        b"<?php /* silence is golden",
        b"<?php die;",
    )
    if any(fragment in normalized for fragment in safe_fragments):
        return True

    return len(payload) <= 512 and HTTP_404_GUARD.fullmatch(payload) is not None


def allowed_upload_php(relative: str, path: Path, config: GuardianConfig) -> bool:
    normalized = relative.replace(os.sep, "/")
    if normalized.startswith("cache/wpml/twig/"):
        return True
    if normalized.startswith(("wpallexport/", "wpallimport/")) and path.name in {"index.php", "functions.php"}:
        return path.stat().st_size == 0 or looks_like_guard_file(path)
    for entry in config.allow_php_upload_paths:
        if entry.endswith("/") and normalized.startswith(entry):
            return True
        if normalized == entry and looks_like_guard_file(path):
            return True
    return False


def allowed_public_backup(relative: str, config: GuardianConfig) -> bool:
    normalized = relative.replace(os.sep, "/")
    for entry in config.allow_public_backup_paths:
        clean = entry.replace(os.sep, "/")
        if clean.endswith("/") and normalized.startswith(clean):
            return True
        if normalized == clean:
            return True
    return False


def backup_context(relative: str) -> bool:
    normalized = relative.replace(os.sep, "/").lower()
    parts = normalized.split("/")
    # Avoid treating plugin/theme/vendor package assets as backup storage merely
    # because a component happens to contain a backup-related product name.
    if any(part in {"plugins", "themes", "vendor", "node_modules"} for part in parts):
        return BACKUP_NAME_MARKER.search(Path(normalized).name) is not None
    return bool(BACKUP_DIR_MARKERS.intersection(parts)) or BACKUP_NAME_MARKER.search(
        Path(normalized).name
    ) is not None


def classify_public_backup(relative: str) -> tuple[str, str, str] | None:
    name = Path(relative).name.lower()

    if SENSITIVE_CONFIG_COPY.fullmatch(name):
        return (
            "sensitive_config",
            "CRITICAL",
            "Sensitive configuration file or backup is inside the public web root",
        )

    if name.endswith(DATABASE_SUFFIXES):
        return (
            "database_dump",
            "CRITICAL",
            "Potential database dump is inside the public web root",
        )

    if name.endswith(BACKUP_ARCHIVE_SUFFIXES):
        return (
            "site_backup",
            "HIGH",
            "Potential site backup archive is inside the public web root",
        )

    if name.endswith(CONTEXT_ARCHIVE_SUFFIXES) and backup_context(relative):
        return (
            "backup_archive",
            "HIGH",
            "Potential backup archive is inside the public web root",
        )

    return None


def scan_uploads(site_path: Path, config: GuardianConfig, audit: SiteAudit) -> None:
    uploads = site_path / "wp-content" / "uploads"
    if not uploads.is_dir():
        audit.facts["uploads_php"] = {
            "scanned_files": 0,
            "php_files": 0,
            "suspicious": 0,
            "complete": True,
        }
        return

    scanned_files = php_files = suspicious = 0
    complete = True

    for path in uploads.rglob("*"):
        if not path.is_file():
            continue

        scanned_files += 1
        if not is_php_like(path):
            continue

        # The safety budget applies only to executable candidates. Counting all
        # ordinary media files made large but healthy WordPress libraries stop
        # before the scanner reached later directories.
        if php_files >= config.max_scan_files:
            complete = False
            audit.add(
                "uploads_php",
                "MEDIUM",
                "Uploads scan stopped at configured PHP candidate limit",
                limit=config.max_scan_files,
                scanned_files=scanned_files,
                php_files=php_files,
            )
            break

        php_files += 1
        relative = str(path.relative_to(uploads))
        if allowed_upload_php(relative, path, config):
            continue

        suspicious += 1
        matches: list[str] = []
        try:
            payload = path.read_bytes()[:2_000_000]
            for name, pattern in SUSPICIOUS_PATTERNS.items():
                if pattern.search(payload):
                    matches.append(name)
        except OSError as exc:
            matches.append(f"read_error:{exc}")

        try:
            size = path.stat().st_size
            digest = sha256_file(path)
        except OSError as exc:
            size = -1
            digest = ""
            matches.append(f"stat_error:{exc}")

        audit.add(
            "uploads_php",
            "CRITICAL" if matches else "HIGH",
            "Unexpected executable file in uploads",
            path=str(path),
            relative=relative,
            size=size,
            sha256=digest,
            patterns=matches,
        )

    audit.facts["uploads_php"] = {
        "scanned_files": scanned_files,
        "php_files": php_files,
        "suspicious": suspicious,
        "complete": complete,
    }


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

        classification = classify_public_backup(relative)
        if classification is None:
            continue

        kind, severity, message = classification
        found += 1
        try:
            info = path.stat()
            size = info.st_size
            mode = oct(info.st_mode & 0o777)
        except OSError:
            size = -1
            mode = "unknown"

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


def scan_world_writable(site_path: Path, config: GuardianConfig, audit: SiteAudit) -> None:
    found = scanned = 0
    complete = True
    for path in site_path.rglob("*"):
        if not path.is_file():
            continue
        if scanned >= config.max_scan_files:
            complete = False
            audit.add(
                "permissions",
                "LOW",
                "World-writable scan stopped at configured file limit",
                limit=config.max_scan_files,
                scanned_files=scanned,
            )
            break
        scanned += 1
        try:
            mode = path.stat().st_mode
        except OSError:
            continue
        if mode & 0o002:
            found += 1
            audit.add(
                "permissions",
                "HIGH" if is_php_like(path) else "MEDIUM",
                "World-writable file detected",
                path=str(path),
                mode=oct(mode & 0o777),
            )
    audit.facts["world_writable"] = {
        "scanned": scanned,
        "found": found,
        "complete": complete,
    }

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
    return any(fragment in normalized for fragment in safe_fragments)


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
        # Directories do not consume the file-scan budget. The previous
        # implementation counted every directory entry and could stop early on
        # deeply nested but otherwise harmless upload trees.
        if not path.is_file():
            continue

        if scanned_files >= config.max_scan_files:
            complete = False
            audit.add(
                "uploads_php",
                "MEDIUM",
                "Uploads scan stopped at configured file limit",
                limit=config.max_scan_files,
                scanned_files=scanned_files,
            )
            break

        scanned_files += 1
        if not is_php_like(path):
            continue

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


def scan_world_writable(site_path: Path, config: GuardianConfig, audit: SiteAudit) -> None:
    found = scanned = 0
    for path in site_path.rglob("*"):
        if not path.is_file():
            continue
        if scanned >= config.max_scan_files:
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
    audit.facts["world_writable"] = {"scanned": scanned, "found": found}

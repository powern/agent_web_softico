from __future__ import annotations

import shutil
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def string_tuple(value: Any, setting: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    raise ValueError(f"{setting} must be a string or an array of strings")


@dataclass(slots=True)
class GuardianConfig:
    sites_root: Path = Path("/home/admin/web")
    state_dir: Path = Path("/var/lib/wp-guardian")
    report_dir: Path = Path("/var/lib/wp-guardian/reports")
    backup_dir: Path = Path("/home/admin/private-backups/wp-guardian")
    wp_cli: str = "wp"
    curl: str = "curl"
    command_timeout: int = 60
    http_timeout: int = 20
    backup_timeout: int = 900
    backup_keep_last: int = 3
    max_scan_files: int = 200000
    retention_business_days: int = 3
    include: set[str] = field(default_factory=set)
    exclude: set[str] = field(default_factory=set)
    checks: dict[str, bool] = field(default_factory=dict)
    allowed_admin_logins: set[str] = field(default_factory=set)
    allow_php_upload_paths: tuple[str, ...] = ()
    allow_public_backup_paths: tuple[str, ...] = ()
    mail_enabled: bool = False
    mail_recipients: tuple[str, ...] = ()
    mail_subject_prefix: str = "[WP Guardian]"
    sendmail: str = "/usr/sbin/sendmail"

    def resolve_tools(self) -> None:
        for attr in ("wp_cli", "curl"):
            value = getattr(self, attr)
            resolved = shutil.which(value) if "/" not in value else value
            if not resolved or not Path(resolved).exists():
                raise FileNotFoundError(f"Required tool not found: {value}")
            setattr(self, attr, resolved)


def load_config(path: Path) -> GuardianConfig:
    with path.open("rb") as handle:
        raw = tomllib.load(handle)

    general = raw.get("general", {})
    sites = raw.get("sites", {})
    audit = raw.get("audit", {})
    policy = raw.get("policy", {})
    backup = raw.get("backup", {})
    mail = raw.get("mail", {})

    retention_business_days = int(general.get("retention_business_days", 3))
    if retention_business_days < 1:
        raise ValueError("general.retention_business_days must be at least 1")

    backup_timeout = int(backup.get("timeout", 900))
    if backup_timeout < 60:
        raise ValueError("backup.timeout must be at least 60 seconds")

    backup_keep_last = int(backup.get("keep_last", 3))
    if backup_keep_last < 1:
        raise ValueError("backup.keep_last must be at least 1")

    config = GuardianConfig(
        sites_root=Path(general.get("sites_root", "/home/admin/web")),
        state_dir=Path(general.get("state_dir", "/var/lib/wp-guardian")),
        report_dir=Path(
            general.get("report_dir", "/var/lib/wp-guardian/reports")
        ),
        backup_dir=Path(
            backup.get("directory", "/home/admin/private-backups/wp-guardian")
        ),
        wp_cli=str(general.get("wp_cli", "wp")),
        curl=str(general.get("curl", "curl")),
        command_timeout=int(general.get("command_timeout", 60)),
        http_timeout=int(general.get("http_timeout", 20)),
        backup_timeout=backup_timeout,
        backup_keep_last=backup_keep_last,
        max_scan_files=int(general.get("max_scan_files", 200000)),
        retention_business_days=retention_business_days,
        include=set(sites.get("include", [])),
        exclude=set(sites.get("exclude", [])),
        checks={key: bool(value) for key, value in audit.items()},
        allowed_admin_logins=set(policy.get("allowed_admin_logins", [])),
        allow_php_upload_paths=string_tuple(
            policy.get("allow_php_upload_paths", []),
            "policy.allow_php_upload_paths",
        ),
        allow_public_backup_paths=string_tuple(
            policy.get("allow_public_backup_paths", []),
            "policy.allow_public_backup_paths",
        ),
        mail_enabled=bool(mail.get("enabled", False)),
        mail_recipients=string_tuple(mail.get("recipients", []), "mail.recipients"),
        mail_subject_prefix=str(mail.get("subject_prefix", "[WP Guardian]")),
        sendmail=str(mail.get("sendmail", "/usr/sbin/sendmail")),
    )
    config.resolve_tools()
    return config

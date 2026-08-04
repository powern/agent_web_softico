from __future__ import annotations

import shutil
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class GuardianConfig:
    sites_root: Path = Path("/home/admin/web")
    state_dir: Path = Path("/var/lib/wp-guardian")
    report_dir: Path = Path("/var/lib/wp-guardian/reports")
    wp_cli: str = "wp"
    curl: str = "curl"
    command_timeout: int = 60
    http_timeout: int = 20
    max_scan_files: int = 50000
    include: set[str] = field(default_factory=set)
    exclude: set[str] = field(default_factory=set)
    checks: dict[str, bool] = field(default_factory=dict)
    allowed_admin_logins: set[str] = field(default_factory=set)
    allow_php_upload_paths: tuple[str, ...] = ()

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

    config = GuardianConfig(
        sites_root=Path(general.get("sites_root", "/home/admin/web")),
        state_dir=Path(general.get("state_dir", "/var/lib/wp-guardian")),
        report_dir=Path(
            general.get("report_dir", "/var/lib/wp-guardian/reports")
        ),
        wp_cli=str(general.get("wp_cli", "wp")),
        curl=str(general.get("curl", "curl")),
        command_timeout=int(general.get("command_timeout", 60)),
        http_timeout=int(general.get("http_timeout", 20)),
        max_scan_files=int(general.get("max_scan_files", 50000)),
        include=set(sites.get("include", [])),
        exclude=set(sites.get("exclude", [])),
        checks={key: bool(value) for key, value in audit.items()},
        allowed_admin_logins=set(policy.get("allowed_admin_logins", [])),
        allow_php_upload_paths=tuple(policy.get("allow_php_upload_paths", [])),
    )
    config.resolve_tools()
    return config

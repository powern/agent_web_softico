from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .config import GuardianConfig
from .models import SiteAudit
from .runner import CommandResult, CommandRunner


class WordPress:
    def __init__(self, config: GuardianConfig, runner: CommandRunner) -> None:
        self.config = config
        self.runner = runner

    def wp(self, site_path: Path, *args: str, timeout: int | None = None) -> CommandResult:
        command = [
            self.config.wp_cli,
            f"--path={site_path}",
            "--skip-plugins",
            "--skip-themes",
            *args,
        ]
        return self.runner.run(command, timeout=timeout)

    def core_version(self, site_path: Path) -> str | None:
        result = self.wp(site_path, "core", "version")
        return result.stdout if result.ok else None

    def table_prefix(self, site_path: Path) -> str | None:
        result = self.wp(
            site_path,
            "config",
            "get",
            "table_prefix",
            "--type=variable",
        )
        return result.stdout.strip() if result.ok and result.stdout.strip() else None

    def verify_core(self, site_path: Path) -> CommandResult:
        return self.wp(site_path, "core", "verify-checksums")

    def export_database(
        self,
        site_path: Path,
        target: Path,
        *,
        timeout: int | None = None,
    ) -> CommandResult:
        return self.wp(
            site_path,
            "db",
            "export",
            str(target),
            "--add-drop-table",
            "--single-transaction",
            timeout=timeout,
        )

    def list_updates(self, site_path: Path, kind: str) -> list[dict[str, Any]]:
        result = self.wp(
            site_path,
            kind,
            "list",
            "--update=available",
            "--fields=name,status,version,update_version",
            "--format=json",
        )
        if not result.ok:
            return []
        data = json.loads(result.stdout or "[]")
        return data if isinstance(data, list) else []

    def list_plugins(self, site_path: Path) -> list[dict[str, Any]]:
        result = self.wp(
            site_path,
            "plugin",
            "list",
            "--fields=name,status,version",
            "--format=json",
        )
        if not result.ok:
            return []
        data = json.loads(result.stdout or "[]")
        return data if isinstance(data, list) else []

    def list_admins(self, site_path: Path) -> list[dict[str, Any]]:
        result = self.wp(
            site_path,
            "user",
            "list",
            "--role=administrator",
            "--fields=ID,user_login,user_email,display_name,user_registered",
            "--format=json",
        )
        if not result.ok:
            return []
        data = json.loads(result.stdout or "[]")
        return data if isinstance(data, list) else []

    @staticmethod
    def has_checksum_manifest(plugin: str, version: str, timeout: int = 8) -> bool:
        url = f"https://downloads.wordpress.org/plugin-checksums/{plugin}/{version}.json"
        request = urllib.request.Request(url, method="HEAD")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status == 200
        except urllib.error.HTTPError as exc:
            if exc.code == 405:
                try:
                    with urllib.request.urlopen(url, timeout=timeout) as response:
                        return response.status == 200
                except (urllib.error.URLError, TimeoutError):
                    return False
            return False
        except (urllib.error.URLError, TimeoutError):
            return False

    def verify_plugins(self, site_path: Path, audit: SiteAudit) -> None:
        checked = skipped = failed = timeouts = 0
        for plugin in self.list_plugins(site_path):
            name = str(plugin.get("name", ""))
            version = str(plugin.get("version", ""))
            if not name or not version:
                continue
            if not self.has_checksum_manifest(name, version):
                skipped += 1
                continue
            checked += 1
            result = self.wp(
                site_path,
                "plugin",
                "verify-checksums",
                name,
                timeout=max(self.config.command_timeout, 45),
            )
            if result.timed_out:
                timeouts += 1
                audit.add(
                    "plugin_checksums",
                    "MEDIUM",
                    f"Checksum verification timed out for {name}",
                    plugin=name,
                    version=version,
                )
            elif not result.ok:
                failed += 1
                audit.add(
                    "plugin_checksums",
                    "HIGH",
                    f"Plugin files do not match official checksums: {name}",
                    plugin=name,
                    version=version,
                    output="\n".join(filter(None, [result.stdout, result.stderr])),
                )
        audit.facts["plugin_checksums"] = {
            "checked": checked,
            "skipped_private": skipped,
            "failed": failed,
            "timeouts": timeouts,
        }

from __future__ import annotations

import json

from .config import GuardianConfig
from .discovery import discover_sites
from .models import Site, SiteAudit
from .runner import CommandRunner
from .scanner import scan_uploads, scan_world_writable
from .storage import Storage
from .wordpress import WordPress


def enabled(config: GuardianConfig, check: str, default: bool = True) -> bool:
    return config.checks.get(check, default)


def check_http(site: Site, config: GuardianConfig, runner: CommandRunner, audit: SiteAudit) -> None:
    result = runner.run(
        [
            config.curl,
            "-kLsS",
            "-o",
            "/dev/null",
            "-w",
            '{"code":%{http_code},"time":%{time_total},"url":"%{url_effective}"}',
            "--max-time",
            str(config.http_timeout),
            f"https://{site.domain}/",
        ],
        timeout=config.http_timeout + 5,
    )
    if not result.ok:
        audit.add(
            "http",
            "HIGH",
            "HTTP check failed",
            output="\n".join(filter(None, [result.stdout, result.stderr])),
        )
        return
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        audit.add("http", "MEDIUM", "Could not parse HTTP check result", output=result.stdout)
        return
    audit.facts["http"] = payload
    code = int(payload.get("code", 0))
    if code < 200 or code >= 400:
        audit.add("http", "HIGH", f"Unexpected HTTP status: {code}", **payload)


def audit_site(
    site: Site,
    config: GuardianConfig,
    runner: CommandRunner,
    wordpress: WordPress,
    storage: Storage,
) -> SiteAudit:
    audit = SiteAudit(domain=site.domain, path=str(site.path))

    if enabled(config, "check_http"):
        check_http(site, config, runner, audit)

    version = wordpress.core_version(site.path)
    if version:
        audit.facts["core_version"] = version
    else:
        audit.add("wordpress", "HIGH", "Could not read WordPress version")

    if enabled(config, "check_updates"):
        plugins = wordpress.list_updates(site.path, "plugin")
        themes = wordpress.list_updates(site.path, "theme")
        audit.facts["updates"] = {"plugins": plugins, "themes": themes}
        if plugins:
            audit.add("updates", "MEDIUM", f"{len(plugins)} plugin updates available", plugins=plugins)
        if themes:
            audit.add("updates", "LOW", f"{len(themes)} theme updates available", themes=themes)

    if enabled(config, "verify_core_checksums"):
        result = wordpress.verify_core(site.path)
        audit.facts["core_checksum_ok"] = result.ok
        if not result.ok:
            audit.add(
                "core_checksums",
                "CRITICAL",
                "WordPress core checksum verification failed",
                output="\n".join(filter(None, [result.stdout, result.stderr])),
            )

    if enabled(config, "verify_plugin_checksums"):
        wordpress.verify_plugins(site.path, audit)

    if enabled(config, "scan_uploads_php"):
        scan_uploads(site.path, config, audit)

    if enabled(config, "check_world_writable"):
        scan_world_writable(site.path, config, audit)

    if enabled(config, "check_admin_users"):
        admins = wordpress.list_admins(site.path)
        audit.facts["admins"] = admins
        logins = {str(item.get("user_login", "")) for item in admins if item.get("user_login")}
        new_admins = storage.compare_admins(site.domain, logins)
        for login in sorted(new_admins):
            audit.add("admins", "HIGH", f"New administrator detected: {login}", login=login)
        if config.allowed_admin_logins:
            for login in sorted(logins - config.allowed_admin_logins):
                audit.add(
                    "admins",
                    "MEDIUM",
                    f"Administrator is not in configured allow-list: {login}",
                    login=login,
                )

    audit.finish()
    return audit


def audit_all(config: GuardianConfig, domain: str | None = None) -> list[SiteAudit]:
    runner = CommandRunner(config.command_timeout)
    wordpress = WordPress(config, runner)
    storage = Storage(config.state_dir / "guardian.sqlite3")
    sites = discover_sites(config)
    if domain:
        sites = [site for site in sites if site.domain == domain]
    return [audit_site(site, config, runner, wordpress, storage) for site in sites]

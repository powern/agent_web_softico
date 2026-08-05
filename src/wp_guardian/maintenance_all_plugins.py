from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Callable

from . import maintenance
from .update_apply_all_plugins import (
    ALLOWED_PLUGIN_STATUSES,
    apply_prepared_plugin_update,
)
from .wordpress import WordPress


def _detect_site_updates(
    wordpress: WordPress,
    site_path: Path,
) -> tuple[list[dict[str, Any]], list[maintenance.MaintenanceItem]]:
    plugins = maintenance._checked_updates(wordpress, site_path, "plugin")
    themes = maintenance._checked_updates(wordpress, site_path, "theme")
    candidates: list[dict[str, Any]] = []
    skipped: list[maintenance.MaintenanceItem] = []

    for row in sorted(plugins, key=lambda item: str(item.get("name", ""))):
        status = str(row.get("status", "")).strip()
        name = str(row.get("name", "")).strip()
        target = maintenance._target_version(row)
        if status in ALLOWED_PLUGIN_STATUSES and name and target:
            candidates.append(row)
        elif not target:
            skipped.append(
                maintenance._item_from_row(
                    "plugin",
                    row,
                    "skipped",
                    "The update source did not provide an exact target version",
                )
            )
        else:
            skipped.append(
                maintenance._item_from_row(
                    "plugin",
                    row,
                    "skipped",
                    "Automatic maintenance supports only standard active or inactive plugins",
                )
            )

    for row in sorted(themes, key=lambda item: str(item.get("name", ""))):
        skipped.append(
            maintenance._item_from_row(
                "theme",
                row,
                "skipped",
                "Automatic theme updates are not enabled",
            )
        )
    return candidates, skipped


def enable_all_plugin_updates() -> None:
    maintenance._detect_site_updates = _detect_site_updates
    maintenance.apply_prepared_plugin_update = apply_prepared_plugin_update


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="wp-guardian-maintenance")
    root.add_argument("--config", type=Path, default=maintenance.DEFAULT_CONFIG)
    root.add_argument(
        "--domain",
        help="Run guarded maintenance and the final audit only for this configured domain",
    )
    return root


def _selected_site_discovery(
    original: Callable[[maintenance.GuardianConfig], list[Any]],
    domain: str,
) -> Callable[[maintenance.GuardianConfig], list[Any]]:
    def discover_selected(config: maintenance.GuardianConfig) -> list[Any]:
        sites = original(config)
        selected = [site for site in sites if site.domain == domain]
        if not selected:
            raise maintenance.MaintenanceError(
                f"Configured WordPress site was not found for domain: {domain}"
            )
        return selected

    return discover_selected


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    domain = args.domain.strip().lower() if args.domain is not None else None
    if args.domain is not None and not domain:
        parser().error("--domain must not be empty")

    original_detect_site_updates = maintenance._detect_site_updates
    original_apply_update = maintenance.apply_prepared_plugin_update
    original_discover_sites = maintenance.discover_sites
    original_audit_all = maintenance.audit_all

    enable_all_plugin_updates()
    if domain:
        maintenance.discover_sites = _selected_site_discovery(
            original_discover_sites,
            domain,
        )
        maintenance.audit_all = lambda config: original_audit_all(config, domain=domain)

    try:
        return maintenance.main(["--config", str(args.config)])
    finally:
        maintenance._detect_site_updates = original_detect_site_updates
        maintenance.apply_prepared_plugin_update = original_apply_update
        maintenance.discover_sites = original_discover_sites
        maintenance.audit_all = original_audit_all


if __name__ == "__main__":
    raise SystemExit(main())

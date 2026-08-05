from __future__ import annotations

from pathlib import Path
from typing import Any

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


def main(argv: list[str] | None = None) -> int:
    enable_all_plugin_updates()
    return maintenance.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())

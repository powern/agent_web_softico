import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from wp_guardian.config import GuardianConfig
from wp_guardian.maintenance import (
    _detect_site_updates,
    render_maintenance_text,
    run_maintenance,
)
from wp_guardian.models import Site, SiteAudit
from wp_guardian.runner import CommandResult
from wp_guardian.update_apply import UpdateApplyError


class FakeWordPress:
    def __init__(self, plugins=None, themes=None):
        self.plugins = plugins or []
        self.themes = themes or []

    def wp(self, site_path: Path, kind: str, *args: str, timeout=None):
        payload = self.plugins if kind == "plugin" else self.themes
        return CommandResult(
            ["wp", kind, *args],
            0,
            json.dumps(payload),
            "",
        )


class MaintenanceTests(unittest.TestCase):
    def test_detection_selects_only_inactive_plugins_with_exact_target(self):
        wordpress = FakeWordPress(
            plugins=[
                {
                    "name": "safe-plugin",
                    "status": "inactive",
                    "version": "1.0",
                    "update_version": "1.1",
                },
                {
                    "name": "active-plugin",
                    "status": "active",
                    "version": "2.0",
                    "update_version": "2.1",
                },
                {
                    "name": "unknown-target",
                    "status": "inactive",
                    "version": "3.0",
                    "update_version": None,
                },
            ],
            themes=[
                {
                    "name": "premium-theme",
                    "status": "parent",
                    "version": "7.0",
                    "update_version": "7.1",
                }
            ],
        )

        candidates, skipped = _detect_site_updates(
            wordpress,
            Path("/srv/example"),
        )

        self.assertEqual([item["name"] for item in candidates], ["safe-plugin"])
        self.assertEqual(
            {(item.kind, item.name, item.action) for item in skipped},
            {
                ("plugin", "active-plugin", "skipped"),
                ("plugin", "unknown-target", "skipped"),
                ("theme", "premium-theme", "skipped"),
            },
        )

    def test_successful_run_prepares_applies_audits_and_writes_latest_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = GuardianConfig(
                sites_root=root / "web",
                state_dir=root / "state",
                report_dir=root / "reports",
                backup_dir=root / "backups",
            )
            site = Site("example.com", root / "web/example.com/public_html")
            checkpoint = root / "backups/example.com/20260805T091325Z"
            checkpoint.mkdir(parents=True)
            record = checkpoint / "update-applied.json"
            record.write_text("{}", encoding="utf-8")
            wordpress = FakeWordPress(
                plugins=[
                    {
                        "name": "safe-plugin",
                        "status": "inactive",
                        "version": "1.0",
                        "update_version": "1.1",
                    },
                    {
                        "name": "active-plugin",
                        "status": "active",
                        "version": "2.0",
                        "update_version": "2.1",
                    },
                ]
            )
            audit = SiteAudit(domain=site.domain, path=str(site.path))
            audit.facts["http"] = {
                "code": 200,
                "url": "https://example.com/",
                "time": 0.1,
            }
            audit.finish()

            preparation = SimpleNamespace(
                preparation_id="a" * 64,
                directory=checkpoint,
            )
            applied = SimpleNamespace(record_path=record)

            with (
                patch("wp_guardian.maintenance.discover_sites", return_value=[site]),
                patch("wp_guardian.maintenance.WordPress", return_value=wordpress),
                patch(
                    "wp_guardian.maintenance.prepare_component_update",
                    return_value=preparation,
                ) as prepare,
                patch(
                    "wp_guardian.maintenance.apply_prepared_plugin_update",
                    return_value=applied,
                ) as apply_update,
                patch("wp_guardian.maintenance.audit_all", return_value=[audit]),
            ):
                result = run_maintenance(config)

            self.assertEqual(result.updated, 1)
            self.assertEqual(result.skipped, 1)
            self.assertEqual(result.failed, 0)
            prepare.assert_called_once()
            apply_update.assert_called_once()
            latest = (config.report_dir / "latest.txt").read_text(encoding="utf-8")
            self.assertIn("UPDATED: plugin safe-plugin 1.0 -> 1.1", latest)
            self.assertIn("SKIPPED: plugin active-plugin 2.0 -> 2.1", latest)
            self.assertIn("FINAL SECURITY AUDIT", latest)

    def test_apply_failure_with_rollback_is_reported_and_final_audit_still_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = GuardianConfig(
                sites_root=root / "web",
                state_dir=root / "state",
                report_dir=root / "reports",
                backup_dir=root / "backups",
            )
            site = Site("example.com", root / "web/example.com/public_html")
            checkpoint = root / "backups/example.com/20260805T091325Z"
            checkpoint.mkdir(parents=True)
            rollback = checkpoint / "update-rollback.json"
            rollback.write_text("{}", encoding="utf-8")
            wordpress = FakeWordPress(
                plugins=[
                    {
                        "name": "safe-plugin",
                        "status": "inactive",
                        "version": "1.0",
                        "update_version": "1.1",
                    }
                ]
            )
            audit = SiteAudit(domain=site.domain, path=str(site.path))
            audit.finish()
            preparation = SimpleNamespace(
                preparation_id="b" * 64,
                directory=checkpoint,
            )

            with (
                patch("wp_guardian.maintenance.discover_sites", return_value=[site]),
                patch("wp_guardian.maintenance.WordPress", return_value=wordpress),
                patch(
                    "wp_guardian.maintenance.prepare_component_update",
                    return_value=preparation,
                ),
                patch(
                    "wp_guardian.maintenance.apply_prepared_plugin_update",
                    side_effect=UpdateApplyError(
                        "Update failed and the plugin snapshot was restored automatically"
                    ),
                ),
                patch("wp_guardian.maintenance.audit_all", return_value=[audit]) as audit_all,
            ):
                result = run_maintenance(config)

            self.assertEqual(result.updated, 0)
            self.assertEqual(result.failed, 1)
            self.assertEqual(result.rolled_back, 1)
            audit_all.assert_called_once_with(config)
            latest = (config.report_dir / "latest.txt").read_text(encoding="utf-8")
            self.assertIn("ROLLED_BACK: plugin safe-plugin 1.0 -> 1.1", latest)
            self.assertIn(str(rollback), latest)

    def test_rendered_report_contains_summary_and_audit(self):
        payload = {
            "generated_at": "2026-08-05T10:00:00+00:00",
            "summary": {
                "sites": 1,
                "updated": 1,
                "skipped": 0,
                "failed": 0,
                "rolled_back": 0,
            },
            "maintenance_sites": [
                {
                    "domain": "example.com",
                    "detection_error": None,
                    "items": [
                        {
                            "kind": "plugin",
                            "name": "safe-plugin",
                            "status": "inactive",
                            "current_version": "1.0",
                            "target_version": "1.1",
                            "action": "updated",
                            "message": "ok",
                            "preparation_id": "a" * 64,
                            "checkpoint_directory": "/backup",
                            "record_path": "/backup/update-applied.json",
                        }
                    ],
                }
            ],
            "final_audit": {
                "generated_at": "2026-08-05T10:01:00+00:00",
                "summary": {
                    "sites": 0,
                    "findings": 0,
                    "severities": {},
                    "worst_severity": "INFO",
                },
                "sites": [],
            },
        }
        text = render_maintenance_text(payload)
        self.assertIn("Updated: 1", text)
        self.assertIn("Preparation ID:", text)
        self.assertIn("FINAL SECURITY AUDIT", text)


if __name__ == "__main__":
    unittest.main()

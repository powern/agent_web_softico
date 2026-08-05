import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from wp_guardian import maintenance
from wp_guardian.config import GuardianConfig
from wp_guardian.maintenance_all_plugins import _detect_site_updates, main
from wp_guardian.models import Site
from wp_guardian.runner import CommandResult
from wp_guardian.update_apply import UpdateApplyError
from wp_guardian.update_apply_all_plugins import apply_prepared_plugin_update


class DetectionWordPress:
    def wp(self, site_path, kind, *args, **kwargs):
        if kind == "plugin":
            payload = [
                {
                    "name": "active-plugin",
                    "status": "active",
                    "version": "1.0",
                    "update_version": "2.0",
                },
                {
                    "name": "inactive-plugin",
                    "status": "inactive",
                    "version": "1.0",
                    "update_version": "2.0",
                },
                {
                    "name": "mu-plugin",
                    "status": "must-use",
                    "version": "1.0",
                    "update_version": "2.0",
                },
            ]
        else:
            payload = [
                {
                    "name": "premium-theme",
                    "status": "active",
                    "version": "1.0",
                    "update_version": "2.0",
                }
            ]
        return CommandResult(["wp"], 0, json.dumps(payload), "")


class ApplyWordPress:
    def __init__(self, *, fail_update=False):
        self.fail_update = fail_update

    def update_plugin(self, site_path, name, target_version, *, timeout=None):
        return CommandResult(
            ["wp", "plugin", "update"],
            1 if self.fail_update else 0,
            "" if self.fail_update else "updated",
            "update failed" if self.fail_update else "",
        )

    def has_checksum_manifest(self, name, version):
        return False

    def verify_core(self, site_path):
        return CommandResult(["wp", "core", "verify-checksums"], 0, "Success", "")


class AllPluginMaintenanceTests(unittest.TestCase):
    def test_detection_includes_active_and_inactive_plugins(self):
        candidates, skipped = _detect_site_updates(
            DetectionWordPress(),
            Path("/srv/example"),
        )

        self.assertEqual(
            [item["name"] for item in candidates],
            ["active-plugin", "inactive-plugin"],
        )
        self.assertEqual(
            {(item.kind, item.name) for item in skipped},
            {("plugin", "mu-plugin"), ("theme", "premium-theme")},
        )

    def test_domain_argument_scopes_discovery_and_final_audit(self):
        first = Site("first.example", Path("/srv/first"))
        second = Site("second.example", Path("/srv/second"))
        config_marker = SimpleNamespace()

        with (
            patch.object(
                maintenance,
                "discover_sites",
                return_value=[first, second],
            ) as original_discovery,
            patch.object(
                maintenance,
                "audit_all",
                return_value=["selected-audit"],
            ) as original_audit,
            patch.object(maintenance, "main") as core_main,
        ):
            def run_core(argv):
                self.assertEqual(argv, ["--config", "/tmp/guardian.toml"])
                selected = maintenance.discover_sites(config_marker)
                self.assertEqual([site.domain for site in selected], ["second.example"])
                self.assertEqual(
                    maintenance.audit_all(config_marker),
                    ["selected-audit"],
                )
                return 0

            core_main.side_effect = run_core
            result = main(
                [
                    "--config",
                    "/tmp/guardian.toml",
                    "--domain",
                    "SECOND.EXAMPLE",
                ]
            )

        self.assertEqual(result, 0)
        original_discovery.assert_called_once_with(config_marker)
        original_audit.assert_called_once_with(
            config_marker,
            domain="second.example",
        )

    def test_active_plugin_update_preserves_active_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            checkpoint = base / "checkpoint"
            checkpoint.mkdir()
            site = Site("example.com", base / "site")
            plan = SimpleNamespace(
                blockers=[],
                backup_directory=str(checkpoint),
                http_status=200,
                http_url="https://example.com/",
                http_time=0.1,
                core_version="7.0.2",
                core_checksum_ok=True,
            )
            validation = (
                checkpoint,
                {},
                base / "plugin",
                base / "plugin.tar.gz",
                "1.0",
                "2.0",
                "active",
            )

            with (
                patch(
                    "wp_guardian.update_apply_all_plugins._validate_preparation",
                    return_value=validation,
                ),
                patch(
                    "wp_guardian.update_apply_all_plugins._component_state",
                    side_effect=[("active", "1.0"), ("active", "2.0")],
                ),
                patch(
                    "wp_guardian.update_apply_all_plugins._require_preflight"
                ),
                patch(
                    "wp_guardian.update_apply_all_plugins.build_update_plan",
                    return_value=plan,
                ),
            ):
                result = apply_prepared_plugin_update(
                    GuardianConfig(),
                    site,
                    ApplyWordPress(),
                    SimpleNamespace(),
                    preparation_id="a" * 64,
                    kind="plugin",
                    name="active-plugin",
                    target_version="2.0",
                )

            self.assertEqual(result.status, "active")
            record = json.loads(result.record_path.read_text(encoding="utf-8"))
            self.assertEqual(record["component"]["status"], "active")

    def test_failed_active_update_restores_snapshot_and_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            checkpoint = base / "checkpoint"
            checkpoint.mkdir()
            site = Site("example.com", base / "site")
            plan = SimpleNamespace(
                blockers=[],
                backup_directory=str(checkpoint),
                http_status=200,
                http_url="https://example.com/",
                http_time=0.1,
                core_version="7.0.2",
                core_checksum_ok=True,
            )
            validation = (
                checkpoint,
                {},
                base / "plugin",
                base / "plugin.tar.gz",
                "1.0",
                "2.0",
                "active",
            )

            with (
                patch(
                    "wp_guardian.update_apply_all_plugins._validate_preparation",
                    return_value=validation,
                ),
                patch(
                    "wp_guardian.update_apply_all_plugins._component_state",
                    side_effect=[("active", "1.0"), ("active", "1.0")],
                ),
                patch(
                    "wp_guardian.update_apply_all_plugins._require_preflight"
                ),
                patch(
                    "wp_guardian.update_apply_all_plugins._restore_component"
                ) as restore_component,
                patch(
                    "wp_guardian.update_apply_all_plugins._restore_status"
                ) as restore_status,
                patch(
                    "wp_guardian.update_apply_all_plugins.build_update_plan",
                    return_value=plan,
                ),
            ):
                with self.assertRaises(UpdateApplyError):
                    apply_prepared_plugin_update(
                        GuardianConfig(),
                        site,
                        ApplyWordPress(fail_update=True),
                        SimpleNamespace(),
                        preparation_id="a" * 64,
                        kind="plugin",
                        name="active-plugin",
                        target_version="2.0",
                    )

            restore_component.assert_called_once()
            restore_status.assert_called_once()
            rollback = json.loads(
                (checkpoint / "update-rollback.json").read_text(encoding="utf-8")
            )
            self.assertEqual(rollback["component"]["status"], "active")
            self.assertTrue(rollback["rolled_back"])


if __name__ == "__main__":
    unittest.main()

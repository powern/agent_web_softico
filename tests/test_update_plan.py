import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from wp_guardian.backup import BackupError
from wp_guardian.backup_verify import BackupVerificationResult
from wp_guardian.config import GuardianConfig
from wp_guardian.models import Site
from wp_guardian.runner import CommandResult
from wp_guardian.update_plan import build_update_plan


class FakeRunner:
    def __init__(self, result: CommandResult | None = None) -> None:
        self.result = result or CommandResult(
            ["curl"],
            0,
            '{"code":200,"time":0.25,"url":"https://example.com/"}',
            "",
        )

    def run(self, args, *, cwd=None, timeout=None):
        return self.result


class FakeWordPress:
    def __init__(
        self,
        *,
        plugin_updates=None,
        theme_updates=None,
        core_ok: bool = True,
    ) -> None:
        self.plugin_updates = plugin_updates or []
        self.theme_updates = theme_updates or []
        self.core_ok = core_ok

    def core_version(self, site_path: Path):
        return "7.0.2"

    def verify_core(self, site_path: Path):
        return CommandResult(
            ["wp", "core", "verify-checksums"],
            0 if self.core_ok else 1,
            "Success" if self.core_ok else "",
            "checksum mismatch" if not self.core_ok else "",
        )

    def list_updates(self, site_path: Path, kind: str):
        return self.plugin_updates if kind == "plugin" else self.theme_updates

    def table_prefix(self, site_path: Path):
        return "wp_"


def verified_backup(base: Path) -> BackupVerificationResult:
    directory = base / "private-backups" / "example.com" / "20260805T080000Z"
    return BackupVerificationResult(
        domain="example.com",
        directory=directory,
        database_path=directory / "database.sql.gz",
        manifest_path=directory / "manifest.json",
        created_at="2026-08-05T08:00:00+00:00",
        compressed_size=100,
        decompressed_size=1000,
        sha256="a" * 64,
        table_prefix="wp_",
        create_table_statements=12,
        matching_tables=12,
        insert_statements=8,
    )


class UpdatePlanTests(unittest.TestCase):
    def test_ready_plan_requires_https_core_backup_and_exact_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            site_path = base / "web" / "example.com" / "public_html"
            site_path.mkdir(parents=True)
            config = GuardianConfig(
                sites_root=base / "web",
                backup_dir=base / "private-backups",
                curl="/usr/bin/curl",
            )
            wordpress = FakeWordPress(
                plugin_updates=[
                    {
                        "name": "example-plugin",
                        "status": "active",
                        "version": "1.0.0",
                        "update_version": "1.1.0",
                    }
                ],
                theme_updates=[
                    {
                        "name": "example-theme",
                        "status": "inactive",
                        "version": "2.0.0",
                        "update_version": "2.1.0",
                    }
                ],
            )

            with patch(
                "wp_guardian.update_plan.verify_database_backup",
                return_value=verified_backup(base),
            ):
                plan = build_update_plan(
                    config,
                    Site("example.com", site_path),
                    wordpress,  # type: ignore[arg-type]
                    FakeRunner(),  # type: ignore[arg-type]
                    now=datetime(2026, 8, 5, 9, 0, tzinfo=timezone.utc),
                )

            self.assertTrue(plan.ready)
            self.assertEqual(plan.blockers, [])
            self.assertEqual(plan.backup_age_seconds, 3600)
            self.assertEqual(
                [(item.kind, item.name, item.target_version) for item in plan.updates],
                [
                    ("plugin", "example-plugin", "1.1.0"),
                    ("theme", "example-theme", "2.1.0"),
                ],
            )

    def test_missing_target_version_blocks_future_update(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            site_path = base / "web" / "example.com" / "public_html"
            site_path.mkdir(parents=True)
            config = GuardianConfig(
                sites_root=base / "web",
                backup_dir=base / "private-backups",
                curl="/usr/bin/curl",
            )
            wordpress = FakeWordPress(
                plugin_updates=[
                    {
                        "name": "private-plugin",
                        "status": "active",
                        "version": "3.0.0",
                    }
                ]
            )

            with patch(
                "wp_guardian.update_plan.verify_database_backup",
                return_value=verified_backup(base),
            ):
                plan = build_update_plan(
                    config,
                    Site("example.com", site_path),
                    wordpress,  # type: ignore[arg-type]
                    FakeRunner(),  # type: ignore[arg-type]
                )

            self.assertFalse(plan.ready)
            self.assertTrue(
                any("Target version is unavailable" in blocker for blocker in plan.blockers)
            )

    def test_invalid_backup_and_failed_https_are_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            site_path = base / "web" / "example.com" / "public_html"
            site_path.mkdir(parents=True)
            config = GuardianConfig(
                sites_root=base / "web",
                backup_dir=base / "private-backups",
                curl="/usr/bin/curl",
            )
            failed_http = FakeRunner(
                CommandResult(["curl"], 28, "", "operation timed out", True)
            )

            with patch(
                "wp_guardian.update_plan.verify_database_backup",
                side_effect=BackupError("checksum mismatch"),
            ):
                plan = build_update_plan(
                    config,
                    Site("example.com", site_path),
                    FakeWordPress(),  # type: ignore[arg-type]
                    failed_http,  # type: ignore[arg-type]
                )

            self.assertFalse(plan.ready)
            self.assertTrue(any("HTTPS preflight failed" in item for item in plan.blockers))
            self.assertTrue(any("checksum mismatch" in item for item in plan.blockers))

    def test_no_updates_is_a_warning_not_a_failed_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            site_path = base / "web" / "example.com" / "public_html"
            site_path.mkdir(parents=True)
            config = GuardianConfig(
                sites_root=base / "web",
                backup_dir=base / "private-backups",
                curl="/usr/bin/curl",
            )

            with patch(
                "wp_guardian.update_plan.verify_database_backup",
                return_value=verified_backup(base),
            ):
                plan = build_update_plan(
                    config,
                    Site("example.com", site_path),
                    FakeWordPress(),  # type: ignore[arg-type]
                    FakeRunner(),  # type: ignore[arg-type]
                )

            self.assertFalse(plan.ready)
            self.assertEqual(plan.blockers, [])
            self.assertEqual(plan.updates, [])
            self.assertIn("No plugin or theme updates are currently available", plan.warnings)


if __name__ == "__main__":
    unittest.main()

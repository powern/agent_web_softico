import json
import os
import stat
import tarfile
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from wp_guardian.config import GuardianConfig
from wp_guardian.models import Site
from wp_guardian.runner import CommandResult
from wp_guardian.update_prepare import UpdatePreparationError, prepare_component_update


class FakeRunner:
    def __init__(self, *, http_ok: bool = True) -> None:
        self.http_ok = http_ok

    def run(self, args, *, cwd=None, timeout=None):
        if self.http_ok:
            return CommandResult(
                [str(item) for item in args],
                0,
                '{"code":200,"time":0.2,"url":"https://example.com/"}',
                "",
            )
        return CommandResult(
            [str(item) for item in args],
            28,
            "",
            "operation timed out",
            True,
        )


class FakeWordPress:
    def __init__(
        self,
        *,
        target_version: str = "1.1.0",
        current_version: str = "1.0.0",
    ) -> None:
        self.target_version = target_version
        self.current_version = current_version

    def list_updates(self, site_path: Path, kind: str):
        if kind != "plugin":
            return []
        return [
            {
                "name": "example-plugin",
                "status": "active",
                "version": self.current_version,
                "update_version": self.target_version,
            }
        ]

    def export_database(self, site_path: Path, target: Path, *, timeout=None):
        target.write_text(
            "CREATE TABLE `wp_options` (id INT);\n"
            "CREATE TABLE `wp_posts` (id INT);\n"
            "INSERT INTO `wp_options` VALUES (1);\n",
            encoding="utf-8",
        )
        return CommandResult(["wp", "db", "export"], 0, str(target), "")

    def core_version(self, site_path: Path):
        return "7.0.2"

    def table_prefix(self, site_path: Path):
        return "wp_"

    def verify_core(self, site_path: Path):
        return CommandResult(["wp", "core", "verify-checksums"], 0, "Success", "")


class UpdatePreparationTests(unittest.TestCase):
    def _fixture(self, base: Path):
        site_path = base / "web" / "example.com" / "public_html"
        plugin_path = site_path / "wp-content" / "plugins" / "example-plugin"
        plugin_path.mkdir(parents=True)
        (plugin_path / "example-plugin.php").write_text(
            "<?php /* Plugin Name: Example */\n",
            encoding="utf-8",
        )
        config = GuardianConfig(
            sites_root=base / "web",
            backup_dir=base / "private-backups",
            curl="/usr/bin/curl",
            backup_keep_last=3,
        )
        return config, Site("example.com", site_path), plugin_path

    def test_creates_verified_database_and_private_component_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config, site, plugin_path = self._fixture(base)

            result = prepare_component_update(
                config,
                site,
                FakeWordPress(),  # type: ignore[arg-type]
                FakeRunner(),  # type: ignore[arg-type]
                kind="plugin",
                name="example-plugin",
                target_version="1.1.0",
                now=datetime(2026, 8, 5, 9, 30, tzinfo=timezone.utc),
            )

            self.assertEqual(result.directory.name, "20260805T093000Z")
            self.assertTrue(result.database_path.is_file())
            self.assertTrue(result.component_archive.is_file())
            self.assertTrue(result.manifest_path.is_file())
            self.assertEqual(stat.S_IMODE(result.component_archive.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(result.manifest_path.stat().st_mode), 0o600)
            self.assertEqual(result.backups_removed, 0)

            with tarfile.open(result.component_archive, "r:gz") as archive:
                names = archive.getnames()
            self.assertIn(plugin_path.name, names)
            self.assertIn(
                f"{plugin_path.name}/example-plugin.php",
                names,
            )

            manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["preparation_id"], result.preparation_id)
            self.assertEqual(manifest["component"]["kind"], "plugin")
            self.assertEqual(manifest["component"]["name"], "example-plugin")
            self.assertEqual(manifest["component"]["current_version"], "1.0.0")
            self.assertEqual(manifest["component"]["target_version"], "1.1.0")
            self.assertEqual(
                manifest["component"]["archive"]["sha256"],
                result.component_archive_sha256,
            )
            self.assertEqual(manifest["database"]["sha256"], result.database_sha256)
            self.assertTrue(manifest["preflight"]["core_checksum_ok"])

    def test_target_mismatch_is_rejected_before_creating_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config, site, _ = self._fixture(base)

            with self.assertRaisesRegex(UpdatePreparationError, "Target version mismatch"):
                prepare_component_update(
                    config,
                    site,
                    FakeWordPress(),  # type: ignore[arg-type]
                    FakeRunner(),  # type: ignore[arg-type]
                    kind="plugin",
                    name="example-plugin",
                    target_version="9.9.9",
                )

            self.assertFalse((config.backup_dir / site.domain).exists())

    def test_failed_post_backup_preflight_removes_new_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config, site, _ = self._fixture(base)

            with self.assertRaisesRegex(UpdatePreparationError, "preflight has blockers"):
                prepare_component_update(
                    config,
                    site,
                    FakeWordPress(),  # type: ignore[arg-type]
                    FakeRunner(http_ok=False),  # type: ignore[arg-type]
                    kind="plugin",
                    name="example-plugin",
                    target_version="1.1.0",
                    now=datetime(2026, 8, 5, 9, 30, tzinfo=timezone.utc),
                )

            domain_root = config.backup_dir / site.domain
            self.assertTrue(domain_root.is_dir())
            self.assertEqual(list(domain_root.iterdir()), [])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_component_symlink_is_rejected_before_creating_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config, site, plugin_path = self._fixture(base)
            outside = base / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            os.symlink(outside, plugin_path / "unsafe-link")

            with self.assertRaisesRegex(UpdatePreparationError, "refuses symlink"):
                prepare_component_update(
                    config,
                    site,
                    FakeWordPress(),  # type: ignore[arg-type]
                    FakeRunner(),  # type: ignore[arg-type]
                    kind="plugin",
                    name="example-plugin",
                    target_version="1.1.0",
                )

            self.assertFalse((config.backup_dir / site.domain).exists())


if __name__ == "__main__":
    unittest.main()

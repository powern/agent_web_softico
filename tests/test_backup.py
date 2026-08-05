import gzip
import json
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from wp_guardian.backup import BackupError, create_database_backup, prepare_backup_root
from wp_guardian.config import GuardianConfig
from wp_guardian.models import Site
from wp_guardian.runner import CommandResult


class FakeWordPress:
    def __init__(self, *, fail: bool = False, empty: bool = False) -> None:
        self.fail = fail
        self.empty = empty
        self.export_target: Path | None = None

    def export_database(self, site_path: Path, target: Path, *, timeout: int | None = None):
        self.export_target = target
        if self.fail:
            return CommandResult(["wp", "db", "export"], 1, "", "export failed")
        target.write_bytes(b"" if self.empty else b"CREATE TABLE example (id INT);\n")
        return CommandResult(["wp", "db", "export"], 0, str(target), "")

    def core_version(self, site_path: Path) -> str:
        return "7.0.2"


class BackupTests(unittest.TestCase):
    def test_creates_private_compressed_database_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            site_path = base / "web" / "example.com" / "public_html"
            site_path.mkdir(parents=True)
            backup_dir = base / "private-backups"
            config = GuardianConfig(
                sites_root=base / "web",
                backup_dir=backup_dir,
                backup_timeout=600,
            )
            wordpress = FakeWordPress()

            result = create_database_backup(
                config,
                Site("example.com", site_path),
                wordpress,  # type: ignore[arg-type]
                now=datetime(2026, 8, 5, 8, 15, tzinfo=timezone.utc),
            )

            self.assertEqual(result.directory.name, "20260805T081500Z")
            self.assertEqual(stat.S_IMODE(result.directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(result.database_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(result.manifest_path.stat().st_mode), 0o600)
            with gzip.open(result.database_path, "rb") as handle:
                self.assertEqual(handle.read(), b"CREATE TABLE example (id INT);\n")

            manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["domain"], "example.com")
            self.assertEqual(manifest["wordpress_core_version"], "7.0.2")
            self.assertEqual(manifest["database"]["size"], result.size)
            self.assertEqual(manifest["database"]["sha256"], result.sha256)
            self.assertFalse(any(path.name.startswith(".") for path in result.directory.parent.iterdir()))

    def test_failed_export_leaves_no_backup_or_staging_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            site_path = base / "web" / "example.com" / "public_html"
            site_path.mkdir(parents=True)
            config = GuardianConfig(
                sites_root=base / "web",
                backup_dir=base / "private-backups",
            )

            with self.assertRaisesRegex(BackupError, "export failed"):
                create_database_backup(
                    config,
                    Site("example.com", site_path),
                    FakeWordPress(fail=True),  # type: ignore[arg-type]
                )

            domain_root = config.backup_dir / "example.com"
            self.assertTrue(domain_root.is_dir())
            self.assertEqual(list(domain_root.iterdir()), [])

    def test_empty_export_is_rejected_and_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            site_path = base / "web" / "example.com" / "public_html"
            site_path.mkdir(parents=True)
            config = GuardianConfig(
                sites_root=base / "web",
                backup_dir=base / "private-backups",
            )

            with self.assertRaisesRegex(BackupError, "missing or empty"):
                create_database_backup(
                    config,
                    Site("example.com", site_path),
                    FakeWordPress(empty=True),  # type: ignore[arg-type]
                )

            self.assertEqual(list((config.backup_dir / "example.com").iterdir()), [])

    def test_rejects_backup_directory_inside_sites_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            sites_root = base / "web"
            sites_root.mkdir()
            config = GuardianConfig(
                sites_root=sites_root,
                backup_dir=sites_root / "example.com" / "public_html" / "backups",
            )

            with self.assertRaisesRegex(BackupError, "outside the public sites tree"):
                prepare_backup_root(config)


if __name__ == "__main__":
    unittest.main()

import gzip
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from wp_guardian.backup import BackupError, create_database_backup
from wp_guardian.backup_verify import verify_database_backup
from wp_guardian.config import GuardianConfig
from wp_guardian.models import Site
from wp_guardian.runner import CommandResult


SQL_PAYLOAD = (
    b"-- MySQL dump\n"
    b"DROP TABLE IF EXISTS `wp_options`;\n"
    b"CREATE TABLE `wp_options` (`option_id` bigint NOT NULL);\n"
    b"INSERT INTO `wp_options` VALUES (1);\n"
    b"CREATE TABLE `wp_users` (`ID` bigint NOT NULL);\n"
)


class FakeWordPress:
    def __init__(self, payload: bytes = SQL_PAYLOAD, prefix: str = "wp_") -> None:
        self.payload = payload
        self.prefix = prefix

    def export_database(
        self,
        site_path: Path,
        target: Path,
        *,
        timeout: int | None = None,
    ) -> CommandResult:
        target.write_bytes(self.payload)
        return CommandResult(["wp", "db", "export"], 0, str(target), "")

    def core_version(self, site_path: Path) -> str:
        return "7.0.2"

    def table_prefix(self, site_path: Path) -> str:
        return self.prefix


class BackupVerificationTests(unittest.TestCase):
    def make_environment(self, directory: str):
        base = Path(directory)
        site_path = base / "web" / "example.com" / "public_html"
        site_path.mkdir(parents=True)
        config = GuardianConfig(
            sites_root=base / "web",
            backup_dir=base / "private-backups",
            backup_keep_last=3,
        )
        site = Site("example.com", site_path)
        return config, site

    @staticmethod
    def rewrite_manifest_for_database(backup_dir: Path) -> None:
        database_path = backup_dir / "database.sql.gz"
        manifest_path = backup_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["database"]["size"] = database_path.stat().st_size
        manifest["database"]["sha256"] = hashlib.sha256(
            database_path.read_bytes()
        ).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(manifest_path, 0o600)

    def test_verifies_latest_backup_manifest_gzip_checksum_and_sql(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config, site = self.make_environment(directory)
            wordpress = FakeWordPress()
            created = create_database_backup(
                config,
                site,
                wordpress,  # type: ignore[arg-type]
                now=datetime(2026, 8, 5, 8, 35, 14, tzinfo=timezone.utc),
            )

            result = verify_database_backup(
                config,
                site,
                wordpress,  # type: ignore[arg-type]
            )

            self.assertEqual(result.directory, created.directory)
            self.assertEqual(result.sha256, created.sha256)
            self.assertEqual(result.table_prefix, "wp_")
            self.assertEqual(result.create_table_statements, 2)
            self.assertEqual(result.matching_tables, 2)
            self.assertEqual(result.insert_statements, 1)
            self.assertEqual(result.decompressed_size, len(SQL_PAYLOAD))

    def test_can_verify_an_explicit_backup_directory_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config, site = self.make_environment(directory)
            wordpress = FakeWordPress()
            first = create_database_backup(
                config,
                site,
                wordpress,  # type: ignore[arg-type]
                now=datetime(2026, 8, 4, 8, 0, tzinfo=timezone.utc),
            )
            create_database_backup(
                config,
                site,
                wordpress,  # type: ignore[arg-type]
                now=datetime(2026, 8, 5, 8, 0, tzinfo=timezone.utc),
            )

            result = verify_database_backup(
                config,
                site,
                wordpress,  # type: ignore[arg-type]
                backup_name=first.directory.name,
            )

            self.assertEqual(result.directory, first.directory)

    def test_latest_corrupt_manifest_is_reported_not_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config, site = self.make_environment(directory)
            wordpress = FakeWordPress()
            create_database_backup(
                config,
                site,
                wordpress,  # type: ignore[arg-type]
                now=datetime(2026, 8, 4, 8, 0, tzinfo=timezone.utc),
            )
            latest = create_database_backup(
                config,
                site,
                wordpress,  # type: ignore[arg-type]
                now=datetime(2026, 8, 5, 8, 0, tzinfo=timezone.utc),
            )
            latest.manifest_path.write_text("not json", encoding="utf-8")

            with self.assertRaisesRegex(BackupError, "Could not read backup manifest"):
                verify_database_backup(
                    config,
                    site,
                    wordpress,  # type: ignore[arg-type]
                )

    def test_rejects_archive_sha256_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config, site = self.make_environment(directory)
            wordpress = FakeWordPress()
            created = create_database_backup(
                config,
                site,
                wordpress,  # type: ignore[arg-type]
            )
            with created.database_path.open("ab") as handle:
                handle.write(b"tamper")
            manifest = json.loads(created.manifest_path.read_text(encoding="utf-8"))
            manifest["database"]["size"] = created.database_path.stat().st_size
            created.manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )
            os.chmod(created.manifest_path, 0o600)

            with self.assertRaisesRegex(BackupError, "SHA-256 does not match"):
                verify_database_backup(
                    config,
                    site,
                    wordpress,  # type: ignore[arg-type]
                )

    def test_rejects_invalid_gzip_even_when_manifest_matches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config, site = self.make_environment(directory)
            wordpress = FakeWordPress()
            created = create_database_backup(
                config,
                site,
                wordpress,  # type: ignore[arg-type]
            )
            created.database_path.write_bytes(b"not a gzip stream")
            os.chmod(created.database_path, 0o600)
            self.rewrite_manifest_for_database(created.directory)

            with self.assertRaisesRegex(BackupError, "valid complete gzip stream"):
                verify_database_backup(
                    config,
                    site,
                    wordpress,  # type: ignore[arg-type]
                )

    def test_rejects_sql_without_current_wordpress_table_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config, site = self.make_environment(directory)
            wordpress = FakeWordPress()
            created = create_database_backup(
                config,
                site,
                wordpress,  # type: ignore[arg-type]
            )
            with gzip.open(created.database_path, "wb") as handle:
                handle.write(b"CREATE TABLE `other_options` (`id` bigint);\n")
            os.chmod(created.database_path, 0o600)
            self.rewrite_manifest_for_database(created.directory)

            with self.assertRaisesRegex(BackupError, "no tables with WordPress prefix"):
                verify_database_backup(
                    config,
                    site,
                    wordpress,  # type: ignore[arg-type]
                )

    def test_rejects_broad_backup_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config, site = self.make_environment(directory)
            wordpress = FakeWordPress()
            created = create_database_backup(
                config,
                site,
                wordpress,  # type: ignore[arg-type]
            )
            os.chmod(created.database_path, 0o644)

            with self.assertRaisesRegex(BackupError, "permissions are too broad"):
                verify_database_backup(
                    config,
                    site,
                    wordpress,  # type: ignore[arg-type]
                )

    def test_rejects_path_traversal_as_backup_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config, site = self.make_environment(directory)
            wordpress = FakeWordPress()
            create_database_backup(
                config,
                site,
                wordpress,  # type: ignore[arg-type]
            )

            with self.assertRaisesRegex(BackupError, "Invalid backup directory name"):
                verify_database_backup(
                    config,
                    site,
                    wordpress,  # type: ignore[arg-type]
                    backup_name="../outside",
                )


if __name__ == "__main__":
    unittest.main()

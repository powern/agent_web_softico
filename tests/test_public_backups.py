import tempfile
import unittest
from collections import Counter
from pathlib import Path

from wp_guardian.config import GuardianConfig
from wp_guardian.models import SiteAudit
from wp_guardian.public_backups import classify_public_backup, scan_public_backups


class PublicBackupScannerTests(unittest.TestCase):
    def test_classifies_sensitive_artifacts(self) -> None:
        self.assertEqual(classify_public_backup("database.sql")[1], "CRITICAL")
        self.assertEqual(classify_public_backup("wp-config.php.bak")[1], "CRITICAL")
        self.assertEqual(classify_public_backup("wp-content/backups/site.jpa")[1], "HIGH")
        self.assertEqual(classify_public_backup("wp-content/updraft/site.zip")[1], "HIGH")

    def test_does_not_flag_ordinary_download_archive(self) -> None:
        self.assertIsNone(
            classify_public_backup("wp-content/uploads/downloads/product-manual.zip")
        )

    def test_ignores_small_sql_schema_assets_inside_plugins(self) -> None:
        paths = (
            "wp-content/plugins/litespeed-cache/src/data_structure/url_file.sql",
            "wp-content/plugins/litespeed-cache/src/data_structure/img_optming.sql",
            "wp-content/plugins/litespeed-cache/src/data_structure/crawler.sql",
        )
        for relative in paths:
            with self.subTest(relative=relative):
                self.assertIsNone(classify_public_backup(relative, size=1024))

    def test_ignores_bundled_plugin_source_archive(self) -> None:
        self.assertIsNone(
            classify_public_backup(
                "wp-content/plugins/royal-elementor-addons.tar.gz",
                size=4_078_486,
            )
        )

    def test_still_flags_real_backup_storage_inside_components(self) -> None:
        result = classify_public_backup(
            "wp-content/plugins/example-plugin/backups/site.jpa",
            size=2048,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[1], "HIGH")

    def test_still_flags_database_named_component_sql(self) -> None:
        result = classify_public_backup(
            "wp-content/plugins/example-plugin/database.sql",
            size=2048,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[1], "CRITICAL")

    def test_still_flags_large_component_sql(self) -> None:
        result = classify_public_backup(
            "wp-content/plugins/example-plugin/resources/data.sql",
            size=2 * 1024 * 1024,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result[1], "CRITICAL")

    def test_scans_and_reports_public_backups(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            files = {
                "database.sql": b"CREATE TABLE example(id INT);",
                "wp-config.php.bak": b"<?php define('DB_PASSWORD', 'secret');",
                "wp-content/backups/site-example.jpa": b"JPA",
                "wp-content/uploads/downloads/manual.zip": b"ZIP",
            }
            for relative, payload in files.items():
                path = site / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)

            config = GuardianConfig(max_scan_files=100)
            audit = SiteAudit("example.com", str(site))
            scan_public_backups(site, config, audit)

            facts = audit.facts["public_backups"]
            self.assertEqual(facts["scanned"], 4)
            self.assertEqual(facts["found"], 3)
            self.assertTrue(facts["complete"])
            self.assertEqual(
                Counter(finding.severity for finding in audit.findings),
                Counter({"CRITICAL": 2, "HIGH": 1}),
            )

    def test_user_reported_plugin_assets_are_ignored_but_updraft_remains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            files = {
                "wp-content/plugins/royal-elementor-addons.tar.gz": b"package",
                "wp-content/plugins/litespeed-cache/src/data_structure/url.sql": b"schema",
                "wp-content/plugins/litespeed-cache/src/data_structure/crawler.sql": b"schema",
                "wp-content/updraft/backup_2025-10-17-site-db.gz": b"backup",
                "wp-content/updraft/backup_2025-10-17-site-plugins.zip": b"backup",
            }
            for relative, payload in files.items():
                path = site / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)

            config = GuardianConfig(max_scan_files=100)
            audit = SiteAudit("example.com", str(site))
            scan_public_backups(site, config, audit)

            facts = audit.facts["public_backups"]
            self.assertEqual(facts["scanned"], 5)
            self.assertEqual(facts["found"], 2)
            self.assertTrue(facts["complete"])
            self.assertEqual(
                {finding.details["relative"] for finding in audit.findings},
                {
                    "wp-content/updraft/backup_2025-10-17-site-db.gz",
                    "wp-content/updraft/backup_2025-10-17-site-plugins.zip",
                },
            )

    def test_allow_list_supports_exact_path_and_directory_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            exact = site / "database.sql"
            exact.write_text("safe fixture", encoding="utf-8")
            directory_path = site / "wp-content" / "backups" / "site.jpa"
            directory_path.parent.mkdir(parents=True)
            directory_path.write_text("safe fixture", encoding="utf-8")

            config = GuardianConfig(
                max_scan_files=100,
                allow_public_backup_paths=(
                    "database.sql",
                    "wp-content/backups/",
                ),
            )
            audit = SiteAudit("example.com", str(site))
            scan_public_backups(site, config, audit)

            self.assertEqual(audit.facts["public_backups"]["found"], 0)
            self.assertEqual(audit.findings, [])


if __name__ == "__main__":
    unittest.main()

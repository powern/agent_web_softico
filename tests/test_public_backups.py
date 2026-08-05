import tempfile
import unittest
from collections import Counter
from pathlib import Path

from wp_guardian.config import GuardianConfig
from wp_guardian.models import SiteAudit
from wp_guardian.scanner import classify_public_backup, scan_public_backups


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

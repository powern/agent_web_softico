import tempfile
import unittest
from pathlib import Path

from wp_guardian.config import GuardianConfig
from wp_guardian.models import SiteAudit
from wp_guardian.scanner import scan_uploads


class ScannerLimitTests(unittest.TestCase):
    def test_media_files_do_not_consume_php_candidate_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            uploads = site / "wp-content" / "uploads"
            media = uploads / "2026" / "08"
            media.mkdir(parents=True)
            for index in range(25):
                (media / f"image-{index:02d}.jpg").write_bytes(b"jpeg")

            guard = uploads / "zz-service" / "index.php"
            guard.parent.mkdir(parents=True)
            guard.write_text("<?php exit; ?>", encoding="utf-8")

            config = GuardianConfig(
                allow_php_upload_paths=("zz-service/index.php",),
                max_scan_files=1,
            )
            audit = SiteAudit("example.com", str(site))
            scan_uploads(site, config, audit)

            facts = audit.facts["uploads_php"]
            self.assertEqual(facts["scanned_files"], 26)
            self.assertEqual(facts["php_files"], 1)
            self.assertTrue(facts["complete"])

    def test_php_candidate_limit_stops_excessive_executables(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            uploads = site / "wp-content" / "uploads"
            uploads.mkdir(parents=True)
            (uploads / "one.php").write_text("<?php exit; ?>", encoding="utf-8")
            (uploads / "two.php").write_text("<?php exit; ?>", encoding="utf-8")

            config = GuardianConfig(max_scan_files=1)
            audit = SiteAudit("example.com", str(site))
            scan_uploads(site, config, audit)

            facts = audit.facts["uploads_php"]
            self.assertEqual(facts["php_files"], 1)
            self.assertFalse(facts["complete"])
            self.assertTrue(
                any(
                    finding.message
                    == "Uploads scan stopped at configured PHP candidate limit"
                    for finding in audit.findings
                )
            )


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from wp_guardian.config import GuardianConfig
from wp_guardian.models import SiteAudit
from wp_guardian.scanner import scan_uploads


class ScannerTests(unittest.TestCase):
    def test_allows_known_guard_and_flags_shell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            uploads = site / "wp-content" / "uploads"
            safe = uploads / "wpseo-redirects" / "index.php"
            safe.parent.mkdir(parents=True)
            safe.write_text("<?php exit(0); ?>", encoding="utf-8")
            shell = uploads / "2026" / "08" / "image.php"
            shell.parent.mkdir(parents=True)
            shell.write_text("<?php eval(base64_decode($_POST['x']));", encoding="utf-8")
            config = GuardianConfig(
                allow_php_upload_paths=("wpseo-redirects/index.php",),
                max_scan_files=100,
            )
            audit = SiteAudit("example.com", str(site))
            scan_uploads(site, config, audit)
            self.assertEqual(audit.facts["uploads_php"]["files"], 2)
            self.assertEqual(audit.facts["uploads_php"]["suspicious"], 1)
            self.assertEqual(audit.findings[0].severity, "CRITICAL")
            self.assertIn("base64_decode", audit.findings[0].details["patterns"])


if __name__ == "__main__":
    unittest.main()

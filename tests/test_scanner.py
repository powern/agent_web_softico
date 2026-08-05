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
            facts = audit.facts["uploads_php"]
            self.assertEqual(facts["scanned_files"], 2)
            self.assertEqual(facts["php_files"], 2)
            self.assertEqual(facts["suspicious"], 1)
            self.assertTrue(facts["complete"])
            self.assertEqual(audit.findings[0].severity, "CRITICAL")
            self.assertIn("base64_decode", audit.findings[0].details["patterns"])

    def test_allows_exact_wpforms_404_guards(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            uploads = site / "wp-content" / "uploads"
            payload = (
                "<?php\n"
                "header( $_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found' );\n"
                "header( 'Status: 404 Not Found' );\n"
            )
            for relative in (
                "wpforms/cache/index.php",
                "wpforms/cache/templates/index.php",
            ):
                path = uploads / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(payload, encoding="utf-8")

            config = GuardianConfig(
                allow_php_upload_paths=(
                    "wpforms/cache/index.php",
                    "wpforms/cache/templates/index.php",
                ),
                max_scan_files=100,
            )
            audit = SiteAudit("example.com", str(site))
            scan_uploads(site, config, audit)

            facts = audit.facts["uploads_php"]
            self.assertEqual(facts["php_files"], 2)
            self.assertEqual(facts["suspicious"], 0)
            self.assertEqual(audit.findings, [])

    def test_rejects_code_appended_to_wpforms_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            guard = site / "wp-content" / "uploads" / "wpforms" / "cache" / "index.php"
            guard.parent.mkdir(parents=True)
            guard.write_text(
                "<?php\n"
                "header( $_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found' );\n"
                "header( 'Status: 404 Not Found' );\n"
                "echo shell_exec($_GET['cmd']);\n",
                encoding="utf-8",
            )

            config = GuardianConfig(
                allow_php_upload_paths=("wpforms/cache/index.php",),
                max_scan_files=100,
            )
            audit = SiteAudit("example.com", str(site))
            scan_uploads(site, config, audit)

            self.assertEqual(audit.facts["uploads_php"]["suspicious"], 1)
            self.assertEqual(audit.findings[0].severity, "CRITICAL")
            self.assertIn("shell_exec", audit.findings[0].details["patterns"])

    def test_directories_do_not_consume_scan_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            uploads = site / "wp-content" / "uploads"
            current = uploads
            for index in range(25):
                current = current / f"level-{index}"
                current.mkdir(parents=True)
            guard = current / "index.php"
            guard.write_text("<?php exit; ?>", encoding="utf-8")

            config = GuardianConfig(
                allow_php_upload_paths=(),
                max_scan_files=1,
            )
            audit = SiteAudit("example.com", str(site))
            scan_uploads(site, config, audit)

            facts = audit.facts["uploads_php"]
            self.assertEqual(facts["scanned_files"], 1)
            self.assertEqual(facts["php_files"], 1)
            self.assertTrue(facts["complete"])
            self.assertFalse(
                any(
                    finding.message == "Uploads scan stopped at configured file limit"
                    for finding in audit.findings
                )
            )


if __name__ == "__main__":
    unittest.main()

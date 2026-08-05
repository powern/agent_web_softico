import unittest

from wp_guardian.reporting import finding_label, update_label


class ReportingTests(unittest.TestCase):
    def test_update_label_uses_target_version(self) -> None:
        self.assertEqual(
            update_label(
                {
                    "name": "example-plugin",
                    "version": "1.0.0",
                    "update_version": "1.1.0",
                }
            ),
            "example-plugin 1.0.0 -> 1.1.0",
        )

    def test_update_label_explains_missing_target_version(self) -> None:
        self.assertEqual(
            update_label(
                {
                    "name": "private-plugin",
                    "version": "2.0.0",
                    "update": "available",
                }
            ),
            "private-plugin 2.0.0 -> available (target version not provided)",
        )

    def test_permission_finding_includes_mode_and_path(self) -> None:
        self.assertEqual(
            finding_label(
                {
                    "severity": "MEDIUM",
                    "check": "permissions",
                    "message": "World-writable file detected",
                    "details": {
                        "mode": "0o666",
                        "path": "/srv/site/wp-content/cache/file.css",
                    },
                }
            ),
            "- MEDIUM permissions: 0o666 /srv/site/wp-content/cache/file.css",
        )

    def test_upload_finding_includes_path_and_patterns(self) -> None:
        self.assertEqual(
            finding_label(
                {
                    "severity": "CRITICAL",
                    "check": "uploads_php",
                    "message": "Unexpected executable file in uploads",
                    "details": {
                        "path": "/srv/site/wp-content/uploads/shell.php",
                        "patterns": ["eval", "base64_decode"],
                    },
                }
            ),
            "- CRITICAL uploads_php: /srv/site/wp-content/uploads/shell.php patterns=eval,base64_decode",
        )


if __name__ == "__main__":
    unittest.main()

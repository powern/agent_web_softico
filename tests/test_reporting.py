import unittest

from wp_guardian.reporting import update_label


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


if __name__ == "__main__":
    unittest.main()

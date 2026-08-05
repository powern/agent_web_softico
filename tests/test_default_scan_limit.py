from pathlib import Path
import unittest

from wp_guardian.config import GuardianConfig


class DefaultScanLimitTests(unittest.TestCase):
    def test_runtime_default_covers_large_wordpress_sites(self) -> None:
        self.assertEqual(GuardianConfig().max_scan_files, 200000)

    def test_example_config_uses_same_default(self) -> None:
        example = Path("config/guardian.toml.example").read_text(encoding="utf-8")
        self.assertIn("max_scan_files = 200000", example)


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from wp_guardian.config import GuardianConfig
from wp_guardian.discovery import discover_sites


class DiscoveryTests(unittest.TestCase):
    def test_discovers_only_wordpress_and_respects_filters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for domain in ("a.example", "b.example", "ignored.example"):
                site = root / domain / "public_html"
                (site / "wp-admin").mkdir(parents=True)
                (site / "wp-config.php").write_text("<?php", encoding="utf-8")
            config = GuardianConfig(
                sites_root=root,
                include={"a.example", "ignored.example"},
                exclude={"ignored.example"},
            )
            domains = [site.domain for site in discover_sites(config)]
            self.assertEqual(domains, ["a.example"])


if __name__ == "__main__":
    unittest.main()

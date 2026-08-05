import json
import unittest
from pathlib import Path
from unittest.mock import patch

from wp_guardian import maintenance
from wp_guardian.maintenance_all_plugins import main
from wp_guardian.runner import CommandResult


class DetectionWordPress:
    def wp(self, site_path, kind, *args, **kwargs):
        if kind == "plugin":
            payload = [
                {
                    "name": "elementskit",
                    "status": "active",
                    "version": "4.4.0",
                    "update_version": "4.5.3",
                },
                {
                    "name": "woocommerce",
                    "status": "active",
                    "version": "10.9.4",
                    "update_version": "11.0.0",
                },
            ]
        else:
            payload = []
        return CommandResult(["wp"], 0, json.dumps(payload), "")


class PluginScopedMaintenanceTests(unittest.TestCase):
    def test_plugin_argument_selects_only_exact_plugin(self):
        def run_core(argv):
            self.assertEqual(argv, ["--config", "/tmp/guardian.toml"])
            candidates, skipped = maintenance._detect_site_updates(
                DetectionWordPress(),
                Path("/srv/tech-future"),
            )
            self.assertEqual(
                [row["name"] for row in candidates],
                ["woocommerce"],
            )
            self.assertEqual(skipped, [])
            return 0

        with patch.object(maintenance, "main", side_effect=run_core):
            result = main(
                [
                    "--config",
                    "/tmp/guardian.toml",
                    "--domain",
                    "tech-future.eu",
                    "--plugin",
                    "woocommerce",
                ]
            )

        self.assertEqual(result, 0)

    def test_plugin_argument_requires_domain(self):
        with self.assertRaises(SystemExit):
            main(["--plugin", "woocommerce"])


if __name__ == "__main__":
    unittest.main()

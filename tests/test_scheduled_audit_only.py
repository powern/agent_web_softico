import unittest
from pathlib import Path


class ScheduledAuditOnlyTests(unittest.TestCase):
    def test_systemd_service_runs_read_only_audit(self):
        service = (
            Path(__file__).resolve().parents[1]
            / "systemd"
            / "wp-guardian.service"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "ExecStart=/opt/wp-guardian/venv/bin/wp-guardian "
            "--config /etc/wp-guardian/guardian.toml audit",
            service,
        )
        self.assertNotIn("wp-guardian-maintenance", service)
        self.assertNotIn("ReadWritePaths=/home/admin/web", service)
        self.assertNotIn(
            "ReadWritePaths=/home/admin/private-backups/wp-guardian",
            service,
        )
        self.assertIn("OnSuccess=wp-guardian-mail.service", service)
        self.assertIn("SuccessExitStatus=2", service)


if __name__ == "__main__":
    unittest.main()

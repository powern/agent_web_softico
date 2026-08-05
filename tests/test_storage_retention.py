import tempfile
import unittest
from pathlib import Path

from wp_guardian.storage import Storage


class StorageRetentionTests(unittest.TestCase):
    def test_prunes_old_runs_and_keeps_admin_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            storage = Storage(Path(directory) / "guardian.sqlite3")
            old_run = storage.start_run("2026-07-30T03:00:00+00:00", "audit")
            new_run = storage.start_run("2026-08-05T03:00:00+00:00", "audit")

            storage.connection.execute(
                "INSERT INTO site_audits(run_id, domain, payload_json) VALUES (?, ?, ?)",
                (old_run, "old.example", "{}"),
            )
            storage.connection.execute(
                "INSERT INTO site_audits(run_id, domain, payload_json) VALUES (?, ?, ?)",
                (new_run, "new.example", "{}"),
            )
            storage.connection.execute(
                "INSERT INTO admin_baseline(domain, user_login) VALUES (?, ?)",
                ("example.com", "admin"),
            )
            storage.connection.commit()

            removed = storage.prune_runs_before("2026-08-03T00:00:00+00:00")

            self.assertEqual(removed, 1)
            self.assertEqual(
                storage.connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0],
                1,
            )
            self.assertEqual(
                storage.connection.execute("SELECT COUNT(*) FROM site_audits").fetchone()[0],
                1,
            )
            self.assertEqual(
                storage.connection.execute("SELECT COUNT(*) FROM admin_baseline").fetchone()[0],
                1,
            )


if __name__ == "__main__":
    unittest.main()

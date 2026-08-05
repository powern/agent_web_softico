import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from wp_guardian.retention import business_day_cutoff, prune_report_files


class RetentionTests(unittest.TestCase):
    def test_three_business_days_from_wednesday(self) -> None:
        now = datetime(2026, 8, 5, 9, 0, tzinfo=timezone.utc)  # Wednesday
        cutoff = business_day_cutoff(3, now)
        self.assertEqual(cutoff, datetime(2026, 8, 3, 0, 0, tzinfo=timezone.utc))

    def test_three_business_days_from_monday_crosses_weekend(self) -> None:
        now = datetime(2026, 8, 3, 9, 0, tzinfo=timezone.utc)  # Monday
        cutoff = business_day_cutoff(3, now)
        self.assertEqual(cutoff, datetime(2026, 7, 30, 0, 0, tzinfo=timezone.utc))

    def test_prunes_only_timestamped_audit_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            old_txt = report_dir / "audit-20260730-030000.txt"
            old_json = report_dir / "audit-20260730-030000.json"
            new_txt = report_dir / "audit-20260805-030000.txt"
            latest_txt = report_dir / "latest.txt"
            unrelated = report_dir / "manual-note.txt"

            for path in (old_txt, old_json, new_txt, latest_txt, unrelated):
                path.write_text(path.name, encoding="utf-8")

            old_timestamp = datetime(2026, 7, 30, 3, 0, tzinfo=timezone.utc).timestamp()
            new_timestamp = datetime(2026, 8, 5, 3, 0, tzinfo=timezone.utc).timestamp()
            os.utime(old_txt, (old_timestamp, old_timestamp))
            os.utime(old_json, (old_timestamp, old_timestamp))
            os.utime(new_txt, (new_timestamp, new_timestamp))

            removed = prune_report_files(
                report_dir,
                datetime(2026, 8, 3, 0, 0, tzinfo=timezone.utc),
            )

            self.assertEqual(removed, 2)
            self.assertFalse(old_txt.exists())
            self.assertFalse(old_json.exists())
            self.assertTrue(new_txt.exists())
            self.assertTrue(latest_txt.exists())
            self.assertTrue(unrelated.exists())


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import SiteAudit

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    command TEXT NOT NULL,
    report_path TEXT
);
CREATE TABLE IF NOT EXISTS site_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES runs(id)
);
CREATE TABLE IF NOT EXISTS admin_baseline (
    domain TEXT NOT NULL,
    user_login TEXT NOT NULL,
    first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(domain, user_login)
);
"""


class Storage:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def start_run(self, started_at: str, command: str) -> int:
        cursor = self.connection.execute(
            "INSERT INTO runs(started_at, command) VALUES (?, ?)",
            (started_at, command),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def save_site_audit(self, run_id: int, audit: SiteAudit) -> None:
        self.connection.execute(
            "INSERT INTO site_audits(run_id, domain, payload_json) VALUES (?, ?, ?)",
            (run_id, audit.domain, json.dumps(audit.to_dict(), ensure_ascii=False)),
        )
        self.connection.commit()

    def compare_admins(self, domain: str, logins: set[str]) -> set[str]:
        rows = self.connection.execute(
            "SELECT user_login FROM admin_baseline WHERE domain = ?",
            (domain,),
        ).fetchall()
        known = {str(row[0]) for row in rows}
        new = logins - known
        for login in logins:
            self.connection.execute(
                """
                INSERT INTO admin_baseline(domain, user_login)
                VALUES (?, ?)
                ON CONFLICT(domain, user_login)
                DO UPDATE SET last_seen = CURRENT_TIMESTAMP
                """,
                (domain, login),
            )
        self.connection.commit()
        return new if known else set()

    def finish_run(self, run_id: int, finished_at: str, report_path: str) -> None:
        self.connection.execute(
            "UPDATE runs SET finished_at = ?, report_path = ? WHERE id = ?",
            (finished_at, report_path, run_id),
        )
        self.connection.commit()

    def prune_runs_before(self, cutoff_iso: str) -> int:
        """Remove historical audit payloads older than cutoff.

        The administrator baseline is intentionally retained because it is
        security state, not audit-log history.
        """
        rows = self.connection.execute(
            "SELECT id FROM runs WHERE started_at < ?",
            (cutoff_iso,),
        ).fetchall()
        run_ids = [int(row[0]) for row in rows]
        if not run_ids:
            return 0

        placeholders = ",".join("?" for _ in run_ids)
        self.connection.execute(
            f"DELETE FROM site_audits WHERE run_id IN ({placeholders})",
            run_ids,
        )
        self.connection.execute(
            f"DELETE FROM runs WHERE id IN ({placeholders})",
            run_ids,
        )
        self.connection.commit()
        return len(run_ids)

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .audit import audit_all
from .config import load_config
from .discovery import discover_sites
from .reporting import build_report, render_text, write_report
from .storage import Storage

DEFAULT_CONFIG = Path("/etc/wp-guardian/guardian.toml")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="wp-guardian")
    root.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="command", required=True)
    sub.add_parser("sites", help="List discovered WordPress sites")
    audit = sub.add_parser("audit", help="Run read-only audit")
    audit.add_argument("--domain", help="Audit only one domain")
    audit.add_argument("--json", action="store_true", help="Print JSON report")
    report = sub.add_parser("report", help="Print the latest report")
    report.add_argument("--json", action="store_true", help="Print latest JSON report")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        config = load_config(args.config)
    except (OSError, ValueError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if args.command == "sites":
        for site in discover_sites(config):
            print(f"{site.domain}\t{site.path}")
        return 0

    if args.command == "report":
        target = config.report_dir / ("latest.json" if args.json else "latest.txt")
        if not target.exists():
            print("No report exists yet", file=sys.stderr)
            return 1
        print(target.read_text(encoding="utf-8"), end="")
        return 0

    if args.command == "audit":
        started_at = datetime.now(timezone.utc).isoformat()
        storage = Storage(config.state_dir / "guardian.sqlite3")
        run_id = storage.start_run(started_at, "audit")
        audits = audit_all(config, args.domain)
        if args.domain and not audits:
            print(f"Domain not found or excluded: {args.domain}", file=sys.stderr)
            return 1
        for audit in audits:
            storage.save_site_audit(run_id, audit)
        report = build_report(audits)
        json_path, text_path = write_report(config.report_dir, report)
        storage.finish_run(run_id, datetime.now(timezone.utc).isoformat(), str(json_path))
        print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else render_text(report))
        print(f"Saved: {text_path}", file=sys.stderr)
        return 2 if report["summary"]["worst_severity"] in {"HIGH", "CRITICAL"} else 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

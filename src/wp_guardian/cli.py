from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .audit import audit_all
from .backup import BackupError, create_database_backup
from .backup_verify import verify_database_backup
from .config import load_config
from .discovery import discover_sites
from .mailer import send_latest_report
from .reporting import build_report, render_text, write_report
from .retention import business_day_cutoff, prune_report_files
from .runner import CommandRunner
from .storage import Storage
from .update_plan import build_update_plan
from .wordpress import WordPress

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
    backup = sub.add_parser("backup", help="Create a private database backup for one domain")
    backup.add_argument("--domain", required=True, help="Exact configured domain to back up")
    verify = sub.add_parser(
        "verify-backup",
        help="Verify the latest or selected private database backup",
    )
    verify.add_argument("--domain", required=True, help="Exact configured domain")
    verify.add_argument(
        "--backup",
        help="Backup directory name; defaults to the newest timestamped backup",
    )
    plan = sub.add_parser(
        "update-plan",
        help="Build a read-only guarded update plan for one domain",
    )
    plan.add_argument("--domain", required=True, help="Exact configured domain")
    plan.add_argument("--json", action="store_true", help="Print the plan as JSON")
    report = sub.add_parser("report", help="Print the latest report")
    report.add_argument("--json", action="store_true", help="Print latest JSON report")
    sub.add_parser("send-report", help="Send the latest text report by local mail transport")
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

    if args.command in {"backup", "verify-backup", "update-plan"}:
        matching = [site for site in discover_sites(config) if site.domain == args.domain]
        if len(matching) != 1:
            print(f"Domain not found or excluded: {args.domain}", file=sys.stderr)
            return 1
        runner = CommandRunner(config.backup_timeout)
        wordpress = WordPress(config, runner)

        if args.command == "backup":
            try:
                result = create_database_backup(config, matching[0], wordpress)
            except (BackupError, OSError) as exc:
                print(f"Backup error: {exc}", file=sys.stderr)
                return 1
            print(f"Database backup completed for {result.domain}")
            print(f"Directory: {result.directory}")
            print(f"Database: {result.database_path}")
            print(f"Manifest: {result.manifest_path}")
            print(f"Size: {result.size}")
            print(f"SHA256: {result.sha256}")
            print(
                "Backup retention: "
                f"keep_last={config.backup_keep_last}, "
                f"removed={result.backups_removed}"
            )
            return 0

        if args.command == "verify-backup":
            try:
                result = verify_database_backup(
                    config,
                    matching[0],
                    wordpress,
                    backup_name=args.backup,
                )
            except (BackupError, OSError) as exc:
                print(f"Backup verification error: {exc}", file=sys.stderr)
                return 1
            print(f"Database backup verified for {result.domain}")
            print(f"Directory: {result.directory}")
            print(f"Created: {result.created_at}")
            print(f"Compressed size: {result.compressed_size}")
            print(f"Decompressed size: {result.decompressed_size}")
            print(f"SHA256: {result.sha256}")
            print(f"Table prefix: {result.table_prefix}")
            print(f"CREATE TABLE statements: {result.create_table_statements}")
            print(f"Matching WordPress tables: {result.matching_tables}")
            print(f"INSERT statements: {result.insert_statements}")
            return 0

        plan_result = build_update_plan(config, matching[0], wordpress, runner)
        if args.json:
            print(json.dumps(plan_result.to_dict(), ensure_ascii=False, indent=2))
        else:
            print("SOFTICO WORDPRESS GUARDIAN UPDATE PLAN")
            print(f"Domain: {plan_result.domain}")
            print(f"Generated: {plan_result.generated_at}")
            print(f"Site path: {plan_result.site_path}")
            print(f"Ready: {'YES' if plan_result.ready else 'NO'}")
            print(
                "HTTPS: "
                f"status={plan_result.http_status}, "
                f"url={plan_result.http_url}, "
                f"time={plan_result.http_time}"
            )
            print(
                "Core: "
                f"version={plan_result.core_version}, "
                f"checksum_ok={plan_result.core_checksum_ok}"
            )
            print(
                "Backup: "
                f"directory={plan_result.backup_directory}, "
                f"created={plan_result.backup_created_at}, "
                f"age_seconds={plan_result.backup_age_seconds}"
            )
            print(f"Updates: {len(plan_result.updates)}")
            for item in plan_result.updates:
                print(
                    f"- {item.kind}: {item.name} "
                    f"{item.current_version} -> {item.target_version or 'unknown'} "
                    f"(status={item.status})"
                )
            if plan_result.blockers:
                print("Blockers:")
                for blocker in plan_result.blockers:
                    print(f"- {blocker}")
            if plan_result.warnings:
                print("Warnings:")
                for warning in plan_result.warnings:
                    print(f"- {warning}")
        return 2 if plan_result.blockers else 0

    if args.command == "report":
        target = config.report_dir / ("latest.json" if args.json else "latest.txt")
        if not target.exists():
            print("No report exists yet", file=sys.stderr)
            return 1
        print(target.read_text(encoding="utf-8"), end="")
        return 0

    if args.command == "send-report":
        try:
            sent = send_latest_report(config)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"Mail delivery error: {exc}", file=sys.stderr)
            return 1
        if sent:
            print("Latest report submitted to the local mail transport")
        else:
            print("Mail delivery is disabled in the configuration")
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

        cutoff = business_day_cutoff(config.retention_business_days)
        removed_reports = prune_report_files(config.report_dir, cutoff)
        removed_runs = storage.prune_runs_before(cutoff.isoformat())

        print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else render_text(report))
        print(f"Saved: {text_path}", file=sys.stderr)
        print(
            "Retention cleanup: "
            f"business_days={config.retention_business_days}, "
            f"reports_removed={removed_reports}, runs_removed={removed_runs}",
            file=sys.stderr,
        )
        return 2 if report["summary"]["worst_severity"] in {"HIGH", "CRITICAL"} else 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

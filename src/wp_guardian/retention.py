from __future__ import annotations

from datetime import datetime, time, timedelta, timezone
from pathlib import Path


def business_day_cutoff(
    business_days: int,
    now: datetime | None = None,
) -> datetime:
    """Return the UTC cutoff for an inclusive business-day retention window.

    A value of 3 keeps the current business day and the two preceding business
    days. On weekends, Friday is treated as the current business day, while any
    reports created during the weekend remain inside the retained window.
    """
    if business_days < 1:
        raise ValueError("retention_business_days must be at least 1")

    local_now = now if now is not None else datetime.now().astimezone()
    if local_now.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    anchor = local_now.date()
    while anchor.weekday() >= 5:
        anchor -= timedelta(days=1)

    remaining = business_days - 1
    cutoff_date = anchor
    while remaining:
        cutoff_date -= timedelta(days=1)
        if cutoff_date.weekday() < 5:
            remaining -= 1

    local_cutoff = datetime.combine(cutoff_date, time.min, tzinfo=local_now.tzinfo)
    return local_cutoff.astimezone(timezone.utc)


def prune_report_files(report_dir: Path, cutoff: datetime) -> int:
    """Delete timestamped audit and maintenance reports older than cutoff.

    The latest.txt and latest.json convenience copies are never matched or
    removed. Only files created by Guardian report writers are eligible.
    """
    if cutoff.tzinfo is None:
        raise ValueError("cutoff must be timezone-aware")
    if not report_dir.exists():
        return 0

    removed = 0
    cutoff_timestamp = cutoff.timestamp()
    for pattern in (
        "audit-*.txt",
        "audit-*.json",
        "maintenance-*.txt",
        "maintenance-*.json",
    ):
        for path in report_dir.glob(pattern):
            try:
                if path.stat().st_mtime < cutoff_timestamp:
                    path.unlink()
                    removed += 1
            except FileNotFoundError:
                continue
    return removed

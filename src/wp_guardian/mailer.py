from __future__ import annotations

import re
import shutil
import socket
import subprocess
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path

from .config import GuardianConfig

EMAIL_RE = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")


def validate_recipient(address: str) -> str:
    value = address.strip()
    if "\r" in value or "\n" in value or not EMAIL_RE.fullmatch(value):
        raise ValueError(f"Invalid mail recipient: {address!r}")
    return value


def build_message(
    config: GuardianConfig,
    report_text: str,
    *,
    hostname: str | None = None,
) -> bytes:
    recipients = [validate_recipient(item) for item in config.mail_recipients]
    if not recipients:
        raise ValueError("Mail is enabled but no recipients are configured")

    host = (hostname or socket.getfqdn() or socket.gethostname() or "localhost").strip()
    safe_host = re.sub(r"[^A-Za-z0-9.-]", "-", host) or "localhost"
    prefix = config.mail_subject_prefix.strip() or "[WP Guardian]"
    first_line = report_text.splitlines()[0] if report_text.splitlines() else ""
    report_kind = (
        "maintenance report"
        if "MAINTENANCE" in first_line.upper()
        else "audit report"
    )

    message = EmailMessage(policy=SMTP)
    message["To"] = ", ".join(recipients)
    message["From"] = f"wp-guardian@{safe_host}"
    message["Subject"] = f"{prefix} {safe_host} {report_kind}"
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(report_text, subtype="plain", charset="utf-8")
    return message.as_bytes()


def resolve_sendmail(command: str) -> str:
    resolved = shutil.which(command) if "/" not in command else command
    if not resolved or not Path(resolved).is_file():
        raise FileNotFoundError(f"sendmail-compatible command not found: {command}")
    return resolved


def send_latest_report(config: GuardianConfig) -> bool:
    if not config.mail_enabled:
        return False

    report_path = config.report_dir / "latest.txt"
    if not report_path.is_file():
        raise FileNotFoundError(f"Latest report not found: {report_path}")

    payload = build_message(
        config,
        report_path.read_text(encoding="utf-8"),
    )
    sendmail = resolve_sendmail(config.sendmail)

    try:
        subprocess.run(
            [sendmail, "-t", "-oi"],
            input=payload,
            check=True,
            timeout=60,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"sendmail failed with exit code {exc.returncode}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("sendmail timed out after 60 seconds") from exc

    return True

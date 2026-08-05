# Softico WordPress Guardian

`softico-wp-guardian` is a deterministic, read-only audit agent for the WordPress fleet hosted under MyVesta. The first release intentionally does not update, delete, quarantine, block, or modify production sites.

## MVP capabilities

- discovers WordPress installations under `/home/admin/web/*/public_html`;
- supports explicit include/exclude domain lists;
- checks HTTPS status and redirect target;
- reports available plugin and theme updates;
- verifies WordPress core checksums;
- verifies official WordPress.org plugin checksums without flooding logs with expected 404 responses for premium/private plugins;
- scans `wp-content/uploads` for executable files with allow-rules for known WPML, WPForms, Yoast and import/export service files;
- detects high-risk PHP constructs in unexpected uploads;
- detects database dumps, site-backup archives and sensitive configuration copies inside public web roots;
- lists administrators and establishes an SQLite baseline for detecting newly appearing administrators;
- detects world-writable files;
- stores audit history in SQLite;
- writes human-readable and JSON reports;
- removes expired report files and audit-run history after a configurable number of business days;
- sends the latest text report through the server's local sendmail-compatible mail transport;
- includes hardened systemd services that run the audit and mail submission as the existing `admin` account.

## Safety model

Version `0.1.0` is audit-only. It has no code paths for automatic updates, file deletion, quarantine, user deletion, configuration changes, IP blocking, or rollback.

The agent never runs WP-CLI as root and does not use `--allow-root`. The audit and report-mail commands run as `admin:admin`, which already owns and manages the hosted WordPress files. Root privileges are needed only for installing files under `/opt`, `/etc`, `/usr/local/bin`, and `/etc/systemd/system`.

Persistent state and reports are stored in `/var/lib/wp-guardian`, owned by `admin:admin`. The program code and configuration remain root-owned and read-only to the runtime account.

## Requirements

- Linux with Python 3.11+
- WP-CLI
- curl
- a local sendmail-compatible mail transport such as Exim
- existing `admin` user with access to `/home/admin/web/*/public_html`
- sudo/root access only for installation and systemd administration

## Development test

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```

## Installation

```bash
git clone https://github.com/powern/agent_web_softico.git
cd agent_web_softico
git checkout agent/mvp-read-only-audit
sudo bash scripts/install.sh
```

Using `bash scripts/install.sh` avoids depending on the executable bit of the checked-out script.

The installer:

- preserves an existing `/etc/wp-guardian/guardian.toml`;
- adds the `[mail]` section once when upgrading an older installation;
- adds `retention_business_days = 3` once when upgrading an older installation;
- installs the audit service, mail service and timer;
- reloads systemd;
- does not enable or start the timer automatically.

Review `/etc/wp-guardian/guardian.toml` before the first scheduled run.

## First server test

Run the initial checks explicitly as `admin`:

```bash
sudo -u admin wp-guardian --config /etc/wp-guardian/guardian.toml sites
sudo -u admin wp-guardian --config /etc/wp-guardian/guardian.toml audit --domain softico.ua
sudo -u admin wp-guardian --config /etc/wp-guardian/guardian.toml report
```

To inspect the exact systemd identity before starting anything:

```bash
systemctl cat wp-guardian.service
systemctl cat wp-guardian-mail.service
grep -E '^(User|Group)=' /etc/systemd/system/wp-guardian*.service
```

Expected values:

```text
User=admin
Group=admin
```

The audit command returns exit code `2` when a HIGH or CRITICAL finding exists. The systemd unit declares `SuccessExitStatus=2`, so a completed security audit still triggers email delivery. Genuine execution or configuration failures do not trigger delivery of an older report.

## Public backup and dump detection

The `check_public_backups` audit identifies potentially exposed sensitive artifacts beneath each site's `public_html`:

- database dumps such as `.sql`, `.sql.gz`, `.sqlite3` and `.dump` are `CRITICAL`;
- copies of `wp-config.php` and `.env` are `CRITICAL`;
- JPA, WPRESS and TAR-family site archives are `HIGH`;
- ZIP, GZ, 7Z and RAR files are `HIGH` only when their path or filename clearly indicates backup, dump, migration, snapshot or archive storage.

Ordinary downloadable ZIP files are not flagged solely by extension. The scan records metadata only and does not open or hash large backup archives.

Known intentional fixtures can be excluded narrowly:

```toml
[policy]
allow_public_backup_paths = [
  "path/to/exact-fixture.sql",
  "path/to/test-backups/",
]
```

Exact paths and directory prefixes are relative to the site's `public_html` directory.

## Email reports

Email delivery is configured in `/etc/wp-guardian/guardian.toml`:

```toml
[mail]
enabled = true
recipients = ["skr@softico.ua"]
subject_prefix = "[WP Guardian]"
sendmail = "/usr/sbin/sendmail"
```

The audit unit contains:

```ini
OnSuccess=wp-guardian-mail.service
```

After an audit completes with exit code `0` or `2`, systemd runs:

```bash
wp-guardian --config /etc/wp-guardian/guardian.toml send-report
```

The command reads `/var/lib/wp-guardian/reports/latest.txt` and submits it to the configured local mail transport. No interactive password or sudo prompt is involved in scheduled runs.

## Reports, state and retention

```text
/var/lib/wp-guardian/guardian.sqlite3
/var/lib/wp-guardian/reports/latest.txt
/var/lib/wp-guardian/reports/latest.json
/var/lib/wp-guardian/reports/audit-YYYYMMDD-HHMMSS.txt
/var/lib/wp-guardian/reports/audit-YYYYMMDD-HHMMSS.json
```

Retention is configured in the `[general]` section:

```toml
retention_business_days = 3
```

After each completed audit, the agent deletes timestamped `audit-*.txt` and `audit-*.json` files older than the current and two preceding business days. Matching historical `runs` and `site_audits` rows are deleted from SQLite. `latest.txt`, `latest.json`, unrelated files and the administrator baseline are retained.

This setting does not change the global systemd journal policy and does not delete logs belonging to other services.

## Enabling the schedule

After manual audit and email verification:

```bash
systemctl enable --now wp-guardian.timer
systemctl list-timers wp-guardian.timer --all
```

## Roadmap

1. validate read-only results against the existing manual audit;
2. add database backup and single-domain guarded updates under `admin`;
3. add reversible quarantine with manifests under `admin` ownership;
4. add structured log ingestion;
5. only after production validation, consider scheduled safe updates.

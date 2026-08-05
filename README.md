# Softico WordPress Guardian

`softico-wp-guardian` is a deterministic security and maintenance agent for the WordPress fleet hosted under MyVesta. Auditing and update planning remain read-only. Site writes are restricted to explicit private backups, explicit recovery-checkpoint preparation, and one guarded update of a previously prepared inactive plugin.

Bulk updates, scheduled automatic updates, active-plugin updates, theme apply, WordPress core updates, database import, user deletion, quarantine and IP blocking are not implemented.

## Current capabilities

- discovers WordPress installations under `/home/admin/web/*/public_html`;
- supports explicit include/exclude domain lists;
- checks HTTPS status and redirect target;
- reports available plugin and theme updates;
- verifies WordPress core checksums;
- verifies official WordPress.org plugin checksums without flooding logs with expected 404 responses for premium/private plugins;
- scans `wp-content/uploads` for executable files with narrow allow-rules for known service files;
- detects high-risk PHP constructs in unexpected uploads;
- detects database dumps, site-backup archives and sensitive configuration copies inside public web roots;
- lists administrators and establishes an SQLite baseline for detecting newly appearing administrators;
- detects world-writable files;
- stores audit history in SQLite;
- writes human-readable and JSON reports;
- removes expired report files and audit-run history after a configurable number of business days;
- sends the latest text report through the server's local sendmail-compatible mail transport;
- creates an explicit private compressed database backup for exactly one configured domain;
- retains only the newest configured number of completed backups per domain;
- verifies backup manifest, permissions, size, SHA-256, gzip completeness and WordPress SQL structure;
- creates read-only guarded plugin/theme update plans;
- prepares a fresh database backup and private component snapshot for one exact update;
- applies one exact prepared update only when the component is an inactive plugin;
- automatically restores the prepared plugin snapshot when the update or postflight fails;
- includes separate hardened systemd services for the unprivileged audit and privileged local-mail submission.

## Safety model

The `audit`, `sites`, `report`, `verify-backup` and `update-plan` commands are read-only.

`backup --domain ...` writes only to the private backup tree. It requires an exact configured domain, exports only that site's database, rejects destinations below the hosted web tree, uses atomic staging and removes incomplete output after a failure.

`prepare-update` does not update WordPress. It confirms one exact advertised target, creates and verifies a fresh database backup, snapshots the exact plugin or theme path, records SHA-256 values and writes `update-preparation.json`. A failed preparation removes the new incomplete checkpoint without pruning prior backups.

`apply-update` is intentionally narrower than preparation. It currently permits only `kind=plugin` when both the preparation and live WordPress state say the plugin is `inactive`. The command requires the exact domain, preparation ID, slug and target version; rejects stale, changed, reused or non-private checkpoints; repeats HTTPS/core/backup/update-target checks; then runs one exact WP-CLI plugin update. It verifies the resulting version, status, HTTPS, core checksum and official plugin checksum when available.

After WP-CLI has been invoked, any failed update or postflight triggers automatic restoration of the component snapshot. This is file rollback only. The verified database backup is retained as recovery material but is not imported automatically.

Backup retention deletes only completed Guardian backup directories containing matching managed files. Temporary, incomplete, unrelated and symlink entries are ignored. The newly created checkpoint is protected during retention cleanup.

The agent never runs WP-CLI as root and does not use `--allow-root`. Discovery, audits, backups and guarded update commands run as `admin:admin`, which already owns and manages the hosted WordPress files.

Debian Exim requires privileged access to its local spool when submitting through `/usr/sbin/sendmail`. The dedicated `wp-guardian-mail.service` therefore runs only the `send-report` operation as root. Its systemd sandbox hides `/home`, makes the system read-only, and permits writes only to the Exim spool, log and runtime paths. It does not run WP-CLI or inspect hosted sites.

Persistent state and reports are stored in `/var/lib/wp-guardian`, owned by `admin:admin`. Private database backups and update checkpoints are stored under `/home/admin/private-backups/wp-guardian`, also owned by `admin:admin` with mode `0700`. Managed checkpoint files use mode `0600`. Program code and configuration remain root-owned and read-only to the runtime account.

## Requirements

- Linux with Python 3.11+
- WP-CLI with working database export and plugin update commands
- curl
- a local sendmail-compatible mail transport such as Exim
- existing `admin` user with access to `/home/admin/web/*/public_html`
- sudo/root access for installation, systemd administration and isolated local-mail submission

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
- adds the `[mail]` and `[backup]` sections once when upgrading an older installation;
- adds `retention_business_days = 3` once when upgrading an older installation;
- adds `keep_last = 3` to an existing `[backup]` section once;
- creates `/home/admin/private-backups/wp-guardian` as `admin:admin` with mode `0700`;
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

To inspect the exact systemd identities before starting anything:

```bash
systemctl cat wp-guardian.service
systemctl cat wp-guardian-mail.service
grep -E '^(User|Group)=' /etc/systemd/system/wp-guardian*.service
```

Expected identities:

```text
wp-guardian.service:      User=admin, Group=admin
wp-guardian-mail.service: User=root,  Group=root
```

The audit command returns exit code `2` when a HIGH or CRITICAL finding exists. The systemd unit declares `SuccessExitStatus=2`, so a completed security audit still triggers email delivery. Genuine execution or configuration failures do not trigger delivery of an older report.

## Private database backup and verification

Backup settings are separate from report retention:

```toml
[backup]
directory = "/home/admin/private-backups/wp-guardian"
timeout = 900
keep_last = 3
```

Create and verify a backup for one exact domain:

```bash
sudo -u admin wp-guardian \
  --config /etc/wp-guardian/guardian.toml \
  backup --domain teamviewer.softico.ua

sudo -u admin wp-guardian \
  --config /etc/wp-guardian/guardian.toml \
  verify-backup --domain teamviewer.softico.ua
```

A successful backup creates:

```text
/home/admin/private-backups/wp-guardian/<domain>/<UTC-timestamp>/
├── database.sql.gz
└── manifest.json
```

Directories use mode `0700`; files use mode `0600`. `manifest.json` records the domain, original site path, creation time, WordPress version, compressed size and SHA-256 checksum. The command uses `wp db export --single-transaction`, rejects empty dumps, and atomically promotes the staging directory only after compression and manifest creation succeed.

Verification streams the complete gzip without extracting SQL to disk. It checks the manifest, permissions, compressed size, SHA-256, decompressed size, actual WordPress table prefix, `CREATE TABLE` statements and matching tables.

After a successful backup or preparation, the agent keeps the newest `keep_last` completed copies for that domain and removes older completed Guardian copies. Retention is per domain and runs only after a new checkpoint has completed successfully.

## Guarded update workflow

The guarded workflow is always single-domain and single-component:

1. `update-plan --domain ...` performs read-only HTTPS, core checksum, backup and exact-version preflight checks.
2. `prepare-update` creates a new verified database backup, a private component `tar.gz`, SHA-256 metadata and a deterministic preparation ID. No WordPress update is executed.
3. `apply-update` repeats all safety checks and applies only one inactive plugin update whose exact values match the preparation.

Example:

```bash
sudo -u admin wp-guardian \
  --config /etc/wp-guardian/guardian.toml \
  update-plan --domain softico.ua

sudo -u admin wp-guardian \
  --config /etc/wp-guardian/guardian.toml \
  prepare-update \
  --domain softico.ua \
  --kind plugin \
  --name contact-form-7-simple-recaptcha \
  --target-version 0.1.8

sudo -u admin wp-guardian \
  --config /etc/wp-guardian/guardian.toml \
  apply-update \
  --domain softico.ua \
  --preparation-id <exact-id-from-prepare-update> \
  --kind plugin \
  --name contact-form-7-simple-recaptcha \
  --target-version 0.1.8
```

The preparation must be no more than one hour old and must remain the newest verified backup. A successful apply writes `update-applied.json`. A failed apply with successful automatic file restoration writes `update-rollback.json` and exits with code `2`.

Detailed contracts:

- `docs/update-plan.md`
- `docs/update-preparation.md`
- `docs/update-apply.md`
- `docs/backup-verification.md`

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

After an audit completes with exit code `0` or `2`, systemd starts the isolated mail unit, which runs:

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

Report retention is configured in the `[general]` section:

```toml
retention_business_days = 3
```

After each completed audit, the agent deletes timestamped `audit-*.txt` and `audit-*.json` files older than the current and two preceding business days. Matching historical `runs` and `site_audits` rows are deleted from SQLite. `latest.txt`, `latest.json`, private checkpoints and the administrator baseline are unaffected by this report policy. Database backups use their own per-domain `keep_last` policy.

This setting does not change the global systemd journal policy and does not delete logs belonging to other services.

## Enabling the schedule

After manual audit and email verification:

```bash
systemctl enable --now wp-guardian.timer
systemctl list-timers wp-guardian.timer --all
```

The scheduled unit runs audits and report delivery only. It does not run `prepare-update` or `apply-update`.

## Roadmap

1. validate the guarded inactive-plugin apply and automatic file rollback on production data;
2. test database restoration on an isolated clone;
3. add guarded active-plugin and theme workflows only after rollback validation;
4. add reversible quarantine with manifests under `admin` ownership;
5. add structured log ingestion;
6. only after production validation, consider narrowly scheduled safe updates.

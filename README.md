# Softico WordPress Guardian

`softico-wp-guardian` is a deterministic security and guarded-maintenance agent for the WordPress fleet hosted under MyVesta.

The enabled nightly timer now performs two phases:

1. guarded automatic updates for eligible inactive plugins;
2. a full security audit of every included site, followed by one email report.

Active plugins, must-use/drop-in plugins, themes, WordPress core and premium components are never updated automatically by the current policy.

## Current capabilities

- discovers WordPress installations under `/home/admin/web/*/public_html`;
- supports explicit include/exclude domain lists;
- checks HTTPS status and redirect target;
- reports available plugin and theme updates;
- verifies WordPress core and official WordPress.org plugin checksums;
- scans uploads for unexpected executable PHP;
- detects public database dumps, backup archives and sensitive configuration copies;
- detects world-writable files;
- lists administrators and maintains an SQLite administrator baseline;
- creates private compressed database backups with manifests and SHA-256;
- verifies gzip completeness and WordPress SQL structure before an update;
- snapshots exact plugin/theme files into private recovery checkpoints;
- applies one exact prepared inactive-plugin update with automatic file rollback;
- orchestrates eligible inactive-plugin updates across the fleet at night;
- performs a complete fleet audit after all update attempts;
- writes JSON and text maintenance reports and emails the latest report;
- retains report/run history for three business days by default;
- retains the newest three completed backup checkpoints per domain by default.

## Nightly automatic policy

`wp-guardian.timer` starts `wp-guardian.service`, which runs:

```bash
/opt/wp-guardian/venv/bin/wp-guardian-maintenance \
  --config /etc/wp-guardian/guardian.toml
```

An automatic candidate must satisfy all conditions:

- WP-CLI advertises an update;
- an exact non-empty `update_version` is available;
- the component is a plugin;
- the live status is exactly `inactive`.

Everything else is included in the report as `SKIPPED`.

The run attempts no more than 25 eligible plugin updates across the fleet. After the first failed or rolled-back update on a site, further changes on that site stop for the current run. Other sites are still inspected, and the final audit still executes.

Full details: [`docs/nightly-maintenance.md`](docs/nightly-maintenance.md).

## Per-plugin guarded sequence

For each eligible inactive plugin, Guardian:

1. confirms the exact current and target versions;
2. creates a fresh private database backup;
3. verifies its manifest, permissions, size, SHA-256, gzip stream and SQL table prefix;
4. snapshots the exact plugin files;
5. reruns HTTPS, core checksum, backup and update-target preflight checks;
6. applies only the exact prepared version;
7. confirms the plugin remains inactive and reports the exact target version;
8. reruns HTTPS and core checksum checks;
9. verifies official plugin checksums when WordPress.org provides a manifest;
10. writes `update-applied.json`.

Any failure after WP-CLI begins changing files triggers restoration of the component snapshot and writes `update-rollback.json`.

Automatic rollback currently restores plugin files only. The verified database backup remains available for manual recovery; automatic database import is intentionally disabled.

## Safety model

Read-only commands:

```text
sites
report
verify-backup
update-plan
audit
```

Explicit write commands:

```text
backup
prepare-update
apply-update
wp-guardian-maintenance
```

`prepare-update` writes only recovery material and never updates WordPress. `apply-update` permits only one exact prepared inactive plugin. `wp-guardian-maintenance` is an orchestrator around those same validated functions; it does not contain a broader bypass path.

WP-CLI never runs as root and Guardian never uses `--allow-root`. Audits, backups and maintenance run as `admin:admin`.

The maintenance systemd service has a read-only system view and write access limited to:

```text
/var/lib/wp-guardian
/home/admin/web
/home/admin/private-backups/wp-guardian
/home/admin/.wp-cli
```

The separate root mail service cannot access hosted sites and is privileged only for local Exim spool submission.

## Installation or upgrade

```bash
cd /home/admin/agent_web_softico
git pull --ff-only origin agent/mvp-read-only-audit
sudo bash scripts/install.sh
```

The installer:

- installs the package into `/opt/wp-guardian/venv`;
- validates both `wp-guardian` and `wp-guardian-maintenance` launchers;
- creates stable launchers in `/usr/local/bin`;
- preserves `/etc/wp-guardian/guardian.toml`;
- installs and reloads the service, mail service and timer units;
- preserves the existing enabled/disabled state of the timer.

## Manual maintenance test

Run the same command used by the timer:

```bash
sudo -u admin wp-guardian-maintenance \
  --config /etc/wp-guardian/guardian.toml

echo "EXIT_CODE=$?"
```

Exit codes:

- `0`: maintenance completed and the final audit has no HIGH/CRITICAL findings;
- `2`: an update failed/rolled back or the final audit has HIGH/CRITICAL findings; a fresh report still exists and systemd sends it;
- `1`: configuration, lock or report-generation failure prevented a completed run.

A non-blocking lock at `/var/lib/wp-guardian/maintenance.lock` prevents concurrent runs.

## Reports and email

Nightly reports are written to:

```text
/var/lib/wp-guardian/reports/maintenance-YYYYMMDD-HHMMSS.txt
/var/lib/wp-guardian/reports/maintenance-YYYYMMDD-HHMMSS.json
/var/lib/wp-guardian/reports/latest.txt
/var/lib/wp-guardian/reports/latest.json
```

Every component is marked as one of:

```text
UPDATED
SKIPPED
FAILED
ROLLED_BACK
```

The full final security audit is appended to the same report. After a completed systemd run, `wp-guardian-mail.service` sends `latest.txt` with a subject identifying it as a maintenance report.

## Manual guarded workflow

Read-only plan:

```bash
sudo -u admin wp-guardian \
  --config /etc/wp-guardian/guardian.toml \
  update-plan --domain softico.ua
```

Create a recovery checkpoint without updating:

```bash
sudo -u admin wp-guardian \
  --config /etc/wp-guardian/guardian.toml \
  prepare-update \
  --domain softico.ua \
  --kind plugin \
  --name example-plugin \
  --target-version 1.2.3
```

Apply one exact prepared inactive plugin:

```bash
sudo -u admin wp-guardian \
  --config /etc/wp-guardian/guardian.toml \
  apply-update \
  --domain softico.ua \
  --preparation-id <64-character-id> \
  --kind plugin \
  --name example-plugin \
  --target-version 1.2.3
```

Additional design documents:

- [`docs/update-plan.md`](docs/update-plan.md)
- [`docs/update-preparation.md`](docs/update-preparation.md)
- [`docs/update-apply.md`](docs/update-apply.md)
- [`docs/nightly-maintenance.md`](docs/nightly-maintenance.md)

## Development validation

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```

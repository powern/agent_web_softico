# Guarded nightly maintenance

The enabled `wp-guardian.timer` starts `wp-guardian.service`. The service now runs:

```bash
/opt/wp-guardian/venv/bin/wp-guardian-maintenance \
  --config /etc/wp-guardian/guardian.toml
```

The process runs as `admin:admin`. Root is not used for WP-CLI, backups, audits or WordPress file changes.

## Automatic update scope

The initial automatic policy is intentionally narrow:

- an update must be advertised by WP-CLI with an exact `update_version`;
- the component must be a plugin;
- the plugin status must be exactly `inactive`;
- no more than 25 plugins are attempted in one fleet run;
- active plugins, must-use/drop-in plugins and all themes are reported as `SKIPPED`;
- after the first failed or rolled-back update on one site, further changes on that site stop for the current run;
- other sites are still inspected and the final fleet audit still runs.

Premium themes such as Avada are never updated automatically by this workflow.

## Per-plugin safety sequence

For each eligible inactive plugin, the orchestrator calls the already validated guarded workflow:

1. confirm the exact current and target versions;
2. create a fresh private compressed database backup;
3. verify gzip integrity, SHA-256, SQL structure and the live table prefix;
4. snapshot the exact plugin files to a private `tar.gz` archive;
5. rerun HTTPS, WordPress core checksum and update-target preflight checks;
6. apply only the exact prepared target version;
7. confirm the plugin remains inactive and now reports the exact target version;
8. rerun HTTPS and WordPress core checksum checks;
9. verify the updated plugin against WordPress.org checksums when a checksum manifest exists;
10. write `update-applied.json` on success.

If any post-write step fails, the plugin snapshot is restored automatically and `update-rollback.json` is written. The verified database backup remains available for manual recovery; automatic database import is not enabled.

## Fleet completion and email

After update processing, Guardian performs a full audit of every included site. The maintenance summary and complete final audit are written to:

```text
/var/lib/wp-guardian/reports/maintenance-YYYYMMDD-HHMMSS.txt
/var/lib/wp-guardian/reports/maintenance-YYYYMMDD-HHMMSS.json
/var/lib/wp-guardian/reports/latest.txt
/var/lib/wp-guardian/reports/latest.json
```

The report records every component as one of:

- `UPDATED`
- `SKIPPED`
- `FAILED`
- `ROLLED_BACK`

`wp-guardian.service` treats exit code `2` as a completed run with problems, so `OnSuccess=wp-guardian-mail.service` still sends the fresh report. An unexpected configuration failure that prevents creation of a fresh report returns exit code `1`, and the mail unit is not started.

The email subject identifies the message as a maintenance report.

## Concurrency

The process obtains a non-blocking exclusive lock at:

```text
/var/lib/wp-guardian/maintenance.lock
```

A second manual or scheduled maintenance process cannot run in parallel.

## Manual execution

Run the same workflow used by the timer:

```bash
sudo -u admin wp-guardian-maintenance \
  --config /etc/wp-guardian/guardian.toml

echo "EXIT_CODE=$?"
```

Exit codes:

- `0`: maintenance and final audit completed without HIGH/CRITICAL findings or update failures;
- `2`: a component failed/rolled back, or the final audit contains HIGH/CRITICAL findings; a fresh report is still generated and mailed by systemd;
- `1`: configuration, locking or report-generation failure prevented a normal completed run.

## systemd write boundaries

The maintenance service has a read-only system view and write access only to:

```text
/var/lib/wp-guardian
/home/admin/web
/home/admin/private-backups/wp-guardian
/home/admin/.wp-cli
```

The dedicated mail service remains isolated from `/home` and runs as root only because local Exim submission requires access to the Exim spool.

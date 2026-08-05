# Guarded single-domain update planning

`update-plan` is a read-only preflight command. It does not call `wp plugin update`, `wp theme update`, modify WordPress files, change the database, enable maintenance mode, or create a new backup.

Run it for exactly one configured domain:

```bash
sudo -u admin wp-guardian \
  --config /etc/wp-guardian/guardian.toml \
  update-plan --domain teamviewer.softico.ua
```

Machine-readable output is available with `--json`.

## Ready conditions

The plan reports `Ready: YES` only when all of the following are true:

1. the domain is explicitly configured and not excluded;
2. the HTTPS preflight returns a status from 200 through 399;
3. the current WordPress core version can be read;
4. WordPress core checksum verification succeeds;
5. the newest private database backup passes full Guardian verification;
6. at least one plugin or theme update is available;
7. WP-CLI provides an exact `update_version` for every planned item.

The plan includes the verified backup directory and age, current and target versions, component status, redirect target, response time, blockers and warnings.

## Exit codes

- `0`: preflight has no blockers. This also covers the harmless case where no updates are currently available.
- `1`: the requested domain does not exist or is excluded.
- `2`: one or more safety blockers exist.

A zero exit code does not perform or authorize an update. It only means the read-only preflight completed without blockers.

## Current scope

Only plugin and theme updates are planned. WordPress core updates, automatic execution, rollback and restore remain outside this command and are not implemented here.

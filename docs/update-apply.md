# Guarded inactive-plugin update apply

`apply-update` is the first deliberately narrow WordPress write operation in Softico WordPress Guardian. It applies exactly one previously prepared update and currently permits only a plugin whose recorded and current status is `inactive`.

It does not support active plugins, must-use plugins, drop-ins, themes, WordPress core updates, bulk updates or scheduled automatic updates.

## Required preparation

Run `update-plan`, then `prepare-update`, and copy the exact values printed by the preparation command:

```bash
sudo -u admin wp-guardian \
  --config /etc/wp-guardian/guardian.toml \
  apply-update \
  --domain softico.ua \
  --preparation-id a4385ba605bdd1977bd28dd5409f73b57dfabffb8184229cb673fb6f4dbd4625 \
  --kind plugin \
  --name contact-form-7-simple-recaptcha \
  --target-version 0.1.8
```

Every supplied value must match `update-preparation.json`. The preparation must be no more than one hour old and must still be the newest verified backup for the domain.

## Checks before changing files

Before WP-CLI is allowed to update the plugin, Guardian verifies:

1. the exact domain is configured and not excluded;
2. the preparation ID is a valid canonical SHA-256 digest of the manifest;
3. the manifest, database archive and component snapshot are private regular files;
4. the database backup passes full Guardian verification;
5. the component snapshot size, SHA-256 and tar structure are valid;
6. the snapshot has no absolute paths, traversal, symlinks, hard links or special entries;
7. the plugin still exists at the exact prepared path;
8. the plugin is still inactive and still has the prepared current version;
9. WP-CLI still advertises the exact prepared target version;
10. HTTPS, WordPress core checksum and the prepared backup pass the update preflight.

Any failed check stops before the update command is called.

## Apply and postflight

Guardian runs one exact command equivalent to:

```text
wp plugin update <slug> --version=<exact-target> --format=json
```

Afterwards it requires:

- the plugin status to remain `inactive`;
- the installed version to equal the exact target;
- HTTPS to remain healthy;
- WordPress core checksum verification to remain clean;
- the prepared backup to remain the selected checkpoint;
- official WordPress.org plugin checksum verification to pass when a checksum manifest exists.

A successful operation writes private mode-`0600` metadata to:

```text
<checkpoint>/update-applied.json
```

The same preparation cannot be applied twice.

## Automatic file rollback

After WP-CLI has been invoked, any update or postflight failure triggers automatic file rollback from the prepared component snapshot. Rollback also handles a partially updated or completely missing plugin directory.

The restored plugin must again be inactive at the original version, and Guardian reruns WordPress core checksum and HTTPS/update preflight checks. A successful rollback writes:

```text
<checkpoint>/update-rollback.json
```

The command then exits with code `2` and reports that the snapshot was restored.

The database backup is retained as recovery material but is not imported automatically. This is intentional for the initial inactive-plugin scope: importing a production database is a substantially higher-risk action and remains manual until restore testing is completed on an isolated clone.

## Exit codes

- `0`: the exact plugin update and all postflight checks succeeded;
- `1`: the requested domain does not exist or is excluded;
- `2`: validation failed, the update failed, postflight failed, or rollback required attention.

## Current scope boundary

Do not use this command for Avada or any other theme. Theme apply, active-plugin apply, database rollback and production-grade restore orchestration remain blocked until this inactive-plugin path is validated on the server.

# Guarded update preparation

`prepare-update` creates a private recovery checkpoint for exactly one advertised plugin or theme update. It does **not** execute `wp plugin update`, `wp theme update`, change WordPress files, activate maintenance mode, or import a database.

Run it only with values copied from `update-plan`:

```bash
sudo -u admin wp-guardian \
  --config /etc/wp-guardian/guardian.toml \
  prepare-update \
  --domain example.com \
  --kind plugin \
  --name example-plugin \
  --target-version 1.1.0
```

## Safety sequence

The command:

1. requires an exact configured domain, component kind, slug and target version;
2. confirms that WP-CLI currently advertises exactly that update;
3. resolves the existing component beneath `wp-content/plugins` or `wp-content/themes`;
4. rejects component paths or entries implemented as symlinks and rejects special filesystem entries;
5. creates a new private database backup without pruning older copies yet;
6. fully verifies the new database backup;
7. reruns HTTPS, WordPress core checksum, backup and update-target preflight checks;
8. confirms that the current and target versions did not change during preparation;
9. creates a private `tar.gz` snapshot of the component files;
10. writes `update-preparation.json` with SHA-256 checksums and a deterministic preparation ID;
11. only after the complete checkpoint exists, applies the normal per-domain `keep_last` retention policy.

If preparation fails before the manifest is finalized, the newly created checkpoint is removed. Existing completed backups are not pruned.

## Checkpoint layout

```text
/home/admin/private-backups/wp-guardian/<domain>/<UTC-timestamp>/
├── database.sql.gz
├── manifest.json
├── component-<kind>-<slug>.tar.gz
└── update-preparation.json
```

The directory remains mode `0700`; all files are mode `0600`.

`update-preparation.json` records:

- domain and site path;
- component kind, slug, status, current version and exact target version;
- original component path;
- component archive size and SHA-256;
- database archive size, SHA-256, table prefix and matching table count;
- HTTPS result and WordPress core checksum status;
- deterministic `preparation_id` for a later explicit apply step.

## Current scope

This command only prepares rollback material. Applying an update, restoring files, importing the database, maintenance mode and automatic rollback remain unimplemented until the preparation format is validated on production data.

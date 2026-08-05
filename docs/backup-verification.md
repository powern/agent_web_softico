# Private database backup verification

`verify-backup` validates a completed Softico WordPress Guardian database backup without importing it and without writing to the WordPress site or database.

## Verify the newest backup

```bash
sudo -u admin wp-guardian \
  --config /etc/wp-guardian/guardian.toml \
  verify-backup --domain teamviewer.softico.ua
```

The command selects the newest Guardian timestamp directory for the exact configured domain.

## Verify a specific retained backup

```bash
sudo -u admin wp-guardian \
  --config /etc/wp-guardian/guardian.toml \
  verify-backup \
  --domain teamviewer.softico.ua \
  --backup 20260805T083514Z
```

`--backup` accepts only a Guardian timestamp directory name. Paths, `..`, hidden directories and arbitrary names are rejected.

## Checks performed

The verification is read-only and checks:

- the backup remains outside the hosted sites tree;
- the domain backup path and selected backup are not symbolic links;
- directory and file permissions are private;
- `manifest.json` is valid JSON with supported schema version `1`;
- the manifest domain and original site path match the selected configured site;
- `database.sql.gz` has the filename and gzip compression declared by the manifest;
- compressed file size matches the manifest;
- SHA-256 matches the manifest;
- the complete gzip stream can be decompressed, including its end-of-stream integrity check;
- the SQL is non-empty and contains `CREATE TABLE` statements;
- at least one table uses the live WordPress table prefix read through WP-CLI;
- counts of `CREATE TABLE`, matching WordPress tables and `INSERT INTO` statements are reported.

The gzip stream is read incrementally. The SQL is not extracted to disk and is not loaded fully into memory.

## Scope and limitation

Passing `verify-backup` proves file integrity, manifest consistency, gzip readability and expected WordPress SQL structure. It is a prerequisite for guarded maintenance operations, but it is not a full database restore test. A full restore test must import the dump into a disposable database that is isolated from production.

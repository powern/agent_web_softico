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
- lists administrators and establishes an SQLite baseline for detecting newly appearing administrators;
- detects world-writable files;
- stores audit history in SQLite;
- writes human-readable and JSON reports;
- includes hardened systemd service and timer examples.

## Safety model

Version `0.1.0` is audit-only. It has no code paths for automatic updates, file deletion, quarantine, user deletion, configuration changes, IP blocking, or rollback.

## Requirements

- Linux with Python 3.11+
- WP-CLI
- curl
- root access is currently expected because the existing server workflow uses `wp --allow-root`

## Development test

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```

## Installation

```bash
git clone https://github.com/powern/agent_web_softico.git
cd agent_web_softico
sudo ./scripts/install.sh
```

Review `/etc/wp-guardian/guardian.toml` before the first run.

## First server test

```bash
wp-guardian --config /etc/wp-guardian/guardian.toml sites
wp-guardian --config /etc/wp-guardian/guardian.toml audit --domain softico.ua
wp-guardian --config /etc/wp-guardian/guardian.toml report
```

The audit command returns exit code `2` when a HIGH or CRITICAL finding exists. This is useful for systemd and monitoring integrations.

## Reports and state

```text
/var/lib/wp-guardian/guardian.sqlite3
/var/lib/wp-guardian/reports/latest.txt
/var/lib/wp-guardian/reports/latest.json
```

## Roadmap

1. validate read-only results against the existing manual audit;
2. add database backup and single-domain guarded updates;
3. add reversible quarantine with manifests;
4. add notifications and structured log ingestion;
5. only after production validation, consider scheduled safe updates.

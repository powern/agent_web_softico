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
- includes a hardened systemd service that runs as the existing `admin` account.

## Safety model

Version `0.1.0` is audit-only. It has no code paths for automatic updates, file deletion, quarantine, user deletion, configuration changes, IP blocking, or rollback.

The agent never runs WP-CLI as root and does not use `--allow-root`. The systemd service runs as `admin:admin`, which already owns and manages the hosted WordPress files. Root privileges are needed only once for installing files under `/opt`, `/etc`, `/usr/local/bin`, and `/etc/systemd/system`.

Persistent state and reports are stored in `/var/lib/wp-guardian`, owned by `admin:admin`. The program code and configuration remain root-owned and read-only to the runtime account.

## Requirements

- Linux with Python 3.11+
- WP-CLI
- curl
- existing `admin` user with access to `/home/admin/web/*/public_html`
- sudo/root access only for installation

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

The installer does not enable or start the timer. Review `/etc/wp-guardian/guardian.toml` before the first run.

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
grep -E '^(User|Group)=' /etc/systemd/system/wp-guardian.service
```

Expected values:

```text
User=admin
Group=admin
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
2. add database backup and single-domain guarded updates under `admin`;
3. add reversible quarantine with manifests under `admin` ownership;
4. add notifications and structured log ingestion;
5. only after production validation, consider scheduled safe updates.

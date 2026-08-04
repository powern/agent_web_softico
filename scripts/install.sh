#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

python3 -m venv /opt/wp-guardian/venv
/opt/wp-guardian/venv/bin/pip install --no-build-isolation .
ln -sfn /opt/wp-guardian/venv/bin/wp-guardian /usr/local/bin/wp-guardian

install -d -m 0750 /etc/wp-guardian /var/lib/wp-guardian/reports
if [[ ! -f /etc/wp-guardian/guardian.toml ]]; then
  install -m 0640 config/guardian.toml.example /etc/wp-guardian/guardian.toml
fi
install -m 0644 systemd/wp-guardian.service /etc/systemd/system/wp-guardian.service
install -m 0644 systemd/wp-guardian.timer /etc/systemd/system/wp-guardian.timer
systemctl daemon-reload

echo "Installed in read-only mode."
echo "Run: wp-guardian --config /etc/wp-guardian/guardian.toml sites"
echo "Then: wp-guardian --config /etc/wp-guardian/guardian.toml audit --domain softico.ua"

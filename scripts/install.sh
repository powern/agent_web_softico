#!/usr/bin/env bash
set -euo pipefail

RUNTIME_USER="admin"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run the installer with sudo/root privileges" >&2
  exit 1
fi

if ! id "$RUNTIME_USER" >/dev/null 2>&1; then
  echo "Required runtime user does not exist: $RUNTIME_USER" >&2
  exit 1
fi

RUNTIME_GROUP="$(id -gn "$RUNTIME_USER")"
RUNTIME_HOME="$(getent passwd "$RUNTIME_USER" | cut -d: -f6)"

if [[ -z "$RUNTIME_HOME" || ! -d "$RUNTIME_HOME" ]]; then
  echo "Runtime home directory is invalid for $RUNTIME_USER: $RUNTIME_HOME" >&2
  exit 1
fi

python3 -m venv /opt/wp-guardian/venv
/opt/wp-guardian/venv/bin/pip install --no-build-isolation .
ln -sfn /opt/wp-guardian/venv/bin/wp-guardian /usr/local/bin/wp-guardian

install -d -o root -g "$RUNTIME_GROUP" -m 0750 /etc/wp-guardian
install -d -o "$RUNTIME_USER" -g "$RUNTIME_GROUP" -m 0750 \
  /var/lib/wp-guardian \
  /var/lib/wp-guardian/reports

if [[ ! -f /etc/wp-guardian/guardian.toml ]]; then
  install -o root -g "$RUNTIME_GROUP" -m 0640 \
    config/guardian.toml.example \
    /etc/wp-guardian/guardian.toml
fi

install -o root -g root -m 0644 \
  systemd/wp-guardian.service \
  /etc/systemd/system/wp-guardian.service
install -o root -g root -m 0644 \
  systemd/wp-guardian.timer \
  /etc/systemd/system/wp-guardian.timer

systemctl daemon-reload

# The service is intentionally not enabled or started automatically.
echo "Installed in read-only mode."
echo "Runtime account: $RUNTIME_USER:$RUNTIME_GROUP"
echo "Root is used only for installation; audits run as $RUNTIME_USER."
echo "Run as $RUNTIME_USER:"
echo "  sudo -u $RUNTIME_USER wp-guardian --config /etc/wp-guardian/guardian.toml sites"
echo "  sudo -u $RUNTIME_USER wp-guardian --config /etc/wp-guardian/guardian.toml audit --domain softico.ua"

#!/usr/bin/env bash
set -euo pipefail

RUNTIME_USER="admin"
PYTHON_BIN="${PYTHON_BIN:-python3}"
INSTALL_ROOT="/opt/wp-guardian"
VENV_DIR="$INSTALL_ROOT/venv"
VENV_NEW="$INSTALL_ROOT/venv.new"
VENV_OLD="$INSTALL_ROOT/venv.old"

if [[ ${EUID} -ne 0 ]]; then
  echo "Run the installer with sudo/root privileges" >&2
  exit 1
fi

if ! id "$RUNTIME_USER" >/dev/null 2>&1; then
  echo "Required runtime user does not exist: $RUNTIME_USER" >&2
  exit 1
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python interpreter not found: $PYTHON_BIN" >&2
  exit 1
fi

RUNTIME_GROUP="$(id -gn "$RUNTIME_USER")"
RUNTIME_HOME="$(getent passwd "$RUNTIME_USER" | cut -d: -f6)"
PYTHON_VERSION="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"

if [[ -z "$RUNTIME_HOME" || ! -d "$RUNTIME_HOME" ]]; then
  echo "Runtime home directory is invalid for $RUNTIME_USER: $RUNTIME_HOME" >&2
  exit 1
fi

install -d -o root -g root -m 0755 "$INSTALL_ROOT"
rm -rf "$VENV_NEW"

if ! "$PYTHON_BIN" -m venv "$VENV_NEW"; then
  rm -rf "$VENV_NEW"
  cat >&2 <<EOF
Unable to create a Python virtual environment.

On Debian/Ubuntu install the matching venv package:
  sudo apt update
  sudo apt install -y python${PYTHON_VERSION}-venv

If the version-specific package is unavailable, use:
  sudo apt install -y python3-venv

Then run this installer again.
EOF
  exit 1
fi

"$VENV_NEW/bin/pip" install --no-build-isolation .

rm -rf "$VENV_OLD"
if [[ -d "$VENV_DIR" ]]; then
  mv "$VENV_DIR" "$VENV_OLD"
fi
mv "$VENV_NEW" "$VENV_DIR"
rm -rf "$VENV_OLD"

ln -sfn "$VENV_DIR/bin/wp-guardian" /usr/local/bin/wp-guardian

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

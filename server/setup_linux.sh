#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run this installer with sudo/root." >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
APP_DIR="/opt/myspeedify"
SECRET_DIR="/etc/myspeedify"
SECRET_FILE="$SECRET_DIR/secret"
SYSCTL_FILE="/etc/sysctl.d/90-myspeedify-ipv4-forward.conf"
FIREWALL_UNIT="/etc/systemd/system/myspeedify-firewall.service"
SERVER_UNIT="/etc/systemd/system/myspeedify-server.service"

if [[ ! -f "$REPO_ROOT/relay.py" || ! -d "$REPO_ROOT/core" || ! -d "$REPO_ROOT/server" ]]; then
    echo "Run the installer from a complete MySpeedify checkout." >&2
    exit 1
fi
if [[ -L "$APP_DIR" || ( -e "$APP_DIR" && ! -d "$APP_DIR" ) ]]; then
    echo "Refusing to use a non-directory or symlinked app path: $APP_DIR" >&2
    exit 1
fi
for managed_dir in "$APP_DIR/core" "$APP_DIR/server"; do
    if [[ -L "$managed_dir" || ( -e "$managed_dir" && ! -d "$managed_dir" ) ]]; then
        echo "Refusing to use a non-directory or symlinked app path: $managed_dir" >&2
        exit 1
    fi
    if [[ -d "$managed_dir" ]]; then
        if ! symlink_path="$(find "$managed_dir" -type l -print -quit)"; then
            echo "Could not inspect managed app path: $managed_dir" >&2
            exit 1
        fi
        if [[ -n "$symlink_path" ]]; then
            echo "Refusing to use a symlink in managed app path: $symlink_path" >&2
            exit 1
        fi
    fi
done
if [[ -L "$APP_DIR/relay.py" ||
      ( -e "$APP_DIR/relay.py" && ! -f "$APP_DIR/relay.py" ) ]]; then
    echo "Refusing to use a non-regular or symlinked app path: $APP_DIR/relay.py" >&2
    exit 1
fi
if [[ -L "$APP_DIR/venv" ||
      ( -e "$APP_DIR/venv" && ! -d "$APP_DIR/venv" ) ]]; then
    echo "Refusing to use a non-directory or symlinked app path: $APP_DIR/venv" >&2
    exit 1
fi
if [[ -L "$SECRET_DIR" || ( -e "$SECRET_DIR" && ! -d "$SECRET_DIR" ) ]]; then
    echo "Refusing to use a non-directory or symlinked secret path: $SECRET_DIR" >&2
    exit 1
fi
if [[ -L "$SYSCTL_FILE" ]]; then
    echo "Refusing to use a symlinked sysctl config: $SYSCTL_FILE" >&2
    exit 1
fi
if [[ -e "$SYSCTL_FILE" && ! -f "$SYSCTL_FILE" ]]; then
    echo "Refusing to use a non-regular sysctl config: $SYSCTL_FILE" >&2
    exit 1
fi
if [[ -e "$SYSCTL_FILE" ]] &&
   ! grep -Fxq "net.ipv4.ip_forward=1" "$SYSCTL_FILE"; then
    echo "Refusing to overwrite existing sysctl config: $SYSCTL_FILE" >&2
    exit 1
fi
if [[ -L "$SECRET_FILE" || ( -e "$SECRET_FILE" && ! -f "$SECRET_FILE" ) ]]; then
    echo "Refusing to use a non-regular or symlinked secret path: $SECRET_FILE" >&2
    exit 1
fi
for unit_file in "$FIREWALL_UNIT" "$SERVER_UNIT"; do
    if [[ -L "$unit_file" || ( -e "$unit_file" && ! -f "$unit_file" ) ]]; then
        echo "Refusing to overwrite a non-regular or symlinked systemd unit: $unit_file" >&2
        exit 1
    fi
done

echo "Installing MySpeedify v2 relay dependencies..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 python3-venv iptables iproute2
modprobe tun

install -d -o root -g root -m 0755 "$APP_DIR"
if [[ "$REPO_ROOT" != "$APP_DIR" ]]; then
    cp -r "$REPO_ROOT/core" "$APP_DIR/"
    cp "$REPO_ROOT/relay.py" "$APP_DIR/"
    cp -r "$REPO_ROOT/server" "$APP_DIR/"
fi

if ! getent group myspeedify >/dev/null 2>&1; then
    groupadd --system myspeedify
fi
if ! id -u myspeedify >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin --gid myspeedify myspeedify
fi

install -d -o root -g myspeedify -m 0750 "$SECRET_DIR"
if [[ ! -s "$SECRET_FILE" ]]; then
    (umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > "$SECRET_FILE")
fi
chown myspeedify:myspeedify "$SECRET_FILE"
chmod 0600 "$SECRET_FILE"

if [[ ! -e "$SYSCTL_FILE" ]]; then
    printf '%s\n' "net.ipv4.ip_forward=1" > "$SYSCTL_FILE"
    chmod 0644 "$SYSCTL_FILE"
fi
sysctl -w net.ipv4.ip_forward=1

python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install --require-hashes -r "$APP_DIR/server/requirements.lock.txt"

if ! PYTHONPATH="$APP_DIR" "$APP_DIR/venv/bin/python" -c '
from pathlib import Path
import sys
from core.crypto import derive_psk
derive_psk(Path(sys.argv[1]).read_text(encoding="utf-8").strip())
' "$SECRET_FILE"; then
    echo "The existing relay secret is not a canonical 32-byte URL-safe key." >&2
    echo "Run server/rotate_secret.sh, then securely update every client." >&2
    exit 1
fi

cat > "$FIREWALL_UNIT" <<EOF
[Unit]
Description=MySpeedify scoped Linux firewall policy
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$APP_DIR/venv/bin/python3 $APP_DIR/server/firewall.py install --wan auto
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

cat > "$SERVER_UNIT" <<EOF
[Unit]
Description=MySpeedify v2 Channel Bonding Relay
Requires=myspeedify-firewall.service
After=network-online.target myspeedify-firewall.service
Wants=network-online.target

[Service]
Type=simple
User=myspeedify
Group=myspeedify
WorkingDirectory=$APP_DIR
Environment=MYSPEEDIFY_SECRET_FILE=$SECRET_FILE
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$APP_DIR/venv/bin/python3 -m relay
Restart=on-failure
RestartSec=3
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
BindPaths=/dev/net/tun
DeviceAllow=/dev/null rw
DeviceAllow=/dev/zero rw
DeviceAllow=/dev/full rw
DeviceAllow=/dev/random r
DeviceAllow=/dev/urandom r
RestrictSUIDSGID=yes
LockPersonality=yes
DeviceAllow=/dev/net/tun rw

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable myspeedify-firewall.service myspeedify-server.service
systemctl restart myspeedify-firewall.service
systemctl restart myspeedify-server.service

echo "MySpeedify v2 relay is installed."
echo "The client secret is stored at $SECRET_FILE; transfer it securely to clients."
echo "Firewall rules use dedicated MySpeedify chains; unrelated host chains are preserved."

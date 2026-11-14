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

if [[ ! -f "$REPO_ROOT/relay.py" || ! -d "$REPO_ROOT/core" || ! -d "$REPO_ROOT/server" ]]; then
    echo "Run the installer from a complete MySpeedify checkout." >&2
    exit 1
fi
if [[ -L "$APP_DIR" || ( -e "$APP_DIR" && ! -d "$APP_DIR" ) ]]; then
    echo "Refusing to use a non-directory or symlinked app path: $APP_DIR" >&2
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

if [[ -L "$SECRET_FILE" || ( -e "$SECRET_FILE" && ! -f "$SECRET_FILE" ) ]]; then
    echo "Refusing to use a non-regular or symlinked secret path: $SECRET_FILE" >&2
    exit 1
fi
install -d -o root -g myspeedify -m 0750 "$SECRET_DIR"
if [[ ! -s "$SECRET_FILE" ]]; then
    (umask 077; head -c 32 /dev/urandom | base64 > "$SECRET_FILE")
fi
chown myspeedify:myspeedify "$SECRET_FILE"
chmod 0600 "$SECRET_FILE"

if [[ -e "$SYSCTL_FILE" ]]; then
    if ! grep -Fxq "net.ipv4.ip_forward=1" "$SYSCTL_FILE"; then
        echo "Refusing to overwrite existing sysctl config: $SYSCTL_FILE" >&2
        exit 1
    fi
else
    printf '%s\n' "net.ipv4.ip_forward=1" > "$SYSCTL_FILE"
    chmod 0644 "$SYSCTL_FILE"
fi
sysctl -w net.ipv4.ip_forward=1

python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install --require-hashes -r "$APP_DIR/server/requirements.lock.txt"

if [[ -L /etc/systemd/system/myspeedify-firewall.service ||
      -L /etc/systemd/system/myspeedify-server.service ]]; then
    echo "Refusing to overwrite symlinked MySpeedify systemd unit files." >&2
    exit 1
fi

cat > /etc/systemd/system/myspeedify-firewall.service <<EOF
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

cat > /etc/systemd/system/myspeedify-server.service <<EOF
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

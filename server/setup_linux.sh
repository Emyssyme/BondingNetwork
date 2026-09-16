#!/usr/bin/env bash
# ==============================================================================
# MySpeedify Aggregation Relay Server - 1-Click Linux Setup Script
# Works on Ubuntu 20.04/22.04/24.04 and Debian 11/12
# ==============================================================================

set -e

echo "=================================================="
echo "  Installing MySpeedify Aggregation Server        "
echo "=================================================="

# 1. Update and install prerequisites
apt-get update
apt-get install -y python3 python3-pip python3-venv iptables iptables-persistent iproute2 ufw

# 2. Enable IPv4 and IPv6 Forwarding
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-myspeedify.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-myspeedify.conf
sysctl -p /etc/sysctl.d/99-myspeedify.conf

# 3. Detect default internet interface
WAN_IFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
echo "[*] Detected default WAN interface: $WAN_IFACE"

# 4. Configure iptables NAT Masquerade
iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT

# Save iptables rules
netfilter-persistent save

# 5. Open UDP port 51820 on firewall
ufw allow 51820/udp comment "MySpeedify Tunnel" || true

# 6. Setup Python environment
mkdir -p /opt/myspeedify
cp -r ../core /opt/myspeedify/
cp -r . /opt/myspeedify/server/

python3 -m venv /opt/myspeedify/venv
/opt/myspeedify/venv/bin/pip install --upgrade pip
/opt/myspeedify/venv/bin/pip install cryptography

# 7. Create Systemd Service
cat <<EOF > /etc/systemd/system/myspeedify-server.service
[Unit]
Description=MySpeedify Channel Bonding Relay Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/myspeedify
ExecStart=/opt/myspeedify/venv/bin/python3 -m server.relay
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable myspeedify-server
systemctl restart myspeedify-server

echo "=================================================="
echo "  MySpeedify Server is now LIVE & RUNNING!        "
echo "  Listening on UDP Port: 51820                    "
echo "=================================================="

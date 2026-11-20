# ⚡ MySpeedify — Next-Gen Channel Bonding VPN

**MySpeedify** is an experimental channel-bonding VPN prototype. It can distribute tunnel packets across multiple network interfaces and provides a local dashboard. Actual throughput, loss recovery, and failover depend on the network and have not yet been validated on multihomed production hosts.

---

## 🌟 Key Features

- 🚀 **Dynamic Speed Bonding (Capacity / Loss Weighted)**:
  Selects paths using probe-derived relative capacity and quality weights.
- 🛡️ **Streamer / Redundant Mode (Packet Duplication)**:
  Sends copies across active links to improve resilience; it does not guarantee zero packet loss.
- 🔄 **Redundant Failover Mode**:
  Prefers configured path priorities and switches when probes indicate a path is unhealthy.
- ⏱️ **Sliding-Window Jitter & Sequence Reorder Buffer**:
  Reorders packets while they are inside the configured hold window and reports delayed delivery and skipped gaps.
- 🔐 **Authenticated Encryption**:
  ChaCha20-Poly1305 packet encryption with per-session directional keys and authenticated headers.
- 📊 **Local Dashboard**:
  WebSocket telemetry, per-adapter status, and bonding-mode controls.
- 🌐 **Linux VPS Deployment**:
  Installer with dedicated firewall chains and a least-privilege relay service.

---

## 🏗️ Architecture

```
+-------------------------------------------------------------------------+
|                              CLIENT HOST                                |
|                                                                         |
|  [Applications (Browser, Games, OBS, Discord, etc.)]                    |
|                           |                                             |
|                     [Wintun / TUN] (Virtual Network Adapter)            |
|                           |                                             |
|        [Bonding Engine / Packet Scheduler / Reorder Buffer]             |
|              /            |                   \                         |
|      [Socket Bound       [Socket Bound       [Socket Bound              |
|         to NIC 1]           to NIC 2]           to NIC 3]               |
|      (e.g., Ethernet)    (e.g., Wi-Fi)       (e.g., 4G/5G)              |
+-------------|-------------------|-------------------|-------------------+
              | (Encrypted UDP)   | (Encrypted UDP)   | (Encrypted UDP)
              v                   v                   v
+-------------------------------------------------------------------------+
|                        AGGREGATION SERVER (RELAY)                       |
|                                                                         |
|        [Server Multipath Tunnel Receiver / Reorder Buffer]              |
|                           |                                             |
|                     [Server TUN / TAP]                                  |
|                           |                                             |
|                [NAT / iptables Masquerade]                              |
|                           |                                             |
|                     (Open Internet)                                     |
+-------------------------------------------------------------------------+
```

---

## 🚀 Quick Start Guide

### 1. Install Dependencies
```bash
python -m pip install --require-hashes -r requirements.lock.txt
```

`requirements.txt` records the direct runtime constraints; the hash-pinned
`requirements.lock.txt` is used for reproducible client and dashboard installs.
The Linux relay installer uses a separate, minimal hash-pinned dependency lock.
To update the locks, use `pip-tools==7.6.2`:
```bash
python -m pip install pip-tools==7.6.2
pip-compile --generate-hashes --output-file=requirements.lock.txt requirements.txt
pip-compile --generate-hashes --output-file=server/requirements.lock.txt server/requirements.in
```

### 2. Launch the client and local dashboard
```bash
python main.py --server-host YOUR_VPS_IP --port 51820
```
Configure `MYSPEEDIFY_SECRET_FILE` to point to a protected file containing
the relay's shared secret or this client's unique secret. For
per-client authentication, also set `MYSPEEDIFY_CLIENT_ID` to the ID
provisioned on the relay. The client prints a one-time
dashboard URL bound to localhost. Windows requires the bundled, hash-verified
Wintun driver and Administrator rights; Linux requires `/dev/net/tun`,
route-management privileges, and `systemd-resolved` for DNS integration.
If the client process is terminated abnormally and network access remains
blocked, close any running instance and run `python main.py --cleanup` with
Administrator/root privileges. Cleanup refuses to run while another instance
holds the client lock.

### Windows client installer

Windows installers are built from version tags (for example `v0.1.0`) and
attached to the GitHub release. The workflow can also be started manually from
GitHub Actions; its installer is then available as a workflow artifact.

To build locally, install 64-bit Python 3.12-3.14, the hash-pinned runtime
dependencies, PyInstaller 6.22.3, and Inno Setup 6, then run in PowerShell from
the repository root:

```powershell
python -m pip install --require-hashes -r requirements.lock.txt
python -m pip install pyinstaller==6.22.3
.\client\build_windows.ps1
```

The installer is written to `dist-installer\MySpeedify-Setup.exe`. It installs
the bundled client and verified Wintun DLL under Program Files, creates Start
Menu and optional desktop shortcuts, and requests administrator approval when
the client starts. It does not install or configure a relay or store client
credentials.

To build only the standalone executable, install 64-bit Python 3.12-3.14, the
hash-pinned runtime dependencies, and PyInstaller 6.22.3 as above; Inno Setup
is not needed. Then run:

```powershell
.\client\build_exe.ps1
```

This creates the self-contained `dist\MySpeedify.exe`; it still requires
Administrator approval at launch and the client credentials configured below.

Before launching the client, configure its relay and secret in the current
Windows user's environment. For example, in PowerShell, create a secret file
without putting its value in shell history or the command line:

```powershell
$secretPath = Join-Path $env:LOCALAPPDATA "MySpeedify\secret"
New-Item -ItemType Directory -Force (Split-Path $secretPath) | Out-Null
$secureSecret = Read-Host "Client secret" -AsSecureString
$secretBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret)
try {
    $plainSecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretBstr)
    Set-Content -Path $secretPath -Value $plainSecret -NoNewline -Encoding ascii
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretBstr)
    Remove-Variable plainSecret -ErrorAction SilentlyContinue
}
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $secretPath /inheritance:r /grant:r "${identity}:(F)" "SYSTEM:(F)"
[Environment]::SetEnvironmentVariable("MYSPEEDIFY_SECRET_FILE", $secretPath, "User")
[Environment]::SetEnvironmentVariable("MYSPEEDIFY_SERVER_HOST", "YOUR_VPS_IP", "User")
[Environment]::SetEnvironmentVariable("MYSPEEDIFY_SERVER_PORT", "51820", "User")
```

For a provisioned per-client credential, also set `MYSPEEDIFY_CLIENT_ID` as a
user environment variable. Sign out and back in after setting environment
variables so the Start Menu shortcut receives them. The client secret must be
the canonical 43-character URL-safe base64 value for 32 random bytes.

### Per-client authentication and migration

The v2 relay (`python -m relay`) accepts unique client credentials from the
protected JSON file named by `MYSPEEDIFY_CLIENT_SECRETS_FILE`:

```json
{
  "laptop-01": "REPLACE_WITH_A_UNIQUE_RANDOM_SECRET",
  "phone-01": "REPLACE_WITH_ANOTHER_UNIQUE_RANDOM_SECRET"
}
```

Use IDs of 1-64 letters, digits, `.`, `_` or `-`. Each secret must be a
canonical 43-character URL-safe base64 value encoding 32 random bytes. Generate
one with `python -c "import secrets; print(secrets.token_urlsafe(32))"` and
deliver it through a secure channel. Passphrases and shorter keys are rejected.
Keep the registry and each client's
`MYSPEEDIFY_SECRET_FILE` restricted to the relay service account / client user
(mode `0600` on POSIX). On systemd, configure the relay path with a service
override, for example:

```ini
[Service]
Environment=MYSPEEDIFY_CLIENT_SECRETS_FILE=/etc/myspeedify/clients.json
```

Set `MYSPEEDIFY_CLIENT_ID=laptop-01` on that client's environment. During
migration, the relay can continue accepting a shared 256-bit key through
`MYSPEEDIFY_SECRET_FILE`; clients without `MYSPEEDIFY_CLIENT_ID` use the
shared-key v2 handshake. After all clients have unique IDs and secrets, remove the
shared-secret setting and restart the relay. With the Linux installer, set
`Environment=MYSPEEDIFY_SECRET_FILE=` in the systemd override to disable its
shared-key setting; keep `MYSPEEDIFY_CLIENT_SECRETS_FILE` set. Restarting
disconnects active sessions. To revoke a client, remove its ID from the
registry and restart the relay; to rotate one client's key, update the
registry and that client's secret file, then restart. The former v1 client and
relay implementations have been removed; use the current v2 client and relay.

### Optional flow pinning

Flow pinning is disabled by default. To enable it, set
`MYSPEEDIFY_FLOW_PINNING=1` in the environment of the client and relay; enable
it on both ends for both uplink and downlink. For a systemd relay, add
`Environment=MYSPEEDIFY_FLOW_PINNING=1` to the `myspeedify-server` service
override, then restart the service.

In Speed mode, valid IPv4/IPv6 TCP and UDP flows are pinned by their
bidirectional 5-tuple. Pins expire after 120 seconds idle and are capped at
1,024 flows per scheduler; least-recently-used pins are evicted at the cap.
Malformed, fragmented, or unsupported packets use the existing
weighted scheduler; Failover, Redundant, and urgent-packet behavior is
unchanged.

Speed-mode capacity is estimated from trains of four padded probes and smoothed
across recent estimates. This is a relative burst-capacity signal, not a
throughput guarantee; validate performance on the target network.
When there has been no user traffic for five seconds, the client and relay
switch to one unpadded liveness probe every five seconds. Padded capacity trains
resume while user traffic is active and for five seconds after it stops.

The relay caps authenticated INITs at eight new sessions per client per minute,
retains at most 64 INIT replay entries per client, and accepts at most 32 paths
per session. Expired session addresses are held for 120 seconds and their
conntrack entries are removed before an address is reassigned.

---

## ☁️ Deploying on a Cloud Relay Server (Linux VPS)

To host your own remote aggregation server on AWS, DigitalOcean, Hetzner, or Linode:

1. SSH into your Ubuntu/Debian VPS:
```bash
git clone https://github.com/Emyssyme/BondingNetwork.git /opt/myspeedify
cd /opt/myspeedify/server
sudo chmod +x setup_linux.sh
sudo ./setup_linux.sh
```
   The installer creates a persistent relay secret at `/etc/myspeedify/secret`
   and configures the relay to read it without placing it in the service command
   line. New secrets are generated as random 256-bit URL-safe keys. If an
   existing secret uses a non-canonical or legacy format, the installer refuses
   to start the updated relay; rotate it and securely update all clients. Transfer
   the secret to clients using a secure channel. It also creates
   dedicated, MySpeedify-owned firewall chains; it does not save or replace the
   host's global iptables rules. The relay runs as the `myspeedify` system user
   with `CAP_NET_ADMIN` for TUN configuration. IPv4 forwarding is enabled;
   IPv6 forwarding is not changed.

   The firewall unit intentionally keeps its policy installed when the relay
   service stops, so stopping the relay does not silently remove host protection.
   To explicitly remove the MySpeedify firewall policy when decommissioning:

   ```bash
   sudo systemctl stop myspeedify-server.service
   sudo python3 /opt/myspeedify/server/firewall.py remove --wan auto
   sudo systemctl stop myspeedify-firewall.service
   ```

To rotate an exposed or expired secret after deploying the updated relay, run:
```bash
sudo bash /opt/myspeedify/server/rotate_secret.sh
```
The script replaces the secret and restarts the relay without printing the
value. Transfer the new file contents securely to every client and update its
protected `MYSPEEDIFY_SECRET_FILE` before reconnecting.

2. Configure the client with the transferred secret through a protected secret
   file referenced by `MYSPEEDIFY_SECRET_FILE`. Do not put the secret in source
   code, shell history, or command-line arguments. Then launch the client using
   the command above.

### Relay metrics

The v2 relay can expose Prometheus text metrics on loopback only. Set
`MYSPEEDIFY_METRICS_PORT` in the relay service environment (for example,
`9100`) and restart it. Read `http://127.0.0.1:9100/metrics` locally or through
an authenticated SSH tunnel; do not publish this endpoint directly. It
reports active, created, and expired sessions, routed packets/bytes, and
authentication failures. It does not expose client IDs, addresses, or
secrets. Relay lifecycle logs already include session IDs for establishment,
path registration, and expiration.

For the systemd relay, add this to its service override:

```ini
[Service]
Environment=MYSPEEDIFY_METRICS_PORT=9100
```

Then restart the service and verify with:

```bash
curl http://127.0.0.1:9100/metrics
```

### Relay scaling limits

The current relay is one process with one UDP socket and a serial event loop.
Each process supports at most 253 active sessions because it allocates client
addresses from one `/24` tunnel pool. Its session, crypto, replay, and reorder
state is process-local; multiple workers sharing a UDP endpoint are not a
supported scaling method. Ordinary UDP 5-tuple affinity is also insufficient
for bonding because one client session can arrive over several physical
source addresses.

For horizontal scale, use independent relay endpoints with separate tunnel
subnets, TUN interfaces, firewall/NAT state, and client assignment; failover
requires the client to reconnect to another endpoint. A transparent load
balancer would need to keep every path for a protocol session on the same
relay, using the session ID in the authenticated protocol header. That routing
and shared session state are not implemented. There are no production
throughput or capacity guarantees; benchmark on the target host and network
before choosing deployment limits.

---

## 🧪 Running Unit Tests
```bash
python -m unittest discover -s tests
```

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VRoute Deploy is a multi-protocol VPN server deployment and management system. It automates the installation, configuration, and monitoring of six VPN protocols on a single Linux server, with centralized user management via MySQL and session tracking via Redis.

## Running & Deployment

All scripts require root. There is no build system, test suite, or linter — this is infrastructure automation code.

```bash
# Full server deployment (all protocols + monitoring services)
sudo bash deploy.sh

# Individual protocol deployment (requires deploy.sh to have run first)
sudo bash ikev2.sh
sudo bash ocserv.sh
sudo bash v2ray.sh
sudo bash openvpn.sh
sudo bash l2tp.sh

# Iran-specific routing setup (optional)
sudo bash IN.sh

# Bulk update files across servers
bash update_servers.sh                                    # interactive
bash update_servers.sh /local/file /remote/path "command" # non-interactive
```

### Monitoring Commands

```bash
# Central session sync (pushes all protocol sessions to Redis)
python3 sync_online.py --loop              # continuous mode
python3 sync_online.py --dry-run           # preview without pushing

# Per-protocol user sync from MySQL
python3 wg_sync.py [--dry-run]             # WireGuard peer sync
python3 v2ray_sync.py [--loop]             # V2RAY user hot-reload via gRPC

# Per-protocol online user display
python3 wg_online.py [--all]
python3 ovpn_online.py
python3 ikev2_online.py
python3 ocserv_online.py
python3 l2tp_online.py
python3 v2ray_online.py [-s rx] [-w]

# Bandwidth monitoring
python3 bw_monitor.py [--loop] [--interval 5] [--top 10]
```

## Architecture

### Three-Layer Design

1. **Deployment Layer (Bash)** — `deploy.sh` + per-protocol `{protocol}.sh` scripts install packages, write configs, create systemd services. All scripts are idempotent.

2. **User Sync Layer (Python)** — `wg_sync.py` and `v2ray_sync.py` pull active users from MySQL and push them to the local VPN daemon (WireGuard via `wg set`, V2RAY via Xray gRPC Handler API). Other protocols authenticate directly via RADIUS.

3. **Monitoring Layer (Python)** — `sync_online.py` (the central hub, ~1200 lines) collects sessions from all six protocols and pushes them to Redis. Protocol-specific `*_online.py` scripts provide CLI views of connected users. `bw_monitor.py` tracks real-time bandwidth.

### Data Flow

```
MySQL (api.vroute.org)                     RADIUS (185.141.168.2)
  │ users, service configs                   │ auth for OpenVPN/IKEv2/ocserv/L2TP
  ▼                                          ▼
wg_sync.py ─► WireGuard              Protocol daemons
v2ray_sync.py ─► Xray gRPC                  │
                                             ▼
                                     sync_online.py ──► Redis (api.vroute.org)
                                      (collects all)        │
                                                            ▼
                                                     Laravel dashboard
```

### Configuration

- **Central config:** `/opt/vroute.conf` (JSON) — created by `deploy.sh`, read by all Python scripts via `vroute_conf.py`
- **Config loader:** `vroute_conf.py` — shared module providing `server_name()`, `server_ids()`, `db()`, `wg_interface()`, `mgmt_sockets()`
- All Python scripts do `sys.path.insert(0, "/opt")` then `import vroute_conf`

### Network Layout (one subnet per protocol)

| Protocol | Interface | Subnet | Port |
|----------|-----------|--------|------|
| WireGuard | wg0 | 10.1.0.0/16 | 11040/UDP |
| OpenVPN TCP | tun0 | 10.2.0.0/16 | 11041/TCP |
| OpenVPN UDP | tun1 | 10.3.0.0/16 | 11041/UDP |
| IKEv2 | xfrm | 10.4.0.0/16 | 500,4500/UDP |
| ocserv | vpns | 10.5.0.0/16 | 443/TCP+DTLS |
| L2TP/IPsec | ppp | 10.6.0.0/24 | 1701/UDP |
| V2RAY/VLESS | — | — | 11042/TCP |

### Authentication Methods

- **RADIUS:** OpenVPN, IKEv2, ocserv, L2TP
- **MySQL UUID (via Xray Handler API):** V2RAY
- **Public key (synced from MySQL):** WireGuard

### Redis Session Format

Keys: `vroute:online:{server_name}:{session_id}` — hash with username, protocol, bytes_rx/tx, connected_at, last_activity. No TTL; Laravel checks `updated_at` for staleness. Full sync every 30 seconds.

### Session Source per Protocol

- WireGuard: `wg show dump`
- OpenVPN: management socket (Unix domain socket)
- IKEv2: `swanctl --list-sas`
- ocserv: `/var/run/ocserv/` user files
- L2TP: `/proc/net/nf_conntrack` + ppp interface files
- V2RAY: Xray Stats API (gRPC) + access log

## Key Conventions

- All deployment scripts use `set -euo pipefail` and colored logging helpers (`info`, `warn`, `error`, `fatal`, `step`)
- Python scripts use argparse with `--dry-run`, `--loop`, and `--poll` patterns
- User-to-IP mappings are cached in JSON files at `/opt/` (`wg_usermap.json`, `v2ray_usermap.json`)
- Certificates for IKEv2 and ocserv are obtained via Let's Encrypt (certbot)
- OpenVPN certificates are pre-deployed in the repo root (`cert_export_*.crt`, `cert_export_*.key`)

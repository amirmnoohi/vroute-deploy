#!/usr/bin/env python3
"""V2Ray (VLESS) User Sync — Pulls active users from MySQL, hot-reloads Xray.

Uses Xray Handler API (gRPC) for zero-downtime user add/remove.
Only restarts Xray when it's not running or API is unresponsive.

Usage:
  python3 v2ray_sync.py --dry-run      # Preview users, don't write config
  python3 v2ray_sync.py                # Single sync
  python3 v2ray_sync.py --loop         # Continuous sync (default poll=5s)
"""

import subprocess
import sys
import os
import json
import uuid
import hashlib
import argparse
import time
from datetime import datetime

try:
    import mysql.connector
except ImportError:
    print("Run: apt install python3-mysql.connector")
    sys.exit(1)

sys.path.insert(0, "/opt")
import vroute_conf

DB = vroute_conf.db()
XRAY_CONFIG = "/usr/local/etc/xray/config.json"
USERMAP_CACHE = "/opt/v2ray_usermap.json"
LISTEN_PORT = 11042
API_ADDR = "127.0.0.1:10085"
INBOUND_TAG = "vless-in"

# Check if vrtun0 exists (for tunnel routing via fwmark)
HAS_TUNNEL = os.path.exists("/sys/class/net/vrtun0")


def log(msg, quiet=False):
    if not quiet:
        print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}")


def fetch_users() -> dict:
    """Fetch active users from MySQL. Returns {username: uuid_str}."""
    conn = mysql.connector.connect(
        host=DB["host"], port=DB["port"], database=DB["name"],
        user=DB["user"], password=DB["pass"], connect_timeout=10,
    )
    cursor = conn.cursor(dictionary=True)

    # Check if v2ray_uuid column exists
    cursor.execute("""
        SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'users' AND COLUMN_NAME = 'v2ray_uuid'
    """, (DB["name"],))
    has_uuid_column = cursor.fetchone() is not None

    if has_uuid_column:
        cursor.execute("""
            SELECT username, v2ray_uuid
            FROM users
            WHERE status = 'active'
              AND locked = 0
              AND deleted_at IS NULL
        """)
    else:
        cursor.execute("""
            SELECT username
            FROM users
            WHERE status = 'active'
              AND locked = 0
              AND deleted_at IS NULL
        """)

    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    users = {}
    for row in rows:
        username = row["username"]
        # Use DB UUID if available, otherwise generate deterministic one
        v2ray_uuid = row.get("v2ray_uuid") if has_uuid_column else None
        if not v2ray_uuid:
            v2ray_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"vroute-v2ray-{username}"))
        users[username] = v2ray_uuid

    return users


# ── Xray Handler API (gRPC) ─────────────────────────────────────────────────

def xray_api_check() -> bool:
    """Check if Xray API is responsive."""
    try:
        result = subprocess.run(
            ["/usr/local/bin/xray", "api", "statsquery",
             "-s", API_ADDR, "-pattern", ""],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def api_add_user(email: str, user_uuid: str) -> bool:
    """Add a user to Xray runtime via Handler API (zero downtime)."""
    user_json = json.dumps({
        "inboundTag": INBOUND_TAG,
        "user": {
            "email": email,
            "level": 0,
            "account": {
                "@type": "xray.proxy.vless.Account",
                "id": user_uuid,
            }
        }
    })
    try:
        result = subprocess.run(
            ["/usr/local/bin/xray", "api", "adi", "-s", API_ADDR],
            input=user_json,
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def api_remove_user(email: str) -> bool:
    """Remove a user from Xray runtime via Handler API (zero downtime)."""
    user_json = json.dumps({
        "inboundTag": INBOUND_TAG,
        "email": email,
    })
    try:
        result = subprocess.run(
            ["/usr/local/bin/xray", "api", "rmi", "-s", API_ADDR],
            input=user_json,
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


# ── Config generation ────────────────────────────────────────────────────────

def generate_config(users: dict) -> dict:
    """Generate Xray config.json with all users."""
    clients = []
    for username, user_uuid in users.items():
        clients.append({
            "id": user_uuid,
            "email": username,
            "level": 0,
        })

    # Freedom outbound — with fwmark if tunnel available
    freedom_outbound = {
        "tag": "direct",
        "protocol": "freedom",
        "settings": {},
    }
    if HAS_TUNNEL:
        freedom_outbound["streamSettings"] = {
            "sockopt": {
                "mark": 2
            }
        }

    config = {
        "log": {
            "access": "/var/log/xray/access.log",
            "error": "/var/log/xray/error.log",
            "loglevel": "warning"
        },
        "stats": {},
        "api": {
            "tag": "api",
            "listen": f"127.0.0.1:{API_ADDR.split(':')[1]}",
            "services": ["HandlerService", "StatsService"]
        },
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True
            }
        },
        "inbounds": [
            {
                "tag": INBOUND_TAG,
                "port": LISTEN_PORT,
                "listen": "0.0.0.0",
                "protocol": "vless",
                "settings": {
                    "clients": clients,
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "none",
                    "tcpSettings": {
                        "header": {
                            "type": "http",
                            "request": {
                                "version": "1.1",
                                "method": "GET",
                                "path": ["/"],
                                "headers": {
                                    "Host": [
                                        "bale.ai",
                                        "web.igap.net",
                                        "igap.net"
                                    ],
                                    "User-Agent": [
                                        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
                                        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/53.0.2785.109 Mobile/14A456 Safari/601.1.46"
                                    ],
                                    "Accept-Encoding": ["gzip, deflate"],
                                    "Connection": ["keep-alive"],
                                    "Pragma": "no-cache"
                                }
                            },
                            "response": {
                                "version": "1.1",
                                "status": "200",
                                "reason": "OK",
                                "headers": {
                                    "Content-Type": ["application/octet-stream", "video/mpeg"],
                                    "Transfer-Encoding": ["chunked"],
                                    "Connection": ["keep-alive"],
                                    "Pragma": "no-cache"
                                }
                            }
                        }
                    }
                }
            }
        ],
        "outbounds": [
            freedom_outbound,
            {
                "tag": "blocked",
                "protocol": "blackhole",
                "settings": {}
            }
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["api"],
                    "outboundTag": "api"
                },
                {
                    "type": "field",
                    "outboundTag": "blocked",
                    "protocol": ["bittorrent"]
                }
            ]
        }
    }
    return config


def write_usermap(users: dict):
    """Write uuid<->username mapping cache for v2ray_online.py."""
    usermap = {
        "by_uuid": {v: k for k, v in users.items()},
        "by_username": users,
    }
    with open(USERMAP_CACHE, "w") as f:
        json.dump(usermap, f, indent=2)


def get_users_hash(users: dict) -> str:
    """Get MD5 hash of user list for change detection."""
    return hashlib.md5(json.dumps(users, sort_keys=True).encode()).hexdigest()


def get_cached_users() -> dict:
    """Get currently cached user list {username: uuid}."""
    try:
        with open(USERMAP_CACHE) as f:
            data = json.load(f)
        return data.get("by_username", {})
    except Exception:
        return {}


def get_cached_hash() -> str:
    """Get hash of currently cached user list."""
    return get_users_hash(get_cached_users())


def run_once(dry: bool = False) -> dict:
    """Single sync cycle. Returns stats dict."""
    t0 = time.time()

    users = fetch_users()

    if dry:
        log(f"Found {len(users)} active users:")
        for username, user_uuid in sorted(users.items()):
            print(f"  {username}: {user_uuid}")
        print(f"\nTunnel routing: {'fwmark 0x2 via vrtun0' if HAS_TUNNEL else 'direct (no vrtun0)'}")
        print(f"Listen port: {LISTEN_PORT}/TCP")
        return {"db_users": len(users), "changed": False}

    new_hash = get_users_hash(users)
    old_hash = get_cached_hash()

    if new_hash == old_hash:
        elapsed_ms = int((time.time() - t0) * 1000)
        return {"db_users": len(users), "changed": False, "elapsed_ms": elapsed_ms}

    # Safety: don't wipe all users if DB returns empty
    if len(users) == 0:
        cached = get_cached_users()
        if len(cached) > 50:
            log(f"SAFETY ABORT: DB returned 0 users but cache has {len(cached)}.")
            return {"db_users": 0, "changed": False, "error": "safety_abort"}

    # Compute diff
    cached_users = get_cached_users()
    to_add = {u: uid for u, uid in users.items() if u not in cached_users}
    to_remove = {u: uid for u, uid in cached_users.items() if u not in users}
    to_update = {u: uid for u, uid in users.items()
                 if u in cached_users and cached_users[u] != uid}

    # Always write config.json (for persistence on restart/reboot)
    config = generate_config(users)
    os.makedirs(os.path.dirname(XRAY_CONFIG), exist_ok=True)
    with open(XRAY_CONFIG, "w") as f:
        json.dump(config, f, indent=4)

    # Always write usermap cache
    write_usermap(users)

    # Try hot-reload via API (zero downtime)
    api_ok = xray_api_check()
    added = removed = updated = 0
    need_restart = False

    if api_ok and (to_add or to_remove or to_update):
        # Remove deleted users
        for email in to_remove:
            if api_remove_user(email):
                removed += 1

        # Remove users with changed UUIDs (re-add with new UUID)
        for email in to_update:
            api_remove_user(email)

        # Add new users + updated users
        for email, uid in {**to_add, **to_update}.items():
            if api_add_user(email, uid):
                added += 1
            else:
                # API add failed — need full restart
                need_restart = True
                break

        updated = len(to_update)

    elif not api_ok:
        # API not responding — need restart
        need_restart = True

    # Full restart only if API failed or Xray isn't running
    restarted = False
    if need_restart:
        result = subprocess.run(
            ["systemctl", "restart", "xray"],
            capture_output=True, text=True, timeout=30,
        )
        restarted = result.returncode == 0
        if not restarted:
            log(f"WARNING: Xray restart failed: {result.stderr.strip()}")

    elapsed_ms = int((time.time() - t0) * 1000)

    return {
        "db_users": len(users),
        "changed": True,
        "added": added,
        "removed": removed,
        "updated": updated,
        "hot_reload": api_ok and not need_restart,
        "restarted": restarted,
        "elapsed_ms": elapsed_ms,
    }


def main():
    parser = argparse.ArgumentParser(description="Sync V2Ray (VLESS) users with MySQL")
    parser.add_argument("--dry-run", "-n", action="store_true")
    parser.add_argument("--loop", action="store_true", help="Run continuously as a service")
    parser.add_argument("--poll", type=float, default=5.0, help="Poll interval in seconds (default: 5)")
    args = parser.parse_args()

    if args.dry_run:
        log("DRY RUN — V2Ray user sync")
        run_once(dry=True)
        return

    if not args.loop:
        stats = run_once()
        if "error" in stats:
            sys.exit(1)
        if stats["changed"]:
            method = "hot-reload" if stats.get("hot_reload") else "restart"
            log(f"DB={stats['db_users']} | +{stats.get('added', 0)} -{stats.get('removed', 0)} "
                f"~{stats.get('updated', 0)} | {method} | {stats['elapsed_ms']}ms")
        else:
            log(f"DB={stats['db_users']} | no changes | {stats['elapsed_ms']}ms")
        return

    # Continuous loop
    log(f"Starting V2Ray sync service (poll={args.poll}s, port={LISTEN_PORT})")
    log(f"Tunnel: {'fwmark 0x2 via vrtun0' if HAS_TUNNEL else 'direct (no vrtun0)'}")
    cycle = 0
    while True:
        cycle += 1
        try:
            stats = run_once()
            if "error" not in stats:
                ts = datetime.now().strftime("%H:%M:%S")
                if stats["changed"]:
                    method = "API" if stats.get("hot_reload") else "RESTART"
                    print(
                        f"[{ts}] #{cycle} | DB={stats['db_users']} "
                        f"| +{stats.get('added', 0)} -{stats.get('removed', 0)} "
                        f"~{stats.get('updated', 0)} | {method} | {stats.get('elapsed_ms', 0)}ms"
                    )
                else:
                    print(
                        f"[{ts}] #{cycle} | DB={stats['db_users']} "
                        f"| ok | {stats.get('elapsed_ms', 0)}ms"
                    )
        except KeyboardInterrupt:
            log(f"Stopped after {cycle} cycles.")
            break
        except Exception as e:
            print(f"[ERROR] Cycle #{cycle}: {e}")

        try:
            time.sleep(args.poll)
        except KeyboardInterrupt:
            log(f"Stopped after {cycle} cycles.")
            break


if __name__ == "__main__":
    main()

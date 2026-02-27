#!/usr/bin/env python3
"""WireGuard Peer Sync — Pulls active users from MySQL, syncs local WG interface."""

import subprocess
import sys
import argparse
import json
from datetime import datetime

try:
    import mysql.connector
except ImportError:
    print("Run: apt install python3-mysql.connector")
    sys.exit(1)

sys.path.insert(0, "/opt")
import vroute_conf

DB = vroute_conf.db()
WG_INTERFACE = vroute_conf.wg_interface()
CACHE_FILE = "/opt/wg_usermap.json"


def log(msg, quiet=False):
    if not quiet:
        print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}")


def fetch_expected_peers() -> dict:
    conn = mysql.connector.connect(
        host=DB["host"], port=DB["port"], database=DB["name"],
        user=DB["user"], password=DB["pass"], connect_timeout=10,
    )
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT username, wireguard_public, wireguard_ip
        FROM users
        WHERE status = 'active'
          AND locked = 0
          AND wireguard_public IS NOT NULL
          AND wireguard_ip IS NOT NULL
          AND deleted_at IS NULL
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return {
        row["wireguard_public"]: {
            "username": row["username"],
            "ip": row["wireguard_ip"],
        }
        for row in rows
    }


def get_current_peers(iface: str) -> set:
    result = subprocess.run(
        ["wg", "show", iface, "peers"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"wg show failed: {result.stderr.strip()}")
    return {line.strip() for line in result.stdout.strip().split("\n") if line.strip()}


def add_peer(iface, pubkey, allowed_ip):
    return subprocess.run(
        ["wg", "set", iface, "peer", pubkey, "allowed-ips", f"{allowed_ip}/32"],
        capture_output=True, text=True, timeout=10,
    ).returncode == 0


def remove_peer(iface, pubkey):
    return subprocess.run(
        ["wg", "set", iface, "peer", pubkey, "remove"],
        capture_output=True, text=True, timeout=10,
    ).returncode == 0


def run_once(iface: str, dry: bool = False) -> dict:
    """Single sync cycle. Returns stats dict."""
    import time as _time
    t0 = _time.time()

    expected = fetch_expected_peers()

    # Write local cache for wg_online.py
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(expected, f)
    except Exception:
        pass

    current = get_current_peers(iface)

    expected_keys = set(expected.keys())
    to_add = expected_keys - current
    to_remove = current - expected_keys

    if len(expected) == 0 and len(current) > 50:
        print(f"SAFETY ABORT: DB returned 0 peers but WG has {len(current)}.")
        return {"error": "safety_abort"}
    if len(to_remove) > len(current) * 0.8 and len(current) > 50:
        print(f"SAFETY ABORT: Would remove {len(to_remove)}/{len(current)} peers (>80%).")
        return {"error": "safety_abort"}

    added = removed = errors = 0

    for pubkey in to_remove:
        if dry:
            print(f"  [DRY-RUN] REMOVE: {pubkey}")
        else:
            if remove_peer(iface, pubkey):
                removed += 1
            else:
                print(f"  FAIL removing: {pubkey}")

    for pubkey in to_add:
        user = expected[pubkey]
        if dry:
            print(f"  [DRY-RUN] ADD: {user['username']} ({user['ip']}) key={pubkey}")
        else:
            if add_peer(iface, pubkey, user["ip"]):
                added += 1
            else:
                print(f"  FAIL adding: {user['username']} ({user['ip']})")
                errors += 1
        if (added + errors) % 500 == 0 and (added + errors) > 0:
            print(f"  Progress: {added + errors}/{len(to_add)}")

    elapsed_ms = int((_time.time() - t0) * 1000)

    return {
        "db_peers": len(expected),
        "wg_peers": len(current),
        "added": added,
        "removed": removed,
        "errors": errors,
        "elapsed_ms": elapsed_ms,
    }


def main():
    import time as _time

    parser = argparse.ArgumentParser(description="Sync WireGuard peers with MySQL")
    parser.add_argument("--interface", "-i", default=WG_INTERFACE)
    parser.add_argument("--dry-run", "-n", action="store_true")
    parser.add_argument("--loop", action="store_true", help="Run continuously as a service")
    parser.add_argument("--poll", type=float, default=5.0, help="Poll interval in seconds (default: 5)")
    args = parser.parse_args()

    if args.dry_run:
        log(f"DRY RUN — syncing {args.interface}")
        run_once(args.interface, dry=True)
        return

    if not args.loop:
        # Single run
        stats = run_once(args.interface)
        if "error" in stats:
            sys.exit(1)
        log(f"DB={stats['db_peers']} WG={stats['wg_peers']} | +{stats['added']} -{stats['removed']} err={stats['errors']} | {stats['elapsed_ms']}ms")
        return

    # Continuous loop
    log(f"Starting WG sync service (poll={args.poll}s, iface={args.interface})")
    cycle = 0
    while True:
        cycle += 1
        try:
            stats = run_once(args.interface)
            if "error" not in stats:
                ts = datetime.now().strftime("%H:%M:%S")
                changed = stats["added"] + stats["removed"]
                print(
                    f"[{ts}] #{cycle} | DB={stats['db_peers']} WG={stats['wg_peers']} "
                    f"| +{stats['added']} -{stats['removed']} err={stats['errors']} "
                    f"| {stats['elapsed_ms']}ms"
                )
        except KeyboardInterrupt:
            log(f"Stopped after {cycle} cycles.")
            break
        except Exception as e:
            print(f"[ERROR] Cycle #{cycle}: {e}")

        try:
            _time.sleep(args.poll)
        except KeyboardInterrupt:
            log(f"Stopped after {cycle} cycles.")
            break


if __name__ == "__main__":
    main()

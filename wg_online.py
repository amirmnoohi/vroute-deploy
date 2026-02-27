#!/usr/bin/env python3
"""Show WireGuard users — online (default) or all peers.
Uses local cache file for instant username lookups (no DB query)."""

import subprocess
import sys
import time
import json
import os
import argparse

sys.path.insert(0, "/opt")
import vroute_conf

WG_INTERFACE = vroute_conf.wg_interface()
ONLINE_THRESHOLD = 120  # seconds
CACHE_FILE = "/opt/wg_usermap.json"


def load_usermap() -> dict:
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def get_peers(iface: str) -> list:
    result = subprocess.run(
        ["wg", "show", iface, "dump"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        print(f"ERROR: wg show failed: {result.stderr.strip()}")
        sys.exit(1)

    now = int(time.time())
    peers = []
    lines = result.stdout.strip().split("\n")
    if len(lines) < 2:
        return peers

    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 7:
            continue

        pubkey = parts[0]
        endpoint = parts[2]
        allowed_ips = parts[3]
        latest_handshake = int(parts[4])
        rx_bytes = int(parts[5])
        tx_bytes = int(parts[6])

        if latest_handshake > 0:
            age = now - latest_handshake
            online = age <= ONLINE_THRESHOLD
        else:
            age = None
            online = False

        peers.append({
            "pubkey": pubkey,
            "endpoint": endpoint,
            "allowed_ips": allowed_ips,
            "handshake_age": age,
            "online": online,
            "rx": rx_bytes,
            "tx": tx_bytes,
        })

    return peers


def fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / 1024 / 1024:.1f} MB"
    else:
        return f"{b / 1024 / 1024 / 1024:.2f} GB"


def fmt_age(age) -> str:
    if age is None:
        return "never"
    if age < 60:
        return f"{age}s ago"
    elif age < 3600:
        return f"{age // 60}m ago"
    elif age < 86400:
        return f"{age // 3600}h {(age % 3600) // 60}m ago"
    else:
        return f"{age // 86400}d {(age % 86400) // 3600}h ago"


SORT_KEYS = {
    "handshake": lambda p: (p["handshake_age"] is None, p["handshake_age"] if p["handshake_age"] is not None else 999999999),
    "rx": lambda p: p["rx"],
    "tx": lambda p: p["tx"],
    "username": lambda p: p.get("_username", "").lower(),
}


def main():
    parser = argparse.ArgumentParser(description="Show WireGuard users")
    parser.add_argument("-i", "--interface", default=WG_INTERFACE)
    parser.add_argument("-a", "--all", action="store_true", help="Show all peers including never-connected")
    parser.add_argument("-o", "--offline", action="store_true", help="Show online + offline (skip never-connected)")
    parser.add_argument("-s", "--sort", choices=["handshake", "rx", "tx", "username"], default="username")
    args = parser.parse_args()

    usermap = load_usermap()
    peers = get_peers(args.interface)

    if not usermap:
        print("WARNING: No cache file. Run wg_sync.py first or wait for cron.")
    elif os.path.exists(CACHE_FILE):
        cache_age = time.time() - os.path.getmtime(CACHE_FILE)
        if cache_age > 600:
            print(f"WARNING: Cache is {int(cache_age // 60)}m old.")

    for p in peers:
        info = usermap.get(p["pubkey"], {})
        p["_username"] = info.get("username", "")
        p["_vpn_ip"] = info.get("ip", p["allowed_ips"].replace("/32", ""))

    total_peers = len(peers)
    online_count = sum(1 for p in peers if p["online"])
    never_count = sum(1 for p in peers if p["handshake_age"] is None)
    offline_count = total_peers - online_count - never_count

    if args.all:
        mode = "All Peers"
    elif args.offline:
        mode = "Online + Offline"
        peers = [p for p in peers if p["handshake_age"] is not None]
    else:
        mode = "Online Only"
        peers = [p for p in peers if p["online"]]

    peers.sort(key=SORT_KEYS[args.sort])

    title = f"WireGuard {mode} ({args.interface}) — total: {total_peers}, online: {online_count}, offline: {offline_count}, never: {never_count}  [sorted by {args.sort}]"

    print(f"\n{'='*120}")
    print(f"  {title}")
    print(f"{'='*120}")
    print(f"  {'Status':<8} {'Username':<20} {'VPN IP':<18} {'Endpoint':<24} {'Handshake':<14} {'RX':<12} {'TX':<12}")
    print(f"  {'-'*8} {'-'*20} {'-'*18} {'-'*24} {'-'*14} {'-'*12} {'-'*12}")

    for p in peers:
        username = p["_username"] or (p["pubkey"][:16] + "...")
        vpn_ip = p["_vpn_ip"]
        endpoint = p["endpoint"] if p["endpoint"] != "(none)" else "-"
        handshake = fmt_age(p["handshake_age"])
        status = "\033[32m● ON\033[0m" if p["online"] else "\033[90m○ OFF\033[0m"
        print(f"  {status:<17} {username:<20} {vpn_ip:<18} {endpoint:<24} {handshake:<14} {fmt_bytes(p['rx']):<12} {fmt_bytes(p['tx']):<12}")

    print(f"{'='*120}\n")


if __name__ == "__main__":
    main()

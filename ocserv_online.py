#!/usr/bin/env python3
"""Show ocserv (Cisco AnyConnect / OpenConnect) users via occtl."""

import subprocess
import sys
import json
import time
import argparse
import os

sys.path.insert(0, "/opt")


def fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / 1024 / 1024:.1f} MB"
    else:
        return f"{b / 1024 / 1024 / 1024:.2f} GB"


def fmt_duration(secs: int) -> str:
    if secs < 0:
        return "?"
    if secs < 60:
        return f"{secs}s"
    elif secs < 3600:
        return f"{secs // 60}m"
    elif secs < 86400:
        return f"{secs // 3600}h {(secs % 3600) // 60}m"
    else:
        return f"{secs // 86400}d {(secs % 86400) // 3600}h"


def find_occtl() -> str:
    """Find occtl binary path."""
    for path in ["/usr/bin/occtl", "/usr/local/bin/occtl"]:
        if os.path.exists(path):
            return path
    return "occtl"


def get_sessions() -> list:
    occtl = find_occtl()
    try:
        result = subprocess.run(
            [occtl, "--json", "show", "users"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        print("ERROR: occtl not found. Is ocserv installed?")
        return []

    if result.returncode != 0 or not result.stdout.strip():
        return []

    try:
        users = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"ERROR: Failed to parse occtl JSON output")
        return []

    now = int(time.time())
    sessions = []

    for u in users:
        username = u.get("Username", "")
        if not username or username == "(none)":
            continue

        real_ip = u.get("Remote IP", "")
        vpn_ip = u.get("IPv4", "")
        rx = int(u.get("RX", 0))
        tx = int(u.get("TX", 0))
        connected_at = int(u.get("raw_connected_at", 0))
        uptime_secs = max(0, now - connected_at) if connected_at > 0 else 0

        sessions.append({
            "username": username,
            "real_address": real_ip,
            "vpn_ip": vpn_ip,
            "rx": rx,
            "tx": tx,
            "uptime_secs": uptime_secs,
            "device": u.get("Device", ""),
        })

    return sessions


SORT_KEYS = {
    "username": lambda c: c.get("username", "").lower(),
    "rx": lambda c: c.get("rx", 0),
    "tx": lambda c: c.get("tx", 0),
    "uptime": lambda c: -c.get("uptime_secs", 0),
}


def main():
    parser = argparse.ArgumentParser(description="Show ocserv (AnyConnect) users")
    parser.add_argument("-s", "--sort", choices=["username", "rx", "tx", "uptime"], default="uptime")
    args = parser.parse_args()

    sessions = get_sessions()
    sessions.sort(key=SORT_KEYS[args.sort])

    print(f"\n{'='*120}")
    print(f"  ocserv (AnyConnect/OpenConnect) Online Users — {len(sessions)} connected  [sorted by {args.sort}]")
    print(f"{'='*120}")
    print(f"  {'Username':<20} {'VPN IP':<18} {'Real Address':<24} {'Uptime':<14} {'RX':<12} {'TX':<12} {'Device'}")
    print(f"  {'-'*20} {'-'*18} {'-'*24} {'-'*14} {'-'*12} {'-'*12} {'-'*10}")

    for s in sessions:
        print(
            f"  {s['username']:<20} {s['vpn_ip']:<18} {s['real_address']:<24} "
            f"{fmt_duration(s['uptime_secs']):<14} {fmt_bytes(s['rx']):<12} "
            f"{fmt_bytes(s['tx']):<12} {s['device']}"
        )

    print(f"\n  Total: {len(sessions)} ocserv clients online")
    print(f"{'='*120}\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Show V2Ray (VLESS) online users — combines Xray Stats API + access.log.

Usage:
  python3 v2ray_online.py          # Show online users
  python3 v2ray_online.py -s rx    # Sort by RX bytes
  python3 v2ray_online.py -w       # Watch mode (refresh every 2s)
"""

import subprocess
import sys
import os
import re
import json
import time
import argparse
from datetime import datetime

sys.path.insert(0, "/opt")

USERMAP_CACHE = "/opt/v2ray_usermap.json"
API_ADDR = "127.0.0.1:10085"
ACCESS_LOG = "/var/log/xray/access.log"
ONLINE_THRESHOLD = 120  # seconds — user seen in access.log within this window


def load_usermap() -> dict:
    """Load uuid->username mapping from cache."""
    if not os.path.exists(USERMAP_CACHE):
        return {}
    try:
        with open(USERMAP_CACHE) as f:
            return json.load(f)
    except Exception:
        return {}


def query_stats() -> dict:
    """Query Xray Stats API for per-user traffic.
    Returns {email: {"uplink": bytes, "downlink": bytes}}.
    NOTE: Does NOT use -reset so we get cumulative values for display."""
    try:
        result = subprocess.run(
            ["/usr/local/bin/xray", "api", "statsquery",
             "-s", API_ADDR, "-pattern", "user>>>"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        return {}

    if result.returncode != 0:
        return {}

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return {}

    stats = {}
    for item in data.get("stat", []):
        name = item.get("name", "")
        value = int(item.get("value", 0))
        parts = name.split(">>>")
        if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
            email = parts[1]
            direction = parts[3]
            if email not in stats:
                stats[email] = {"uplink": 0, "downlink": 0}
            stats[email][direction] = value

    return stats


def parse_access_log() -> dict:
    """Parse Xray access.log for recently active users.
    Returns {email: {"src_address": ip, "last_seen": timestamp, "connections": count}}.
    """
    if not os.path.exists(ACCESS_LOG):
        return {}

    try:
        result = subprocess.run(
            ["tail", "-n", "1000", ACCESS_LOG],
            capture_output=True, text=True, timeout=5,
        )
        lines = result.stdout.strip().split("\n")
    except Exception:
        return {}

    users = {}
    now = time.time()

    for line in lines:
        if not line.strip():
            continue

        # Format: 2026/02/25 00:53:46.104215 from 2.144.7.183:59533 accepted tcp:i.instagram.com:443 [vless-in >> direct] email: amir
        m = re.match(
            r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\S*\s+"
            r"from\s+(\S+)\s+accepted\s+\S+\s+\[.*?\]\s+email:\s+(\S+)",
            line,
        )
        if not m:
            continue

        timestamp_str, src_full, email = m.groups()

        try:
            ts = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S").timestamp()
            if now - ts > ONLINE_THRESHOLD:
                continue
        except Exception:
            continue

        src_ip = src_full.rsplit(":", 1)[0] if ":" in src_full else src_full

        if email not in users:
            users[email] = {
                "src_address": src_ip,
                "last_seen": ts,
                "connections": 0,
                "src_ips": set(),
            }

        users[email]["connections"] += 1
        users[email]["src_ips"].add(src_ip)
        # Keep the most recent source IP
        if ts > users[email]["last_seen"]:
            users[email]["last_seen"] = ts
            users[email]["src_address"] = src_ip

    # Convert sets to counts for display
    for u in users.values():
        u["src_ip_count"] = len(u["src_ips"])
        del u["src_ips"]

    return users


def fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / 1024 / 1024:.1f} MB"
    else:
        return f"{b / 1024 / 1024 / 1024:.2f} GB"


def fmt_age(ts) -> str:
    if ts is None:
        return "-"
    age = int(time.time() - ts)
    if age < 0:
        age = 0
    if age < 60:
        return f"{age}s ago"
    elif age < 3600:
        return f"{age // 60}m{age % 60}s ago"
    else:
        return f"{age // 3600}h{(age % 3600) // 60}m ago"


SORT_KEYS = {
    "username": lambda u: u["username"].lower(),
    "rx": lambda u: u["downlink"],
    "tx": lambda u: u["uplink"],
    "last_seen": lambda u: -(u.get("last_seen") or 0),
    "connections": lambda u: -u.get("connections", 0),
}


def display(sort_by="username"):
    """Collect and display online V2RAY users."""
    stats = query_stats()
    active = parse_access_log()

    # Build display rows — only users seen in access.log are "online"
    rows = []
    for email, info in active.items():
        traffic = stats.get(email, {"uplink": 0, "downlink": 0})
        rows.append({
            "username": email,
            "src_address": info["src_address"],
            "src_ip_count": info.get("src_ip_count", 1),
            "last_seen": info["last_seen"],
            "connections": info["connections"],
            "uplink": traffic["uplink"],
            "downlink": traffic["downlink"],
        })

    rows.sort(key=SORT_KEYS.get(sort_by, SORT_KEYS["username"]))

    # Also count users with traffic but not currently active
    traffic_only = set(stats.keys()) - set(active.keys())
    total_with_traffic = len(stats)

    title = f"V2Ray VLESS Online — {len(rows)} online, {total_with_traffic} with traffic  [sorted by {sort_by}]"

    print(f"\n{'=' * 120}")
    print(f"  {title}")
    print(f"{'=' * 120}")
    print(f"  {'Status':<8} {'Username':<20} {'Source IP':<22} {'IPs':<5} {'Last Seen':<14} {'Conns':<7} {'Upload':<12} {'Download':<12}")
    print(f"  {'-' * 8} {'-' * 20} {'-' * 22} {'-' * 5} {'-' * 14} {'-' * 7} {'-' * 12} {'-' * 12}")

    for r in rows:
        status = "\033[32m● ON\033[0m"
        ips = str(r["src_ip_count"]) if r["src_ip_count"] > 1 else ""
        print(
            f"  {status:<17} {r['username']:<20} {r['src_address']:<22} {ips:<5} "
            f"{fmt_age(r['last_seen']):<14} {r['connections']:<7} "
            f"{fmt_bytes(r['uplink']):<12} {fmt_bytes(r['downlink']):<12}"
        )

    if not rows:
        print("  (no online users)")

    # Summary
    total_up = sum(r["uplink"] for r in rows)
    total_down = sum(r["downlink"] for r in rows)
    print(f"\n  Total: upload={fmt_bytes(total_up)}, download={fmt_bytes(total_down)}")

    # Check xray status
    xray_running = subprocess.run(
        ["systemctl", "is-active", "xray"],
        capture_output=True, text=True,
    ).stdout.strip() == "active"

    if not xray_running:
        print("  \033[31mWARNING: Xray service is not running!\033[0m")

    # Cache age
    if os.path.exists(USERMAP_CACHE):
        cache_age = time.time() - os.path.getmtime(USERMAP_CACHE)
        if cache_age > 600:
            print(f"  WARNING: Usermap cache is {int(cache_age // 60)}m old. Is v2ray-sync running?")

    print(f"{'=' * 120}\n")

    return len(rows)


def main():
    parser = argparse.ArgumentParser(description="Show V2Ray (VLESS) online users")
    parser.add_argument("-s", "--sort", choices=["username", "rx", "tx", "last_seen", "connections"],
                        default="username")
    parser.add_argument("-w", "--watch", action="store_true", help="Watch mode — refresh every 2s")
    parser.add_argument("--interval", type=float, default=2.0, help="Watch interval (default: 2s)")
    args = parser.parse_args()

    if args.watch:
        try:
            while True:
                os.system("clear" if os.name != "nt" else "cls")
                display(args.sort)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        display(args.sort)


if __name__ == "__main__":
    main()

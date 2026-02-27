#!/usr/bin/env python3
"""Show L2TP/IPsec online users — zero subprocess, pure procfs + file reads."""

import sys
import re
import os
import time
import argparse
import glob
import json

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


def get_sessions() -> list:
    """Collect all active L2TP/PPP sessions.

    All data from file reads — no subprocess calls:
      - /var/run/pppN.pid             -> PID, uptime (mtime)
      - /proc/<pid>/cmdline           -> tunnel_id, VPN IPs (confirms it's L2TP pppd)
      - /proc/net/dev                 -> rx/tx bytes
      - /var/run/l2tp-sessions.json   -> username + real_ip (ip-up hook)
    """
    now = time.time()

    # 1. Read traffic stats from /proc/net/dev
    traffic = {}
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("ppp"):
                    continue
                parts = line.split(":")
                iface = parts[0].strip()
                nums = parts[1].split()
                if len(nums) >= 9:
                    traffic[iface] = {"rx": int(nums[0]), "tx": int(nums[8])}
    except Exception:
        pass

    # 2. Read session cache (ip-up hook) — has username + real_ip
    session_cache = {}
    cache_file = "/var/run/l2tp-sessions.json"
    if os.path.exists(cache_file):
        try:
            with open(cache_file) as f:
                session_cache = json.load(f)
        except Exception:
            pass

    # 3. Scan /var/run/ppp*.pid -> read /proc/<pid>/cmdline to find L2TP sessions
    sessions = []
    for pidfile in glob.glob("/var/run/ppp*.pid"):
        iface = os.path.basename(pidfile).replace(".pid", "")
        if not iface.startswith("ppp"):
            continue

        try:
            with open(pidfile) as f:
                pid = f.read().strip()
        except Exception:
            continue

        # Read cmdline from procfs (null-separated)
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read().decode("utf-8", errors="replace")
        except Exception:
            continue

        # Only L2TP pppd processes have pppol2tp in their cmdline
        if "pppol2tp" not in raw:
            continue

        args = raw.split("\x00")

        # Extract tunnel_id: arg after "pppol2tp_tunnel_id"
        tunnel_id = ""
        for i, arg in enumerate(args):
            if arg == "pppol2tp_tunnel_id" and i + 1 < len(args):
                tunnel_id = args[i + 1]
                break

        # Extract VPN IP pair from "local:remote" arg
        vpn_ip = ""
        for arg in args:
            m = re.match(r"(\d+\.\d+\.\d+\.\d+):(\d+\.\d+\.\d+\.\d+)$", arg)
            if m:
                vpn_ip = m.group(2)
                break

        if not vpn_ip:
            continue

        # Username + client real IP from session cache (ip-up hook)
        cached = session_cache.get(iface, {})
        username = cached.get("username", "")
        real_address = cached.get("real_ip", "")

        # Traffic
        stats = traffic.get(iface, {"rx": 0, "tx": 0})

        # Uptime from PID file mtime
        uptime_secs = 0
        try:
            uptime_secs = int(now - os.path.getmtime(pidfile))
        except Exception:
            pass

        sessions.append({
            "username": username,
            "real_address": real_address,
            "vpn_ip": vpn_ip,
            "interface": iface,
            "rx": stats["rx"],
            "tx": stats["tx"],
            "uptime_secs": uptime_secs,
            "tunnel_id": tunnel_id,
            "pid": pid,
        })

    return sessions


SORT_KEYS = {
    "username": lambda c: c.get("username", "").lower(),
    "rx": lambda c: c.get("rx", 0),
    "tx": lambda c: c.get("tx", 0),
    "uptime": lambda c: -c.get("uptime_secs", 0),
}


def main():
    parser = argparse.ArgumentParser(description="Show L2TP/IPsec online users")
    parser.add_argument("-s", "--sort", choices=["username", "rx", "tx", "uptime"], default="uptime")
    args = parser.parse_args()

    sessions = get_sessions()
    sessions.sort(key=SORT_KEYS[args.sort])

    print(f"\n{'='*120}")
    print(f"  L2TP/IPsec Online Users — {len(sessions)} connected  [sorted by {args.sort}]")
    print(f"{'='*120}")
    print(f"  {'Username':<20} {'VPN IP':<18} {'Real Address':<24} {'Iface':<8} {'Uptime':<14} {'RX':<12} {'TX':<12}")
    print(f"  {'-'*20} {'-'*18} {'-'*24} {'-'*8} {'-'*14} {'-'*12} {'-'*12}")

    for s in sessions:
        print(
            f"  {s['username'] or '?':<20} {s['vpn_ip']:<18} {s['real_address']:<24} "
            f"{s['interface']:<8} {fmt_duration(s['uptime_secs']):<14} "
            f"{fmt_bytes(s['rx']):<12} {fmt_bytes(s['tx']):<12}"
        )

    print(f"\n  Total: {len(sessions)} L2TP clients online")
    print(f"{'='*120}\n")


if __name__ == "__main__":
    main()

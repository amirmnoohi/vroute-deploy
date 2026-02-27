#!/usr/bin/env python3
"""Show IKEv2/IPsec users via swanctl --list-sas."""

import subprocess
import sys
import re
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


def parse_uptime(text: str) -> int:
    """Parse 'established 18s ago' or 'established 5 minutes ago' etc."""
    m = re.search(r"established\s+(\d+)s\s+ago", text)
    if m:
        return int(m.group(1))
    m = re.search(r"established\s+(\d+)\s+minutes?\s+ago", text)
    if m:
        return int(m.group(1)) * 60
    m = re.search(r"established\s+(\d+)\s+hours?,\s*(\d+)\s+minutes?\s+ago", text)
    if m:
        return int(m.group(1)) * 3600 + int(m.group(2)) * 60
    m = re.search(r"established\s+(\d+)\s+hours?\s+ago", text)
    if m:
        return int(m.group(1)) * 3600
    m = re.search(r"established\s+(\d+)\s+days?,\s*(\d+)\s+hours?\s+ago", text)
    if m:
        return int(m.group(1)) * 86400 + int(m.group(2)) * 3600
    return 0


def find_swanctl() -> str:
    """Find swanctl binary path."""
    for path in ["/usr/sbin/swanctl", "/usr/local/sbin/swanctl"]:
        if os.path.exists(path):
            return path
    return "swanctl"


def get_sessions() -> list:
    swanctl = find_swanctl()
    try:
        result = subprocess.run(
            [swanctl, "--list-sas"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        print("ERROR: swanctl not found. Is strongSwan installed?")
        return []
    # Filter out plugin warning lines
    lines = [l for l in result.stdout.split("\n")
             if not l.strip().startswith("plugin '")]
    raw = "\n".join(lines).strip()
    if not raw:
        return []
    return parse_swanctl(raw)


def parse_swanctl(raw: str) -> list:
    """Parse swanctl --list-sas output into session list.

    Format (note: IKE SA lines start at column 0, child SA lines are indented):
        ikev2: #3, ESTABLISHED, IKEv2, ...
          local  'vs14.vroute.org' @ 87.107.55.62[4500]
          remote '172.16.30.180' @ 37.255.200.123[4500] EAP: 'amir' [10.4.0.1]
          AES_CBC-256/...
          established 18s ago, reauth in 85806s
          ikev2: #3, reqid 1, INSTALLED, TUNNEL-in-UDP, ...
            installed 18s ago, ...
            in  cd5affd5,  62546 bytes, ...
            out 032e955d, 124562 bytes, ...
    """
    sessions = []
    current = None

    for line in raw.split("\n"):
        stripped = line.strip()

        # IKE SA line (NOT indented — starts at column 0)
        # "ikev2: #3, ESTABLISHED, IKEv2, ..."
        if not line.startswith(" ") and re.match(r"\S+:\s+#\d+,\s+ESTABLISHED", stripped):
            if current and current.get("username"):
                sessions.append(current)
            current = {
                "username": "",
                "real_address": "",
                "vpn_ip": "",
                "rx": 0,
                "tx": 0,
                "uptime_secs": 0,
            }
            continue

        if current is None:
            continue

        # Remote line (indented with 2 spaces):
        # "  remote '172.16.30.180' @ 37.255.200.123[4500] EAP: 'amir' [10.4.0.1]"
        m = re.search(r"remote\s+'[^']*'\s+@\s+(\S+)\[\d+\].*?EAP:\s+'([^']+)'\s+\[([^\]]+)\]", stripped)
        if m:
            current["real_address"] = m.group(1)
            current["username"] = m.group(2)
            current["vpn_ip"] = m.group(3)
            continue

        # Established line (indented with 2 spaces, NOT deeply indented child "installed"):
        # "  established 18s ago, reauth in 85806s"
        if "established" in stripped and not stripped.startswith("installed"):
            current["uptime_secs"] = parse_uptime(stripped)
            continue

        # Traffic in (deeply indented child SA):
        # "    in  cd5affd5,  62546 bytes,   221 packets,     2s ago"
        m = re.search(r"^\s+in\s+\w+,\s+(\d+)\s+bytes", line)
        if m:
            current["rx"] = int(m.group(1))
            continue

        # Traffic out:
        # "    out 032e955d, 124562 bytes,   237 packets,     2s ago"
        m = re.search(r"^\s+out\s+\w+,\s+(\d+)\s+bytes", line)
        if m:
            current["tx"] = int(m.group(1))
            continue

    if current and current.get("username"):
        sessions.append(current)

    return sessions


SORT_KEYS = {
    "username": lambda c: c.get("username", "").lower(),
    "rx": lambda c: c.get("rx", 0),
    "tx": lambda c: c.get("tx", 0),
    "uptime": lambda c: -c.get("uptime_secs", 0),
}


def main():
    parser = argparse.ArgumentParser(description="Show IKEv2/IPsec users")
    parser.add_argument("-s", "--sort", choices=["username", "rx", "tx", "uptime"], default="uptime")
    args = parser.parse_args()

    sessions = get_sessions()
    sessions.sort(key=SORT_KEYS[args.sort])

    print(f"\n{'='*120}")
    print(f"  IKEv2/IPsec Online Users — {len(sessions)} connected  [sorted by {args.sort}]")
    print(f"{'='*120}")
    print(f"  {'Username':<20} {'VPN IP':<18} {'Real Address':<24} {'Uptime':<14} {'RX':<12} {'TX':<12}")
    print(f"  {'-'*20} {'-'*18} {'-'*24} {'-'*14} {'-'*12} {'-'*12}")

    for s in sessions:
        print(f"  {s['username']:<20} {s['vpn_ip']:<18} {s['real_address']:<24} {fmt_duration(s['uptime_secs']):<14} {fmt_bytes(s['rx']):<12} {fmt_bytes(s['tx']):<12}")

    print(f"\n  Total: {len(sessions)} IKEv2 clients online")
    print(f"{'='*120}\n")


if __name__ == "__main__":
    main()

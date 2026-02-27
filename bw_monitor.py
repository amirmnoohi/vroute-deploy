#!/usr/bin/env python3
"""Real-time bandwidth monitor per user — WireGuard + OpenVPN + IKEv2 + ocserv.

Usage:
  python3 bw_monitor.py              # Single snapshot (2s sample)
  python3 bw_monitor.py --loop       # Continuous monitoring
  python3 bw_monitor.py --interval 5 # Custom sample interval
  python3 bw_monitor.py --top 10     # Show top 10 users only
"""

import subprocess
import socket
import sys
import os
import time
import json
import re
import argparse
from datetime import datetime

sys.path.insert(0, "/opt")
import vroute_conf

WG_INTERFACE = vroute_conf.wg_interface()
MGMT_SOCKETS = vroute_conf.mgmt_sockets()
CACHE_FILE = "/opt/wg_usermap.json"
WG_ONLINE_THRESHOLD = 120


def fmt_rate(bps: float) -> str:
    """Format bytes/sec to human-readable rate."""
    if bps < 1024:
        return f"{bps:.0f} B/s"
    elif bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    elif bps < 1024 * 1024 * 1024:
        return f"{bps / 1024 / 1024:.1f} MB/s"
    else:
        return f"{bps / 1024 / 1024 / 1024:.2f} GB/s"


def fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / 1024 / 1024:.1f} MB"
    else:
        return f"{b / 1024 / 1024 / 1024:.2f} GB"


###############################################################################
#  WIREGUARD
###############################################################################

def load_wg_usermap() -> dict:
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def collect_wg() -> dict:
    """Returns {username: {"rx": bytes, "tx": bytes, "src": ip, "service": "WG"}}"""
    result = subprocess.run(
        ["wg", "show", WG_INTERFACE, "dump"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        return {}

    usermap = load_wg_usermap()
    now = int(time.time())
    users = {}
    lines = result.stdout.strip().split("\n")
    if len(lines) < 2:
        return {}

    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 7:
            continue

        pubkey = parts[0]
        endpoint = parts[2]
        handshake = int(parts[4])
        rx_bytes, tx_bytes = int(parts[5]), int(parts[6])

        if handshake == 0 or (now - handshake) > WG_ONLINE_THRESHOLD:
            continue

        info = usermap.get(pubkey, {})
        username = info.get("username", "")
        if not username:
            continue

        src = endpoint.rsplit(":", 1)[0] if endpoint != "(none)" else ""
        users[f"WG|{username}"] = {
            "username": username,
            "rx": rx_bytes,
            "tx": tx_bytes,
            "src": src,
            "service": "WG",
        }

    return users


###############################################################################
#  OPENVPN
###############################################################################

def query_ovpn_mgmt(sock_path: str) -> str:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sock_path)

    data = b""
    while b"\r\n" not in data:
        data += s.recv(4096)

    s.sendall(b"status 2\r\n")
    data = b""
    while b"\r\nEND\r\n" not in data:
        chunk = s.recv(8192)
        if not chunk:
            break
        data += chunk

    try:
        s.sendall(b"quit\r\n")
    except Exception:
        pass
    s.close()
    return data.decode("utf-8", errors="replace")


def collect_ovpn() -> dict:
    """Returns {key: {"username", "rx", "tx", "src", "service"}}"""
    users = {}

    for proto, sock_path in MGMT_SOCKETS.items():
        if not os.path.exists(sock_path):
            continue
        try:
            raw = query_ovpn_mgmt(sock_path)
            header_map = {}

            for line in raw.split("\n"):
                line = line.strip("\r\n")
                parts = line.split(",")
                tag = parts[0] if parts else ""

                if tag == "HEADER" and len(parts) >= 3 and parts[1] == "CLIENT_LIST":
                    header_map = {name: idx for idx, name in enumerate(parts[2:])}

                elif tag == "CLIENT_LIST" and header_map:
                    fields = parts[1:]
                    def get(name, f=fields):
                        idx = header_map.get(name)
                        if idx is not None and idx < len(f):
                            return f[idx]
                        return ""

                    username = get("Common Name")
                    if username == "UNDEF":
                        continue

                    real_addr = get("Real Address")
                    src = real_addr.rsplit(":", 1)[0] if real_addr else ""

                    key = f"OVPN-{proto}|{username}|{src}"
                    users[key] = {
                        "username": username,
                        "rx": int(get("Bytes Received") or 0),
                        "tx": int(get("Bytes Sent") or 0),
                        "src": src,
                        "service": f"OVPN-{proto}",
                    }

                elif tag == "END":
                    break

        except Exception:
            pass

    return users


###############################################################################
#  IKEV2
###############################################################################

def find_swanctl() -> str:
    """Find swanctl binary path."""
    for path in ["/usr/sbin/swanctl", "/usr/local/sbin/swanctl", "swanctl"]:
        if os.path.exists(path) or path == "swanctl":
            return path
    return ""


def collect_ikev2() -> dict:
    """Returns {key: {"username", "rx", "tx", "src", "service"}}"""
    swanctl = find_swanctl()
    if not swanctl:
        return {}

    try:
        result = subprocess.run(
            [swanctl, "--list-sas"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return {}

    lines = [l for l in result.stdout.split("\n")
             if not l.strip().startswith("plugin '")]
    raw = "\n".join(lines).strip()
    if not raw:
        return {}

    users = {}
    current = None

    for line in raw.split("\n"):
        stripped = line.strip()

        if not line.startswith(" ") and re.match(r"\S+:\s+#\d+,\s+ESTABLISHED", stripped):
            if current and current.get("username"):
                key = f"IKEV2|{current['username']}|{current['src']}"
                users[key] = current
            current = {
                "username": "",
                "src": "",
                "rx": 0,
                "tx": 0,
                "service": "IKEV2",
            }
            continue

        if current is None:
            continue

        m = re.search(r"remote\s+'[^']*'\s+@\s+(\S+)\[\d+\].*?EAP:\s+'([^']+)'", stripped)
        if m:
            current["src"] = m.group(1)
            current["username"] = m.group(2)
            continue

        m = re.search(r"^\s+in\s+\w+,\s+(\d+)\s+bytes", line)
        if m:
            current["rx"] = int(m.group(1))
            continue

        m = re.search(r"^\s+out\s+\w+,\s+(\d+)\s+bytes", line)
        if m:
            current["tx"] = int(m.group(1))
            continue

    if current and current.get("username"):
        key = f"IKEV2|{current['username']}|{current['src']}"
        users[key] = current

    return users


###############################################################################
#  OCSERV (occtl --json show users)
###############################################################################

def collect_ocserv() -> dict:
    """Returns {key: {"username", "rx", "tx", "src", "service"}}"""
    try:
        result = subprocess.run(
            ["occtl", "--json", "show", "users"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return {}

    if result.returncode != 0 or not result.stdout.strip():
        return {}

    try:
        users = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}

    result_dict = {}
    for u in users:
        username = u.get("Username", "")
        if not username or username == "(none)":
            continue

        src = u.get("Remote IP", "")
        rx_bytes = int(u.get("RX", 0))
        tx_bytes = int(u.get("TX", 0))

        key = f"OCSERV|{username}|{src}"
        result_dict[key] = {
            "username": username,
            "rx": rx_bytes,
            "tx": tx_bytes,
            "src": src,
            "service": "OCSERV",
        }

    return result_dict


###############################################################################
#  MAIN
###############################################################################

def collect_all() -> dict:
    """Collect all users from all VPN services."""
    all_users = {}
    all_users.update(collect_wg())
    all_users.update(collect_ovpn())
    all_users.update(collect_ikev2())
    all_users.update(collect_ocserv())
    return all_users


def calculate_rates(snap1: dict, snap2: dict, interval: float) -> list:
    """Calculate per-user bandwidth rates between two snapshots."""
    rates = []

    for key, s2 in snap2.items():
        s1 = snap1.get(key)
        if s1 is None:
            # New user appeared between snapshots
            dl_rate = 0
            ul_rate = 0
        else:
            dl_rate = max(0, (s2["rx"] - s1["rx"])) / interval
            ul_rate = max(0, (s2["tx"] - s1["tx"])) / interval

        rates.append({
            "username": s2["username"],
            "src": s2["src"],
            "service": s2["service"],
            "dl_rate": dl_rate,
            "ul_rate": ul_rate,
            "total_rate": dl_rate + ul_rate,
            "total_rx": s2["rx"],
            "total_tx": s2["tx"],
        })

    return rates


def print_table(rates: list, top_n: int = 0):
    """Print bandwidth table sorted by total rate descending."""
    rates.sort(key=lambda r: r["total_rate"], reverse=True)

    if top_n > 0:
        rates = rates[:top_n]

    ts = datetime.now().strftime("%H:%M:%S")
    active = len([r for r in rates if r["total_rate"] > 0])

    print(f"\033[2J\033[H", end="")  # Clear screen
    print(f"{'='*120}")
    print(f"  Bandwidth Monitor — {ts} — {len(rates)} users ({active} active)")
    print(f"{'='*120}")
    print(f"  {'Username':<18} {'Source IP':<22} {'Service':<12} {'Download':<14} {'Upload':<14} {'Total':<14} {'Total RX':<12} {'Total TX':<12}")
    print(f"  {'-'*18} {'-'*22} {'-'*12} {'-'*14} {'-'*14} {'-'*14} {'-'*12} {'-'*12}")

    for r in rates:
        dl = fmt_rate(r["dl_rate"])
        ul = fmt_rate(r["ul_rate"])
        total = fmt_rate(r["total_rate"])

        # Color: green if active, dim if idle
        if r["total_rate"] > 0:
            color = "\033[32m"
        else:
            color = "\033[90m"
        reset = "\033[0m"

        print(f"  {color}{r['username']:<18} {r['src']:<22} {r['service']:<12} {dl:<14} {ul:<14} {total:<14} {fmt_bytes(r['total_rx']):<12} {fmt_bytes(r['total_tx']):<12}{reset}")

    print(f"{'='*120}")

    # Summary
    total_dl = sum(r["dl_rate"] for r in rates)
    total_ul = sum(r["ul_rate"] for r in rates)
    print(f"  Total:  DL {fmt_rate(total_dl)}  |  UL {fmt_rate(total_ul)}  |  Combined {fmt_rate(total_dl + total_ul)}")
    print(f"{'='*120}")


def main():
    parser = argparse.ArgumentParser(description="Real-time VPN bandwidth monitor")
    parser.add_argument("--interval", "-i", type=float, default=2.0, help="Sample interval in seconds (default: 2)")
    parser.add_argument("--loop", "-l", action="store_true", help="Continuous monitoring")
    parser.add_argument("--top", "-t", type=int, default=0, help="Show top N users only")
    args = parser.parse_args()

    if args.loop:
        print("Collecting first sample...")
        snap1 = collect_all()

        while True:
            try:
                time.sleep(args.interval)
                snap2 = collect_all()
                rates = calculate_rates(snap1, snap2, args.interval)
                print_table(rates, args.top)
                snap1 = snap2
            except KeyboardInterrupt:
                print("\nStopped.")
                break
    else:
        # Single run: two samples
        print(f"Sampling for {args.interval}s...")
        snap1 = collect_all()
        time.sleep(args.interval)
        snap2 = collect_all()
        rates = calculate_rates(snap1, snap2, args.interval)
        print_table(rates, args.top)


if __name__ == "__main__":
    main()

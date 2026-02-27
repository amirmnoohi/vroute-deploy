#!/usr/bin/env python3
"""Show OpenVPN users (TCP + UDP) via management interface."""

import socket
import sys
import os
import time
import argparse
from datetime import datetime

sys.path.insert(0, "/opt")
import vroute_conf

MGMT_SOCKETS = vroute_conf.mgmt_sockets()


def fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / 1024 / 1024:.1f} MB"
    else:
        return f"{b / 1024 / 1024 / 1024:.2f} GB"


def fmt_duration(epoch: int) -> str:
    secs = int(datetime.now().timestamp()) - epoch
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


def query_mgmt(sock_path: str) -> str:
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


def parse_status2(raw: str) -> list:
    clients = []
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

            connected_epoch = int(get("Connected Since (time_t)") or 0)
            clients.append({
                "username": username,
                "real_address": get("Real Address"),
                "vpn_ip": get("Virtual Address"),
                "rx": int(get("Bytes Received") or 0),
                "tx": int(get("Bytes Sent") or 0),
                "connected_epoch": connected_epoch,
                "connected_since": datetime.fromtimestamp(connected_epoch).strftime("%Y-%m-%d %H:%M:%S") if connected_epoch else "?",
            })

        elif tag == "END":
            break

    return clients


SORT_KEYS = {
    "username": lambda c: c.get("username", ""),
    "rx": lambda c: c.get("rx", 0),
    "tx": lambda c: c.get("tx", 0),
    "connected": lambda c: c.get("connected_epoch", 0),
}


def print_section(proto, clients, sort_by):
    print(f"\n  [{proto}] — {len(clients)} connected")
    if not clients:
        print("  No connected clients.")
        return

    clients.sort(key=SORT_KEYS[sort_by])
    print(f"  {'Username':<20} {'VPN IP':<18} {'Real Address':<24} {'Connected':<20} {'Duration':<12} {'RX':<12} {'TX':<12}")
    print(f"  {'-'*20} {'-'*18} {'-'*24} {'-'*20} {'-'*12} {'-'*12} {'-'*12}")

    for c in clients:
        print(f"  {c['username']:<20} {c.get('vpn_ip', '-'):<18} {c['real_address']:<24} {c['connected_since']:<20} {fmt_duration(c['connected_epoch']):<12} {fmt_bytes(c['rx']):<12} {fmt_bytes(c['tx']):<12}")


def main():
    parser = argparse.ArgumentParser(description="Show OpenVPN users")
    parser.add_argument("-s", "--sort", choices=["username", "rx", "tx", "connected"], default="username")
    parser.add_argument("-p", "--proto", choices=["tcp", "udp", "all"], default="all")
    args = parser.parse_args()

    sockets = MGMT_SOCKETS
    if args.proto == "tcp":
        sockets = {"TCP": MGMT_SOCKETS["TCP"]}
    elif args.proto == "udp":
        sockets = {"UDP": MGMT_SOCKETS["UDP"]}

    total = 0
    print(f"\n{'='*120}")
    print(f"  OpenVPN Online Users  [sorted by {args.sort}]")
    print(f"{'='*120}")

    for proto, sock_path in sockets.items():
        if not os.path.exists(sock_path):
            print(f"\n  [{proto}] ERROR: Socket not found: {sock_path}")
            continue
        try:
            raw = query_mgmt(sock_path)
            clients = parse_status2(raw)
            print_section(proto, clients, args.sort)
            total += len(clients)
        except Exception as e:
            print(f"\n  [{proto}] ERROR: {e}")

    print(f"\n  Total: {total} OpenVPN clients online")
    print(f"{'='*120}\n")


if __name__ == "__main__":
    main()

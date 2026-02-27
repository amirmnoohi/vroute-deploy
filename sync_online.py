#!/usr/bin/env python3
"""
VRoute Linux VPN Monitor — Syncs WireGuard + OpenVPN + IKEv2 + ocserv + L2TP + V2RAY sessions to Redis.

Usage:
  python3 sync_online.py --dry-run          # Show what would be pushed
  python3 sync_online.py                     # Run once
  python3 sync_online.py --loop              # Run continuously
  python3 sync_online.py --loop --poll=2     # Custom poll interval

Redis key structure:
  vroute:online:{server_name}:{session_id}  -> hash with all session fields (no TTL)
  vroute:online_srv:{server_name}           -> set of active session_ids (no TTL)
  vroute:online_usr:{username}              -> set of "server:session_id" (no TTL)
  No TTL on any key — Laravel checks updated_at field for freshness.
"""

import subprocess
import socket
import sys
import os
import re
import time
import json
import hashlib
import argparse
from datetime import datetime

try:
    import redis
except ImportError:
    print("Run: pip3 install redis")
    sys.exit(1)

sys.path.insert(0, "/opt")
import vroute_conf

SERVER_NAME = vroute_conf.server_name()
SERVER_IDS = vroute_conf.server_ids()
WG_INTERFACE = vroute_conf.wg_interface()
MGMT_SOCKETS = vroute_conf.mgmt_sockets()
WG_ONLINE_THRESHOLD = 120
CACHE_FILE = "/opt/wg_usermap.json"

# ── Redis config (hardcoded) ──
REDIS_HOST = "api.vroute.org"
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = "Amn.1104.@#$"

# Key prefix
KEY_PREFIX = "vroute:online"


###############################################################################
#  PERSISTENT REDIS CONNECTION
###############################################################################

class RedisPool:
    def __init__(self):
        self._conn = None

    def get(self) -> redis.Redis:
        if self._conn is None:
            self._conn = redis.Redis(
                host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB,
                password=REDIS_PASSWORD, decode_responses=True,
                socket_connect_timeout=10, socket_timeout=10,
                retry_on_timeout=True,
            )
        # ping to check connection is alive
        try:
            self._conn.ping()
        except (redis.ConnectionError, redis.TimeoutError):
            self._conn = redis.Redis(
                host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB,
                password=REDIS_PASSWORD, decode_responses=True,
                socket_connect_timeout=10, socket_timeout=10,
                retry_on_timeout=True,
            )
        return self._conn

    def close(self):
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

rpool = RedisPool()


###############################################################################
#  HELPERS
###############################################################################

def fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KiB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / 1024 / 1024:.1f} MiB"
    else:
        return f"{b / 1024 / 1024 / 1024:.2f} GiB"


def generate_session_id(service: str, username: str, extra: str = "") -> str:
    raw = f"{service}|{username}|{extra}"
    return hashlib.sha256(raw.encode()).hexdigest()


###############################################################################
#  CHANGE DETECTION — skip full Redis sync when nothing changed
###############################################################################

_last_sessions_hash = None
_last_full_sync = 0.0


def sessions_changed(sessions: list) -> bool:
    """Return True if sessions differ from last cycle or TTL refresh is needed.

    Full sync is forced every 30s even if session list is unchanged,
    to refresh 60s TTLs and update traffic/uptime counters.
    """
    global _last_sessions_hash, _last_full_sync
    now = time.time()

    # Always do a full sync at least every 30s (TTL is 60s — leaves 30s margin)
    if now - _last_full_sync >= 30:
        _last_full_sync = now
        sig = "|".join(sorted(s["session_id"] for s in sessions))
        _last_sessions_hash = hashlib.md5(sig.encode()).hexdigest()
        return True

    # Between forced syncs, only sync if session list actually changed
    sig = "|".join(sorted(s["session_id"] for s in sessions))
    h = hashlib.md5(sig.encode()).hexdigest()
    if h == _last_sessions_hash:
        return False
    _last_sessions_hash = h
    _last_full_sync = now
    return True


###############################################################################
#  WIREGUARD COLLECTOR
###############################################################################

def load_wg_usermap() -> dict:
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


_last_wg_sessions = []


def collect_wireguard_sessions() -> list:
    global _last_wg_sessions
    try:
        result = subprocess.run(
            ["wg", "show", WG_INTERFACE, "dump"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as e:
        print(f"  ERROR: wg show exception: {e}")
        return _last_wg_sessions  # return cached on failure

    if result.returncode != 0:
        print(f"  ERROR: wg show failed: {result.stderr.strip()}")
        return _last_wg_sessions  # return cached on failure

    usermap = load_wg_usermap()
    now = int(time.time())
    sessions = []
    lines = result.stdout.strip().split("\n")
    if len(lines) < 2:
        _last_wg_sessions = []
        return []

    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 7:
            continue

        pubkey, endpoint = parts[0], parts[2]
        allowed_ips = parts[3]
        handshake = int(parts[4])
        rx_bytes, tx_bytes = int(parts[5]), int(parts[6])

        if handshake == 0 or (now - handshake) > WG_ONLINE_THRESHOLD:
            continue

        info = usermap.get(pubkey, {})
        username = info.get("username", "")
        vpn_ip = info.get("ip", allowed_ips.replace("/32", ""))
        if not username:
            continue

        src_addr = endpoint.rsplit(":", 1)[0] if endpoint != "(none)" else ""
        age = now - handshake

        sessions.append({
            "username": username,
            "service": "WIREGUARD",
            "server_id": SERVER_IDS["WIREGUARD"],
            "server_name": SERVER_NAME,
            "session_id": generate_session_id("WG", username, src_addr),
            "src_address": src_addr,
            "dst_address": vpn_ip,
            "interface": WG_INTERFACE,
            "tx_bytes": tx_bytes,
            "rx_bytes": rx_bytes,
            "tx_bytes_hu": fmt_bytes(tx_bytes),
            "rx_bytes_hu": fmt_bytes(rx_bytes),
            "uptime": f"{age}s ago",
        })

    _last_wg_sessions = sessions
    return sessions


###############################################################################
#  OPENVPN COLLECTOR
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


def parse_ovpn_status2(raw: str) -> list:
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

            clients.append({
                "username": username,
                "real_address": get("Real Address"),
                "vpn_ip": get("Virtual Address"),
                "rx": int(get("Bytes Received") or 0),
                "tx": int(get("Bytes Sent") or 0),
                "connected_epoch": int(get("Connected Since (time_t)") or 0),
            })

        elif tag == "END":
            break

    return clients


def collect_openvpn_sessions() -> list:
    sessions = []

    for proto, sock_path in MGMT_SOCKETS.items():
        if not os.path.exists(sock_path):
            continue
        try:
            raw = query_ovpn_mgmt(sock_path)
            clients = parse_ovpn_status2(raw)

            for c in clients:
                username = c["username"]
                src_addr = c["real_address"].rsplit(":", 1)[0] if c["real_address"] else ""
                vpn_ip = c["vpn_ip"]
                connected_epoch = c["connected_epoch"]

                if connected_epoch > 0:
                    age = int(time.time()) - connected_epoch
                    if age < 60:
                        uptime = f"{age}s"
                    elif age < 3600:
                        uptime = f"{age // 60}m{age % 60}s"
                    elif age < 86400:
                        uptime = f"{age // 3600}h{(age % 3600) // 60}m"
                    else:
                        uptime = f"{age // 86400}d{(age % 86400) // 3600}h"
                else:
                    uptime = ""

                sessions.append({
                    "username": username,
                    "service": "OVPN",
                    "server_id": SERVER_IDS["OVPN"],
                    "server_name": SERVER_NAME,
                    "session_id": generate_session_id("OVPN", username, f"{src_addr}|{connected_epoch}"),
                    "src_address": src_addr,
                    "dst_address": vpn_ip,
                    "interface": f"tun-{proto.lower()}",
                    "tx_bytes": c["tx"],
                    "rx_bytes": c["rx"],
                    "tx_bytes_hu": fmt_bytes(c["tx"]),
                    "rx_bytes_hu": fmt_bytes(c["rx"]),
                    "uptime": uptime,
                })

        except Exception as e:
            print(f"  ERROR [{proto}]: {e}")

    return sessions


###############################################################################
#  IKEV2 COLLECTOR (swanctl --list-sas)
###############################################################################

def find_swanctl() -> str:
    """Find swanctl binary path."""
    for path in ["/usr/sbin/swanctl", "/usr/local/sbin/swanctl"]:
        if os.path.exists(path):
            return path
    return "swanctl"


def parse_ikev2_uptime(text: str) -> int:
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


def fmt_uptime(secs: int) -> str:
    if secs < 60:
        return f"{secs}s"
    elif secs < 3600:
        return f"{secs // 60}m{secs % 60}s"
    elif secs < 86400:
        return f"{secs // 3600}h{(secs % 3600) // 60}m"
    else:
        return f"{secs // 86400}d{(secs % 86400) // 3600}h"


def collect_ikev2_sessions() -> list:
    """Collect IKEv2 sessions via swanctl --list-sas."""
    if "IKEV2" not in SERVER_IDS:
        return []

    swanctl = find_swanctl()
    try:
        result = subprocess.run(
            [swanctl, "--list-sas"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return []

    # Filter out plugin warning lines
    lines = [l for l in result.stdout.split("\n")
             if not l.strip().startswith("plugin '")]
    raw = "\n".join(lines).strip()
    if not raw:
        return []

    # Parse swanctl output
    sessions = []
    current = None

    for line in raw.split("\n"):
        stripped = line.strip()

        # IKE SA line (starts at column 0): "ikev2: #3, ESTABLISHED, IKEv2, ..."
        if not line.startswith(" ") and re.match(r"\S+:\s+#\d+,\s+ESTABLISHED", stripped):
            if current and current.get("username"):
                sessions.append(current)
            current = {
                "username": "", "real_address": "", "vpn_ip": "",
                "rx": 0, "tx": 0, "uptime_secs": 0,
            }
            continue

        if current is None:
            continue

        # Remote line: "  remote '...' @ 1.2.3.4[4500] EAP: 'amir' [10.4.0.1]"
        m = re.search(
            r"remote\s+'[^']*'\s+@\s+(\S+)\[\d+\].*?EAP:\s+'([^']+)'\s+\[([^\]]+)\]",
            stripped,
        )
        if m:
            current["real_address"] = m.group(1)
            current["username"] = m.group(2)
            current["vpn_ip"] = m.group(3)
            continue

        # Established line (not the child SA "installed" line)
        if "established" in stripped and not stripped.startswith("installed"):
            current["uptime_secs"] = parse_ikev2_uptime(stripped)
            continue

        # Traffic in: "    in  cd5affd5,  62546 bytes, ..."
        m = re.search(r"^\s+in\s+\w+,\s+(\d+)\s+bytes", line)
        if m:
            current["rx"] = int(m.group(1))
            continue

        # Traffic out: "    out 032e955d, 124562 bytes, ..."
        m = re.search(r"^\s+out\s+\w+,\s+(\d+)\s+bytes", line)
        if m:
            current["tx"] = int(m.group(1))
            continue

    if current and current.get("username"):
        sessions.append(current)

    # Convert to sync format
    result_sessions = []
    for s in sessions:
        username = s["username"]
        src_addr = s["real_address"]
        vpn_ip = s["vpn_ip"]
        uptime = fmt_uptime(s["uptime_secs"])

        result_sessions.append({
            "username": username,
            "service": "IKEV2",
            "server_id": SERVER_IDS["IKEV2"],
            "server_name": SERVER_NAME,
            "session_id": generate_session_id("IKEV2", username, src_addr),
            "src_address": src_addr,
            "dst_address": vpn_ip,
            "interface": "ipsec",
            "tx_bytes": s["tx"],
            "rx_bytes": s["rx"],
            "tx_bytes_hu": fmt_bytes(s["tx"]),
            "rx_bytes_hu": fmt_bytes(s["rx"]),
            "uptime": uptime,
        })

    return result_sessions


###############################################################################
#  OCSERV COLLECTOR (occtl --json show users)
###############################################################################

def find_occtl() -> str:
    """Find occtl binary path."""
    for path in ["/usr/bin/occtl", "/usr/local/bin/occtl"]:
        if os.path.exists(path):
            return path
    return "occtl"


def collect_ocserv_sessions() -> list:
    """Collect ocserv (AnyConnect/OpenConnect) sessions via occtl."""
    if "OCSERV" not in SERVER_IDS:
        return []

    occtl = find_occtl()
    try:
        result = subprocess.run(
            [occtl, "--json", "show", "users"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return []

    if result.returncode != 0 or not result.stdout.strip():
        return []

    try:
        users = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"  ERROR: Failed to parse occtl JSON")
        return []

    now = int(time.time())
    sessions = []

    for u in users:
        username = u.get("Username", "")
        if not username or username == "(none)":
            continue

        src_addr = u.get("Remote IP", "")
        vpn_ip = u.get("IPv4", "")
        rx = int(u.get("RX", 0))
        tx = int(u.get("TX", 0))
        connected_at = int(u.get("raw_connected_at", 0))
        interface = u.get("Device", "vpns")

        if connected_at > 0:
            age = now - connected_at
            uptime = fmt_uptime(age)
        else:
            uptime = ""

        sessions.append({
            "username": username,
            "service": "OCSERV",
            "server_id": SERVER_IDS["OCSERV"],
            "server_name": SERVER_NAME,
            "session_id": generate_session_id("OCSERV", username, f"{src_addr}|{connected_at}"),
            "src_address": src_addr,
            "dst_address": vpn_ip,
            "interface": interface,
            "tx_bytes": tx,
            "rx_bytes": rx,
            "tx_bytes_hu": fmt_bytes(tx),
            "rx_bytes_hu": fmt_bytes(rx),
            "uptime": uptime,
        })

    return sessions


###############################################################################
#  L2TP COLLECTOR — zero subprocess, pure procfs + file reads
###############################################################################

def collect_l2tp_sessions() -> list:
    """Collect L2TP/IPsec sessions — all from file reads, no subprocesses.

    Data sources:
      - /var/run/pppN.pid             -> PID, uptime (mtime)
      - /proc/<pid>/cmdline           -> tunnel_id, VPN IPs (confirms L2TP pppd)
      - /proc/net/dev                 -> rx/tx bytes
      - /var/run/l2tp-sessions.json   -> username + real_ip (ip-up hook)
    """
    if "L2TP" not in SERVER_IDS:
        return []

    import glob as _glob
    now = time.time()

    # 1. Traffic from /proc/net/dev
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

    # 2. Session cache (ip-up hook) — has username + real_ip
    session_cache = {}
    cache_file = "/var/run/l2tp-sessions.json"
    if os.path.exists(cache_file):
        try:
            with open(cache_file) as f:
                session_cache = json.load(f)
        except Exception:
            pass

    # 3. Scan ppp pid files -> read /proc/<pid>/cmdline
    sessions = []
    for pidfile in _glob.glob("/var/run/ppp*.pid"):
        iface = os.path.basename(pidfile).replace(".pid", "")
        if not iface.startswith("ppp"):
            continue

        try:
            with open(pidfile) as f:
                pid = f.read().strip()
        except Exception:
            continue

        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read().decode("utf-8", errors="replace")
        except Exception:
            continue

        if "pppol2tp" not in raw:
            continue

        args = raw.split("\x00")

        # tunnel_id
        tunnel_id = ""
        for i, arg in enumerate(args):
            if arg == "pppol2tp_tunnel_id" and i + 1 < len(args):
                tunnel_id = args[i + 1]
                break

        # VPN IP from "local:remote" arg
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

        stats = traffic.get(iface, {"rx": 0, "tx": 0})

        uptime_secs = 0
        try:
            uptime_secs = int(now - os.path.getmtime(pidfile))
        except Exception:
            pass

        uptime = fmt_uptime(uptime_secs) if uptime_secs > 0 else ""

        sessions.append({
            "username": username,
            "service": "L2TP",
            "server_id": SERVER_IDS["L2TP"],
            "server_name": SERVER_NAME,
            "session_id": generate_session_id("L2TP", username, real_address),
            "src_address": real_address,
            "dst_address": vpn_ip,
            "interface": iface,
            "tx_bytes": stats["tx"],
            "rx_bytes": stats["rx"],
            "tx_bytes_hu": fmt_bytes(stats["tx"]),
            "rx_bytes_hu": fmt_bytes(stats["rx"]),
            "uptime": uptime,
        })

    return sessions


###############################################################################
#  V2RAY (VLESS) COLLECTOR — Xray Stats API + access.log
###############################################################################

V2RAY_ACCESS_LOG = "/var/log/xray/access.log"
V2RAY_ONLINE_THRESHOLD = 120  # seconds — user offline if no traffic change for this long
V2RAY_API_ADDR = "127.0.0.1:10085"
V2RAY_USERMAP = "/opt/v2ray_usermap.json"

# Track previous stats + timing for traffic-delta online detection
_v2ray_prev_stats = {}    # {email: {"tx": int, "rx": int}}
_v2ray_last_active = {}   # {email: float} — last time traffic changed
_v2ray_first_seen = {}    # {email: float} — when user first appeared (for uptime)
_V2RAY_FIRST_SEEN_FILE = "/var/run/v2ray_first_seen.json"


def _load_v2ray_first_seen():
    """Load persisted first_seen timestamps (survives service restarts)."""
    global _v2ray_first_seen
    if os.path.exists(_V2RAY_FIRST_SEEN_FILE):
        try:
            with open(_V2RAY_FIRST_SEEN_FILE) as f:
                _v2ray_first_seen = json.load(f)
        except Exception:
            pass


def _save_v2ray_first_seen():
    """Persist first_seen timestamps to disk."""
    try:
        with open(_V2RAY_FIRST_SEEN_FILE, "w") as f:
            json.dump(_v2ray_first_seen, f)
    except Exception:
        pass


def _load_v2ray_usermap() -> dict:
    """Load username<->uuid mapping from v2ray_sync.py cache."""
    if not os.path.exists(V2RAY_USERMAP):
        return {}
    try:
        with open(V2RAY_USERMAP) as f:
            return json.load(f)
    except Exception:
        return {}


def _parse_v2ray_access_log() -> dict:
    """Parse Xray access.log for source IPs (most recent per user).

    Returns {email: {"ips": set, "last_seen": float}}.
    No time cutoff — we just want the latest source IP for each user.
    """
    result = {}
    if not os.path.exists(V2RAY_ACCESS_LOG):
        return result

    try:
        # Read last 500KB of access log (enough for recent IPs)
        fsize = os.path.getsize(V2RAY_ACCESS_LOG)
        with open(V2RAY_ACCESS_LOG) as f:
            if fsize > 500_000:
                f.seek(fsize - 500_000)
                f.readline()  # skip partial line
            for line in f:
                m = re.match(
                    r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\S*\s+"
                    r"from\s+(\S+)\s+accepted\s+\S+\s+\[.*?\]\s+email:\s+(\S+)",
                    line,
                )
                if not m:
                    continue

                ts_str, src_addr, email = m.group(1), m.group(2), m.group(3)

                try:
                    from datetime import datetime as _dt
                    ts = _dt.strptime(ts_str, "%Y/%m/%d %H:%M:%S").timestamp()
                except Exception:
                    continue

                # Strip port from src_addr (ip:port)
                ip = src_addr.rsplit(":", 1)[0] if ":" in src_addr else src_addr

                if email not in result:
                    result[email] = {"ips": set(), "last_seen": ts}
                result[email]["ips"].add(ip)
                if ts > result[email]["last_seen"]:
                    result[email]["last_seen"] = ts
    except Exception:
        pass

    return result


def _query_v2ray_stats() -> dict:
    """Query Xray Stats API for per-user traffic. Returns {email: {tx, rx}}."""
    result = {}
    try:
        out = subprocess.run(
            ["/usr/local/bin/xray", "api", "statsquery",
             "-s", V2RAY_API_ADDR, "-pattern", "user"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode != 0:
            return result

        # Output is JSON: {"stat": [{"name": "user>>>email>>>traffic>>>uplink", "value": 12345}, ...]}
        data = json.loads(out.stdout)
        for entry in data.get("stat", []):
            name = entry.get("name", "")
            val = int(entry.get("value", 0))
            parts = name.split(">>>")
            if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
                email = parts[1]
                direction = parts[3]  # uplink or downlink
                if email not in result:
                    result[email] = {"tx": 0, "rx": 0}
                if direction == "uplink":
                    result[email]["tx"] = val
                elif direction == "downlink":
                    result[email]["rx"] = val
    except Exception:
        pass

    return result


def collect_v2ray_sessions() -> list:
    """Collect V2RAY (VLESS) sessions from Xray Stats API + access.log.

    Online detection: user is online if their traffic counters changed
    within the last V2RAY_ONLINE_THRESHOLD seconds. This works even when
    the user is idle (background app traffic, keepalives, etc.).
    Access.log is used only for source IP lookup.
    """
    global _v2ray_prev_stats, _v2ray_last_active, _v2ray_first_seen

    if "V2RAY" not in SERVER_IDS:
        return []

    if not os.path.exists("/usr/local/bin/xray"):
        return []

    # Load persisted first_seen on first call
    if not _v2ray_first_seen:
        _load_v2ray_first_seen()

    now = time.time()

    # 1. Get current traffic stats from Xray API
    stats = _query_v2ray_stats()
    if not stats:
        return []

    # 2. Update last_active based on traffic delta + track first_seen
    fs_changed = False
    for email, cur in stats.items():
        prev = _v2ray_prev_stats.get(email, {"tx": 0, "rx": 0})
        if cur["tx"] != prev["tx"] or cur["rx"] != prev["rx"]:
            _v2ray_last_active[email] = now
        if email not in _v2ray_last_active:
            _v2ray_last_active[email] = now
        if email not in _v2ray_first_seen:
            _v2ray_first_seen[email] = now
            fs_changed = True
    _v2ray_prev_stats = stats

    # 3. Get source IPs from access.log (no time cutoff)
    log_info = _parse_v2ray_access_log()

    # 4. Build sessions for users active within threshold
    sessions = []
    cutoff = now - V2RAY_ONLINE_THRESHOLD

    for email, traffic in stats.items():
        last_active = _v2ray_last_active.get(email, 0)
        if last_active < cutoff:
            # User timed out — reset first_seen so uptime starts fresh next time
            if email in _v2ray_first_seen:
                del _v2ray_first_seen[email]
                fs_changed = True
            continue

        # Source IP from access.log
        info = log_info.get(email, {})
        ips = sorted(info.get("ips", set()))
        src_addr = ips[0] if ips else ""

        first_seen = _v2ray_first_seen.get(email, now)
        uptime_secs = int(now - first_seen)
        uptime = fmt_uptime(uptime_secs) if uptime_secs > 0 else "0s"

        sessions.append({
            "username": email,
            "service": "V2RAY",
            "server_id": SERVER_IDS["V2RAY"],
            "server_name": SERVER_NAME,
            "session_id": generate_session_id("V2RAY", email, src_addr),
            "src_address": src_addr,
            "dst_address": "proxy",
            "interface": "xray",
            "tx_bytes": traffic["tx"],
            "rx_bytes": traffic["rx"],
            "tx_bytes_hu": fmt_bytes(traffic["tx"]),
            "rx_bytes_hu": fmt_bytes(traffic["rx"]),
            "uptime": uptime,
        })

    # 5. Clean up stale entries from tracking dicts
    for email in list(_v2ray_last_active):
        if email not in stats:
            del _v2ray_last_active[email]
            _v2ray_prev_stats.pop(email, None)
            if email in _v2ray_first_seen:
                del _v2ray_first_seen[email]
                fs_changed = True

    # 6. Persist first_seen if changed
    if fs_changed:
        _save_v2ray_first_seen()

    return sessions


###############################################################################
#  REDIS SYNC
#
#  Key design (3 layers for fast queries):
#
#  1. Session data (hash per session):
#     vroute:online:{server_name}:{session_id} -> hash with all fields
#
#  2. Server index (which sessions belong to this server):
#     vroute:online_srv:{server_name} -> set of session_ids
#
#  3. User index (which sessions belong to this user):
#     vroute:online_usr:{username} -> set of "{server_name}:{session_id}"
#
#  PHP/Laravel query patterns enabled:
#    - All sessions for user X:     SMEMBERS vroute:online_usr:{username}
#    - Is user on server_id Y:      loop user's sessions, check server_id field
#    - Count per server:            SCARD vroute:online_srv:{server_name}
#    - All online usernames:        KEYS vroute:online_usr:* (or SCAN)
#    - Total online:                sum SCARD across all vroute:online_srv:*
#    - Session details:             HGETALL vroute:online:{server_name}:{sid}
#
#  Each cycle:
#    1. Pipeline HSET all current sessions (NO TTL)
#    2. Build new server index (temp set), SDIFF to find stale
#    3. For stale sessions: DEL hash + SREM from user index
#    4. For new sessions: SADD to user index
#    5. RENAME temp -> server index
#
#  No TTLs anywhere. All keys are explicitly created/deleted.
#  Each session hash has an "updated_at" field — Laravel can check
#  freshness and ignore data older than 60s if a server dies.
###############################################################################

SRV_PREFIX = "vroute:online_srv"
USR_PREFIX = "vroute:online_usr"


def sync_to_redis(sessions: list) -> dict:
    r = rpool.get()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    srv_key = f"{SRV_PREFIX}:{SERVER_NAME}"
    tmp_key = f"{SRV_PREFIX}:{SERVER_NAME}:_tmp"

    pipe = r.pipeline(transaction=False)

    # 1. Write all current sessions (NO TTL — explicitly managed)
    current_ids = set()
    current_users = {}  # session_id -> username
    for s in sessions:
        sid = s["session_id"]
        current_ids.add(sid)
        current_users[sid] = s["username"]
        session_key = f"{KEY_PREFIX}:{SERVER_NAME}:{sid}"
        pipe.hset(session_key, mapping={
            "server_id": str(s["server_id"]),
            "session_id": sid,
            "username": s["username"],
            "service": s["service"],
            "server_name": s["server_name"],
            "src_address": s["src_address"],
            "dst_address": s["dst_address"],
            "interface": s["interface"],
            "tx_bytes": str(s["tx_bytes"]),
            "rx_bytes": str(s["rx_bytes"]),
            "tx_bytes_hu": s["tx_bytes_hu"],
            "rx_bytes_hu": s["rx_bytes_hu"],
            "uptime": s["uptime"],
            "updated_at": now,
        })

    # 2. Build new server index
    pipe.delete(tmp_key)
    if current_ids:
        pipe.sadd(tmp_key, *current_ids)

    pipe.execute()

    # 3. Find stale session_ids and get their usernames before deleting
    old_ids = r.smembers(srv_key)
    stale_ids = old_ids - current_ids
    new_ids = current_ids - old_ids

    deleted = 0
    if stale_ids:
        # Read usernames of stale sessions so we can clean user index
        read_pipe = r.pipeline(transaction=False)
        for sid in stale_ids:
            read_pipe.hget(f"{KEY_PREFIX}:{SERVER_NAME}:{sid}", "username")
        stale_usernames = read_pipe.execute()

        # Delete stale session hashes + remove from user indexes
        del_pipe = r.pipeline(transaction=False)
        for sid, uname in zip(stale_ids, stale_usernames):
            del_pipe.delete(f"{KEY_PREFIX}:{SERVER_NAME}:{sid}")
            if uname:
                del_pipe.srem(f"{USR_PREFIX}:{uname}", f"{SERVER_NAME}:{sid}")
        del_pipe.execute()
        deleted = len(stale_ids)

    # 4. Add new sessions to user indexes
    if new_ids:
        usr_pipe = r.pipeline(transaction=False)
        for sid in new_ids:
            uname = current_users.get(sid, "")
            if uname:
                usr_pipe.sadd(f"{USR_PREFIX}:{uname}", f"{SERVER_NAME}:{sid}")
        usr_pipe.execute()

    # 5. Replace old server index with new
    if current_ids:
        r.rename(tmp_key, srv_key)
    else:
        r.delete(tmp_key, srv_key)

    # 6. Clean up empty user index keys
    #    (only check users who had stale sessions removed)
    if stale_ids:
        clean_pipe = r.pipeline(transaction=False)
        checked_users = set()
        for sid, uname in zip(stale_ids, stale_usernames):
            if uname and uname not in checked_users:
                checked_users.add(uname)
                clean_pipe.scard(f"{USR_PREFIX}:{uname}")
        counts = clean_pipe.execute()
        if checked_users:
            del_pipe = r.pipeline(transaction=False)
            for uname, cnt in zip(checked_users, counts):
                if cnt == 0:
                    del_pipe.delete(f"{USR_PREFIX}:{uname}")
            del_pipe.execute()

    return {"upserted": len(sessions), "deleted": deleted}


###############################################################################
#  DRY RUN
###############################################################################

def dry_run(sessions: list):
    wg = [s for s in sessions if s["service"] == "WIREGUARD"]
    ovpn = [s for s in sessions if s["service"] == "OVPN"]
    ikev2 = [s for s in sessions if s["service"] == "IKEV2"]
    ocserv = [s for s in sessions if s["service"] == "OCSERV"]
    l2tp = [s for s in sessions if s["service"] == "L2TP"]
    v2ray = [s for s in sessions if s["service"] == "V2RAY"]

    print(f"\n{'='*100}")
    print(f"  DRY RUN -- {SERVER_NAME} -- {len(sessions)} sessions to sync")
    print(f"{'='*100}")

    if wg:
        print(f"\n  [WIREGUARD] server_id={SERVER_IDS['WIREGUARD']} -- {len(wg)} online")
        print(f"  {'Username':<20} {'Src IP':<20} {'VPN IP':<18} {'RX':<12} {'TX':<12} {'Session ID (first 16)'}")
        print(f"  {'-'*20} {'-'*20} {'-'*18} {'-'*12} {'-'*12} {'-'*16}")
        for s in wg:
            print(f"  {s['username']:<20} {s['src_address']:<20} {s['dst_address']:<18} {s['rx_bytes_hu']:<12} {s['tx_bytes_hu']:<12} {s['session_id'][:16]}")

    if ovpn:
        print(f"\n  [OPENVPN] server_id={SERVER_IDS['OVPN']} -- {len(ovpn)} online")
        print(f"  {'Username':<20} {'Src IP':<20} {'VPN IP':<18} {'RX':<12} {'TX':<12} {'Uptime':<10} {'Session ID (first 16)'}")
        print(f"  {'-'*20} {'-'*20} {'-'*18} {'-'*12} {'-'*12} {'-'*10} {'-'*16}")
        for s in ovpn:
            print(f"  {s['username']:<20} {s['src_address']:<20} {s['dst_address']:<18} {s['rx_bytes_hu']:<12} {s['tx_bytes_hu']:<12} {s['uptime']:<10} {s['session_id'][:16]}")

    if ikev2:
        print(f"\n  [IKEV2] server_id={SERVER_IDS['IKEV2']} -- {len(ikev2)} online")
        print(f"  {'Username':<20} {'Src IP':<20} {'VPN IP':<18} {'RX':<12} {'TX':<12} {'Uptime':<10} {'Session ID (first 16)'}")
        print(f"  {'-'*20} {'-'*20} {'-'*18} {'-'*12} {'-'*12} {'-'*10} {'-'*16}")
        for s in ikev2:
            print(f"  {s['username']:<20} {s['src_address']:<20} {s['dst_address']:<18} {s['rx_bytes_hu']:<12} {s['tx_bytes_hu']:<12} {s['uptime']:<10} {s['session_id'][:16]}")

    if ocserv:
        print(f"\n  [OCSERV] server_id={SERVER_IDS['OCSERV']} -- {len(ocserv)} online")
        print(f"  {'Username':<20} {'Src IP':<20} {'VPN IP':<18} {'RX':<12} {'TX':<12} {'Uptime':<10} {'Session ID (first 16)'}")
        print(f"  {'-'*20} {'-'*20} {'-'*18} {'-'*12} {'-'*12} {'-'*10} {'-'*16}")
        for s in ocserv:
            print(f"  {s['username']:<20} {s['src_address']:<20} {s['dst_address']:<18} {s['rx_bytes_hu']:<12} {s['tx_bytes_hu']:<12} {s['uptime']:<10} {s['session_id'][:16]}")

    if l2tp:
        print(f"\n  [L2TP] server_id={SERVER_IDS['L2TP']} -- {len(l2tp)} online")
        print(f"  {'Username':<20} {'Src IP':<20} {'VPN IP':<18} {'RX':<12} {'TX':<12} {'Uptime':<10} {'Session ID (first 16)'}")
        print(f"  {'-'*20} {'-'*20} {'-'*18} {'-'*12} {'-'*12} {'-'*10} {'-'*16}")
        for s in l2tp:
            print(f"  {s['username']:<20} {s['src_address']:<20} {s['dst_address']:<18} {s['rx_bytes_hu']:<12} {s['tx_bytes_hu']:<12} {s['uptime']:<10} {s['session_id'][:16]}")

    if v2ray:
        print(f"\n  [V2RAY] server_id={SERVER_IDS['V2RAY']} -- {len(v2ray)} online")
        print(f"  {'Username':<20} {'Src IP':<20} {'VPN IP':<18} {'RX':<12} {'TX':<12} {'Uptime':<10} {'Session ID (first 16)'}")
        print(f"  {'-'*20} {'-'*20} {'-'*18} {'-'*12} {'-'*12} {'-'*10} {'-'*16}")
        for s in v2ray:
            print(f"  {s['username']:<20} {s['src_address']:<20} {s['dst_address']:<18} {s['rx_bytes_hu']:<12} {s['tx_bytes_hu']:<12} {s['uptime']:<10} {s['session_id'][:16]}")

    if not sessions:
        print("\n  No active sessions found.")

    try:
        r = rpool.get()
        srv_key = f"{SRV_PREFIX}:{SERVER_NAME}"
        current_count = r.scard(srv_key)
        stale_count = max(0, current_count - len(sessions))

        print(f"\n  Redis currently has {current_count} sessions for {SERVER_NAME}")
        print(f"  Would UPSERT: {len(sessions)} sessions")
        print(f"  Would DELETE: ~{stale_count} stale sessions")
    except Exception as e:
        print(f"\n  Could not check Redis: {e}")

    print(f"{'='*100}\n")


###############################################################################
#  MAIN
###############################################################################

def run_once(dry: bool = False) -> dict:
    t0 = time.time()
    wg_sessions = collect_wireguard_sessions()
    ovpn_sessions = collect_openvpn_sessions()
    ikev2_sessions = collect_ikev2_sessions()
    ocserv_sessions = collect_ocserv_sessions()
    l2tp_sessions = collect_l2tp_sessions()
    v2ray_sessions = collect_v2ray_sessions()
    all_sessions = wg_sessions + ovpn_sessions + ikev2_sessions + ocserv_sessions + l2tp_sessions + v2ray_sessions
    collect_ms = int((time.time() - t0) * 1000)

    if dry:
        dry_run(all_sessions)
        return {"wg": len(wg_sessions), "ovpn": len(ovpn_sessions), "ikev2": len(ikev2_sessions), "ocserv": len(ocserv_sessions), "l2tp": len(l2tp_sessions), "v2ray": len(v2ray_sessions)}

    t1 = time.time()

    # Skip Redis write if nothing changed (same session_ids as last cycle)
    if not sessions_changed(all_sessions):
        sync_ms = 0
        stats = {"upserted": 0, "deleted": 0}
    else:
        stats = sync_to_redis(all_sessions)
        sync_ms = int((time.time() - t1) * 1000)

    return {
        "wg": len(wg_sessions), "ovpn": len(ovpn_sessions), "ikev2": len(ikev2_sessions),
        "ocserv": len(ocserv_sessions), "l2tp": len(l2tp_sessions), "v2ray": len(v2ray_sessions),
        "upserted": stats["upserted"], "deleted": stats["deleted"],
        "collect_ms": collect_ms, "sync_ms": sync_ms,
        "total_ms": int((time.time() - t0) * 1000),
    }


def main():
    parser = argparse.ArgumentParser(description=f"VRoute VPN Monitor -- {SERVER_NAME}")
    parser.add_argument("--dry-run", "-n", action="store_true")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--poll", type=float, default=1.0)
    args = parser.parse_args()

    if args.dry_run:
        print(f"DRY RUN mode -- {SERVER_NAME}")
        run_once(dry=True)
        return

    if not args.loop:
        stats = run_once()
        print(f"[{SERVER_NAME}] WG={stats['wg']} OVPN={stats['ovpn']} IKEv2={stats['ikev2']} OCSERV={stats['ocserv']} L2TP={stats['l2tp']} V2RAY={stats['v2ray']} | upserted={stats['upserted']} deleted={stats['deleted']} | {stats['total_ms']}ms (collect:{stats['collect_ms']}ms redis:{stats['sync_ms']}ms)")
        return

    print(f"Starting VPN monitor for {SERVER_NAME} (poll={args.poll}s) -> Redis {REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}")
    id_parts = [f"WG server_id={SERVER_IDS['WIREGUARD']}", f"OVPN server_id={SERVER_IDS['OVPN']}"]
    if "IKEV2" in SERVER_IDS:
        id_parts.append(f"IKEV2 server_id={SERVER_IDS['IKEV2']}")
    if "OCSERV" in SERVER_IDS:
        id_parts.append(f"OCSERV server_id={SERVER_IDS['OCSERV']}")
    if "L2TP" in SERVER_IDS:
        id_parts.append(f"L2TP server_id={SERVER_IDS['L2TP']}")
    if "V2RAY" in SERVER_IDS:
        id_parts.append(f"V2RAY server_id={SERVER_IDS['V2RAY']}")
    print(f"   {' | '.join(id_parts)}")
    print()

    cycle = 0
    while True:
        cycle += 1
        try:
            stats = run_once()
            ts = datetime.now().strftime("%H:%M:%S")
            print(
                f"[{ts}] #{cycle} | WG={stats['wg']} OVPN={stats['ovpn']} IKEv2={stats['ikev2']} OCSERV={stats['ocserv']} L2TP={stats['l2tp']} V2RAY={stats['v2ray']} "
                f"| upserted={stats['upserted']} deleted={stats['deleted']} "
                f"| {stats['total_ms']}ms (collect:{stats['collect_ms']}ms redis:{stats['sync_ms']}ms)"
            )
        except KeyboardInterrupt:
            print(f"\nStopped after {cycle} cycles.")
            break
        except Exception as e:
            print(f"[ERROR] Cycle #{cycle}: {e}")
            rpool.close()  # force reconnect on next cycle

        try:
            time.sleep(args.poll)
        except KeyboardInterrupt:
            print(f"\nStopped after {cycle} cycles.")
            break


if __name__ == "__main__":
    main()

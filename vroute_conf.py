"""VRoute shared config — all scripts import this to read /opt/vroute.conf"""

import json
import os
import sys

CONFIG_PATH = "/opt/vroute.conf"
_config = None


def load() -> dict:
    global _config
    if _config is not None:
        return _config
    if not os.path.exists(CONFIG_PATH):
        print(f"ERROR: {CONFIG_PATH} not found. Run deploy.sh first.")
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        _config = json.load(f)
    return _config


def server_name() -> str:
    return load()["server_name"]

def server_ids() -> dict:
    return load()["server_ids"]

def db() -> dict:
    return load()["db"]

def wg_interface() -> str:
    return load().get("wg_interface", "wg0")

def mgmt_sockets() -> dict:
    return load().get("mgmt_sockets", {
        "TCP": "/run/openvpn-server/tcp-mgmt.sock",
        "UDP": "/run/openvpn-server/udp-mgmt.sock",
    })

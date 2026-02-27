#!/bin/bash
###############################################################################
#  VRoute V2Ray (VLESS) Deploy
#
#  Usage:  bash v2ray.sh
#
#  Installs and configures:
#    - Xray-core with VLESS inbound (TCP + HTTP obfuscation)
#    - Port 11042/TCP (no TLS, no certificate needed)
#    - Stats API on 127.0.0.1:10085 (per-user traffic tracking)
#    - User sync from MySQL (v2ray_sync.py)
#    - Session monitoring (v2ray_online.py)
#    - Outbound via vrtun0 tunnel (fwmark 0x2) if available
#    - Updates vroute.conf with V2RAY server_id
#
#  Requires: deploy.sh must be run first (/opt/vroute.conf must exist)
#  Safe to re-run: overwrites configs, restarts services.
###############################################################################

set -euo pipefail

# ── Colors ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
fatal() { echo -e "${RED}[FATAL]${NC} $1"; exit 1; }
step()  { echo -e "\n${CYAN}━━━ STEP $1: $2 ━━━${NC}"; }

[[ $EUID -ne 0 ]] && fatal "Run as root"

# ── Prereqs ──
[[ ! -f /opt/vroute.conf ]] && fatal "/opt/vroute.conf not found. Run deploy.sh first."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
[[ -z "$IFACE" ]] && fatal "Cannot detect default network interface"
SERVER_IP=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
[[ -z "$SERVER_IP" ]] && fatal "Cannot detect server IP on $IFACE"

SERVER_NAME=$(python3 -c "import json; print(json.load(open('/opt/vroute.conf'))['server_name'])")
info "Server: $SERVER_NAME | Interface: $IFACE | IP: $SERVER_IP"

# Check tunnel availability
HAS_TUNNEL=0
if ip link show vrtun0 &>/dev/null; then
    HAS_TUNNEL=1
    info "Tunnel detected: vrtun0 — outbound will use fwmark 0x2"
else
    warn "No vrtun0 tunnel — outbound will go direct via $IFACE"
fi

ERRORS=0

###############################################################################
#  STEP 1: V2RAY server_id
###############################################################################
step 1 "V2RAY configuration"

V2RAY_ID=$(python3 -c "
import json
c = json.load(open('/opt/vroute.conf'))
print(c.get('server_ids', {}).get('V2RAY', ''))
" 2>/dev/null || true)

if [[ -n "$V2RAY_ID" ]]; then
    info "V2RAY already configured: id=$V2RAY_ID"
    read -rp "Re-configure? [y/N]: " RECONF
    if [[ "$RECONF" != "y" && "$RECONF" != "Y" ]]; then
        info "Keeping existing config."
    else
        V2RAY_ID=""
    fi
fi

if [[ -z "$V2RAY_ID" ]]; then
    SERVER_NUM=$(echo "$SERVER_NAME" | grep -oP '\d+$' || true)
    if [[ -n "$SERVER_NUM" ]]; then
        DEFAULT_V2RAY=$((800 + SERVER_NUM - 2))
        echo "  Auto-generated V2RAY server_id: $DEFAULT_V2RAY"
        read -rp "Use this ID? [Y/n]: " USE_DEFAULT
        if [[ "$USE_DEFAULT" == "n" || "$USE_DEFAULT" == "N" ]]; then
            read -rp "  V2RAY server_id: " V2RAY_ID
        else
            V2RAY_ID=$DEFAULT_V2RAY
        fi
    else
        read -rp "  V2RAY server_id: " V2RAY_ID
    fi

    [[ -z "$V2RAY_ID" ]] && fatal "Server ID cannot be empty"

    # Update vroute.conf — add V2RAY server_id
    python3 << PYEOF
import json

with open("/opt/vroute.conf") as f:
    c = json.load(f)

c["server_ids"]["V2RAY"] = $V2RAY_ID

with open("/opt/vroute.conf", "w") as f:
    json.dump(c, f, indent=4)

print("Updated /opt/vroute.conf")
PYEOF

    info "Config updated: V2RAY id=$V2RAY_ID"
fi

###############################################################################
#  STEP 2: Install Xray-core
###############################################################################
step 2 "Install Xray-core"

if [[ -f /usr/local/bin/xray ]]; then
    XRAY_VER=$(/usr/local/bin/xray version 2>/dev/null | head -1 || echo "unknown")
    info "Xray already installed: $XRAY_VER"
    read -rp "Reinstall/upgrade? [y/N]: " REINSTALL
    if [[ "$REINSTALL" == "y" || "$REINSTALL" == "Y" ]]; then
        info "Reinstalling Xray-core..."
        bash -c "$(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install || {
            error "Xray install failed"; ((ERRORS++))
        }
    fi
else
    info "Installing Xray-core..."
    bash -c "$(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install || {
        error "Xray install failed"; ((ERRORS++))
    }
fi

# Verify
if [[ -f /usr/local/bin/xray ]]; then
    XRAY_VER=$(/usr/local/bin/xray version 2>/dev/null | head -1 || echo "unknown")
    info "Xray installed: $XRAY_VER"
else
    fatal "Xray binary not found at /usr/local/bin/xray after install"
fi

# Ensure python3-mysql.connector is installed (needed by v2ray_sync.py)
if ! python3 -c "import mysql.connector" &>/dev/null; then
    info "Installing python3-mysql.connector..."
    apt update -qq
    apt install -y python3-mysql.connector || {
        error "python3-mysql.connector install failed"; ((ERRORS++))
    }
fi

###############################################################################
#  STEP 3: Create directories + log rotation
###############################################################################
step 3 "Directories and log rotation"

mkdir -p /var/log/xray
mkdir -p /usr/local/etc/xray
chmod 755 /var/log/xray

# Logrotate — use copytruncate because Xray doesn't reopen logs on SIGHUP
cat > /etc/logrotate.d/xray << 'LOGEOF'
/var/log/xray/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
}
LOGEOF

info "Log directory created, logrotate configured (copytruncate, 7 days)."

###############################################################################
#  STEP 4: Deploy Python scripts
###############################################################################
step 4 "Deploy monitoring + sync scripts"

for script in v2ray_sync.py v2ray_online.py; do
    if [[ -f "$SCRIPT_DIR/$script" ]]; then
        cp "$SCRIPT_DIR/$script" "/opt/$script"
        chmod +x "/opt/$script"
        info "Installed /opt/$script"
    else
        error "$script not found in $SCRIPT_DIR — skipping!"
        ((ERRORS++))
    fi
done

# Also ensure vroute_conf.py is present
if [[ -f "$SCRIPT_DIR/vroute_conf.py" && ! -f /opt/vroute_conf.py ]]; then
    cp "$SCRIPT_DIR/vroute_conf.py" /opt/vroute_conf.py
    info "Installed /opt/vroute_conf.py"
fi

###############################################################################
#  STEP 5: Initial user sync + Xray config generation
###############################################################################
step 5 "User sync from MySQL → Xray config"

# Stop xray if running (we'll restart after config is written)
systemctl stop xray &>/dev/null 2>&1 || true

info "Running v2ray_sync.py to generate Xray config..."
if python3 /opt/v2ray_sync.py; then
    info "Xray config written to /usr/local/etc/xray/config.json"
    # Show user count
    USER_COUNT=$(python3 -c "
import json
try:
    c = json.load(open('/usr/local/etc/xray/config.json'))
    clients = c.get('inbounds', [{}])[0].get('settings', {}).get('clients', [])
    print(len(clients))
except:
    print('?')
" 2>/dev/null || echo "?")
    info "Loaded $USER_COUNT users from database."
else
    error "v2ray_sync.py failed — check DB connection"
    ((ERRORS++))
fi

# Show tunnel status in config
if [[ $HAS_TUNNEL -eq 1 ]]; then
    MARK_CHECK=$(python3 -c "
import json
try:
    c = json.load(open('/usr/local/etc/xray/config.json'))
    for ob in c.get('outbounds', []):
        if ob.get('tag') == 'direct':
            mark = ob.get('streamSettings', {}).get('sockopt', {}).get('mark', 0)
            print(mark)
            break
except:
    print(0)
" 2>/dev/null || echo "0")
    if [[ "$MARK_CHECK" == "2" ]]; then
        info "Outbound configured: fwmark 0x2 → vrtun0 tunnel"
    else
        warn "Tunnel detected but fwmark not set in config!"
    fi
else
    info "Outbound configured: direct (no tunnel)"
fi

###############################################################################
#  STEP 6: v2ray-sync systemd service
###############################################################################
step 6 "v2ray-sync service (MySQL → Xray user sync daemon)"

cat > /etc/systemd/system/v2ray-sync.service << 'SVCEOF'
[Unit]
Description=VRoute V2Ray User Sync
After=network.target xray.service
Wants=xray.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 -u /opt/v2ray_sync.py --loop --poll=5
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=v2ray-sync

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable v2ray-sync
info "v2ray-sync.service installed + enabled."

###############################################################################
#  STEP 7: Networking (firewall)
###############################################################################
step 7 "Networking (firewall)"

# Ensure IP forwarding (should already be on from deploy.sh)
if [[ $(cat /proc/sys/net/ipv4/ip_forward) -ne 1 ]]; then
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-vpn.conf
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    info "IP forwarding enabled."
else
    info "IP forwarding already enabled."
fi

# Open VLESS port
if ! iptables -C INPUT -p tcp --dport 11042 -j ACCEPT &>/dev/null; then
    iptables -A INPUT -p tcp --dport 11042 -j ACCEPT
    info "Opened TCP port 11042 (VLESS)"
else
    info "TCP port 11042 already open."
fi

netfilter-persistent save &>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
info "Firewall rules saved."

###############################################################################
#  STEP 8: Start services
###############################################################################
step 8 "Start Xray + v2ray-sync"

# Start Xray
systemctl enable xray &>/dev/null
systemctl restart xray || { error "Xray failed to start"; ((ERRORS++)); }

# Verify Xray is running
sleep 1
if systemctl is-active --quiet xray; then
    info "Xray is running."
    # Check if Stats API is responding
    if /usr/local/bin/xray api statsquery -s 127.0.0.1:10085 -pattern "" &>/dev/null; then
        info "Stats API responding on 127.0.0.1:10085"
    else
        warn "Stats API not responding yet (may need a few seconds)."
    fi
else
    error "Xray is NOT running! Check: journalctl -u xray -n 20"
    ((ERRORS++))
fi

# Start v2ray-sync
systemctl restart v2ray-sync || { error "v2ray-sync failed to start"; ((ERRORS++)); }
if systemctl is-active --quiet v2ray-sync; then
    info "v2ray-sync is running."
else
    error "v2ray-sync is NOT running! Check: journalctl -u v2ray-sync -n 20"
    ((ERRORS++))
fi

###############################################################################
#  DONE
###############################################################################
echo ""
echo "============================================================"
if [[ $ERRORS -eq 0 ]]; then
    info "V2Ray (VLESS) deploy complete! (0 errors)"
else
    warn "V2Ray (VLESS) deploy complete with $ERRORS error(s)"
fi
echo "============================================================"
echo ""
echo "  Server:        $SERVER_NAME"
echo "  Server IP:     $SERVER_IP"
echo "  Protocol:      VLESS (Xray-core)"
echo "  Port:          11042/TCP"
echo "  Transport:     TCP + HTTP obfuscation"
echo "  Certificate:   None needed (no TLS)"
echo "  Tunnel:        $([ $HAS_TUNNEL -eq 1 ] && echo 'fwmark 0x2 → vrtun0' || echo 'direct')"
echo "  Stats API:     127.0.0.1:10085"
echo "  Interface:     $IFACE"
echo ""
echo "  Monitoring:"
echo "    python3 /opt/v2ray_online.py         # show online users"
echo "    python3 /opt/v2ray_online.py -w      # watch mode"
echo "    journalctl -u v2ray-sync -f          # sync log"
echo "    journalctl -u xray -f                # xray log"
echo ""

# Generate sample VLESS URL
SAMPLE_UUID=$(python3 -c "
import json
try:
    c = json.load(open('/usr/local/etc/xray/config.json'))
    clients = c.get('inbounds', [{}])[0].get('settings', {}).get('clients', [])
    if clients:
        print(clients[0]['id'])
    else:
        print('no-users')
except:
    print('error')
" 2>/dev/null || echo "error")

SAMPLE_USER=$(python3 -c "
import json
try:
    c = json.load(open('/usr/local/etc/xray/config.json'))
    clients = c.get('inbounds', [{}])[0].get('settings', {}).get('clients', [])
    if clients:
        print(clients[0]['email'])
    else:
        print('unknown')
except:
    print('unknown')
" 2>/dev/null || echo "unknown")

if [[ "$SAMPLE_UUID" != "no-users" && "$SAMPLE_UUID" != "error" ]]; then
    echo "  Sample VLESS URL (user: $SAMPLE_USER):"
    echo "    vless://${SAMPLE_UUID}@${SERVER_IP}:11042?encryption=none&security=none&type=tcp&headerType=http&path=/&host=bale.ai,web.igap.net,igap.net#${SERVER_NAME}"
    echo ""
fi

echo "  Services:"
echo "    systemctl status xray            # Xray VLESS server"
echo "    systemctl status v2ray-sync      # User sync daemon"
echo ""
echo "============================================================"

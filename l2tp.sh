#!/bin/bash
###############################################################################
#  L2TP/IPsec Deploy
#
#  Usage:  bash l2tp.sh
#
#  Installs and configures:
#    - IPsec (strongSwan, PSK authentication)
#    - L2TP (xl2tpd)
#    - PPP with RADIUS authentication
#    - NAT + forwarding rules
#
#  Compatible with native L2TP/IPsec clients:
#    Windows, macOS, iOS, Android (built-in VPN)
#
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

IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
[[ -z "$IFACE" ]] && fatal "Cannot detect default network interface"
SERVER_IP=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
[[ -z "$SERVER_IP" ]] && fatal "Cannot detect server IP on $IFACE"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

info "Interface: $IFACE | Server IP: $SERVER_IP"

ERRORS=0

# ── Defaults (all hardcoded) ──
IPSEC_PSK="123456789"
RADIUS_IP="185.141.168.2"
RADIUS_AUTH_PORT=1812
RADIUS_ACCT_PORT=1813
RADIUS_SECRET="11041104"
L2TP_LOCAL_IP="10.6.0.1"
L2TP_POOL_START="10.6.0.10"
L2TP_POOL_END="10.6.0.254"
L2TP_SUBNET="10.6.0.0/24"
DNS1="8.8.8.8"
DNS2="8.8.4.4"

info "PSK: ******** | RADIUS: $RADIUS_IP:$RADIUS_AUTH_PORT | Subnet: $L2TP_SUBNET"

###############################################################################
#  STEP 1: Install packages
###############################################################################
step 1 "Packages"

NEED_INSTALL=0
for pkg in strongswan xl2tpd ppp; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        NEED_INSTALL=1
        break
    fi
done

if [[ $NEED_INSTALL -eq 1 ]]; then
    info "Installing strongSwan + xl2tpd + PPP..."
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    apt update -qq
    apt install -y strongswan strongswan-pki libcharon-extra-plugins \
        xl2tpd ppp libradcli4 libradcli-dev || {
        error "Package install failed"; ((ERRORS++))
    }
else
    info "All packages already installed."
fi

###############################################################################
#  STEP 2: IPsec (strongSwan) configuration
###############################################################################
step 2 "IPsec (strongSwan)"

# ── strongswan.conf (explicit — default package config can break IKEv2/L2TP on some devices) ──
cat > /etc/strongswan.conf << 'SWANEOF'
charon {
    load_modular = yes
    plugins {
        include strongswan.d/charon/*.conf
    }
}
include strongswan.d/*.conf
SWANEOF
info "strongswan.conf written."

# ── Suppress charon debug logging ──
mkdir -p /etc/strongswan.d
cat > /etc/strongswan.d/charon-logging.conf << 'LOGEOF'
charon {
    syslog {
        daemon {
            default = -1
        }
        auth {
            default = -1
        }
    }
}
LOGEOF
info "Charon logging suppressed."

# ── ipsec.conf ──
# Only add L2TP conn block — don't touch config setup or conn %default
# (IKEv2 may depend on them). All L2TP-specific settings go inside conn l2tp-psk.

# If ipsec.conf doesn't exist, create minimal one
if [[ ! -f /etc/ipsec.conf ]]; then
    cat > /etc/ipsec.conf << 'IPSECEOF'
config setup
    uniqueids=never
IPSECEOF
fi

# Remove old l2tp-psk block if present
if grep -q "conn l2tp-psk" /etc/ipsec.conf; then
    python3 -c "
import re
with open('/etc/ipsec.conf') as f:
    content = f.read()
content = re.sub(r'\nconn l2tp-psk\n(?:[ \t]+[^\n]*\n)*', '\n', content)
with open('/etc/ipsec.conf', 'w') as f:
    f.write(content.rstrip() + '\n')
"
    info "Removed old l2tp-psk block from ipsec.conf."
fi

# Append L2TP conn block (all settings self-contained, no global %default needed)
cat >> /etc/ipsec.conf << 'IPSECEOF'

conn l2tp-psk
    keyexchange=ikev1
    authby=secret
    auto=add
    type=transport
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    rekey=no
    dpddelay=30
    dpdtimeout=300
    dpdaction=clear
    ike=aes256-sha256-modp2048,aes256-sha1-modp2048,aes256-sha256-modp1024,aes256-sha1-modp1024,aes128-sha256-modp2048,aes128-sha256-modp1024,aes128-sha1-modp2048,aes128-sha1-modp1024,3des-sha1-modp1024,3des-sha1-modp768!
    esp=aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1,3des-sha1!
IPSECEOF
info "L2TP conn block appended to ipsec.conf (IKEv2 config preserved)."

# ── ipsec.secrets ──
# Preserve existing entries (e.g. IKEv2 RSA key), append PSK if not present
if [[ -f /etc/ipsec.secrets ]]; then
    # Remove any old L2TP PSK line to avoid duplicates
    sed -i '/# L2TP PSK/d; /^%any %any : PSK/d; /^: PSK/d' /etc/ipsec.secrets
else
    touch /etc/ipsec.secrets
fi
echo "# L2TP PSK" >> /etc/ipsec.secrets
echo ": PSK \"$IPSEC_PSK\"" >> /etc/ipsec.secrets
chmod 600 /etc/ipsec.secrets
info "ipsec.secrets updated (PSK appended, existing entries preserved)."

# Reload IPsec config into running charon (don't restart — IKEv2 sessions stay alive)
ipsec reload 2>/dev/null || true
info "IPsec config reloaded."

# If charon isn't running at all, start it
if ! pgrep -x charon &>/dev/null; then
    if systemctl list-unit-files strongswan-starter.service &>/dev/null 2>&1; then
        systemctl enable strongswan-starter &>/dev/null
        systemctl start strongswan-starter || { error "strongswan-starter failed to start"; ((ERRORS++)); }
        info "strongswan-starter started."
    else
        systemctl enable strongswan &>/dev/null
        systemctl start strongswan || { error "strongswan failed to start"; ((ERRORS++)); }
        info "strongswan started."
    fi
    sleep 1
    ipsec reload 2>/dev/null || true
fi

# Verify IPsec loaded
sleep 1
if ipsec statusall 2>/dev/null | grep -q "l2tp-psk"; then
    info "IPsec conn l2tp-psk loaded successfully."
else
    warn "Could not verify l2tp-psk conn — check: ipsec statusall"
fi

###############################################################################
#  STEP 3: L2TP (xl2tpd) configuration
###############################################################################
step 3 "L2TP (xl2tpd)"

mkdir -p /etc/xl2tpd

cat > /etc/xl2tpd/xl2tpd.conf << XLEOF
[global]
port = 1701
access control = no

[lns default]
ip range = $L2TP_POOL_START-$L2TP_POOL_END
local ip = $L2TP_LOCAL_IP
require authentication = yes
name = l2tp-server
ppp debug = no
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
XLEOF
info "xl2tpd.conf written (pool: $L2TP_POOL_START–$L2TP_POOL_END, local: $L2TP_LOCAL_IP)."

###############################################################################
#  STEP 4: PPP + RADIUS configuration
###############################################################################
step 4 "PPP + RADIUS"

# ── PPP options ──
cat > /etc/ppp/options.xl2tpd << PPPEOF
require-mschap-v2
ms-dns $DNS1
ms-dns $DNS2
asyncmap 0
auth
idle 1800
mtu 1400
mru 1400
hide-password
nodefaultroute
logfile /var/log/ppp-l2tp.log
proxyarp
noaccomp
nopcomp
noccp
lcp-echo-failure 4
lcp-echo-interval 30
ipcp-accept-local
ipcp-accept-remote
PPPEOF

# ── Detect pppd version for plugin path ──
PPPD_VERSION=$(pppd --version 2>&1 | grep -oP '[\d.]+' | head -1 || echo "2.4.9")
RADIUS_PLUGIN_DIR="/usr/lib/pppd/$PPPD_VERSION"

# Check if radius.so exists
if [[ -f "$RADIUS_PLUGIN_DIR/radius.so" ]]; then
    info "RADIUS plugin found: $RADIUS_PLUGIN_DIR/radius.so"
    # Add RADIUS plugin to PPP options
    cat >> /etc/ppp/options.xl2tpd << RADPPPEOF

# RADIUS authentication
plugin $RADIUS_PLUGIN_DIR/radius.so
plugin $RADIUS_PLUGIN_DIR/radattr.so
radius-config-file /etc/ppp/radius/radiusclient.conf
RADPPPEOF
    info "PPP options written with RADIUS plugin."

    # ── RADIUS client config ──
    mkdir -p /etc/ppp/radius

    cat > /etc/ppp/radius/radiusclient.conf << RADCEOF
auth_order radius
login_tries 4
login_timeout 60
nologin /etc/nologin
issue /etc/radiusclient/issue
authserver $RADIUS_IP:$RADIUS_AUTH_PORT
acctserver $RADIUS_IP:$RADIUS_ACCT_PORT
servers /etc/ppp/radius/servers
dictionary /etc/ppp/radius/dictionary
login_radius /usr/sbin/login.radius
seqfile /var/run/radius.seq
mapfile /etc/ppp/radius/port-id-map
default_realm
radius_timeout 10
radius_retries 3
RADCEOF
    info "radiusclient.conf written."

    # ── RADIUS servers file ──
    cat > /etc/ppp/radius/servers << SRVEOF
$RADIUS_IP    $RADIUS_SECRET
SRVEOF
    chmod 600 /etc/ppp/radius/servers
    info "RADIUS servers file written ($RADIUS_IP)."

    # ── Dictionary ──
    # Always write our own dictionary — system dictionaries (radcli, radiusclient-ng)
    # use type names (ipv4addr, ipv6addr) and vendor formats that pppd's radius.so
    # doesn't understand.  The pppd plugin expects: string, ipaddr, integer, date
    # and Microsoft vendor attrs in "ATTRIBUTE name id type vendor" format.
    cat > /etc/ppp/radius/dictionary << 'DICTEOF'
#
# RADIUS dictionary for pppd radius.so plugin
# Only uses types understood by pppd: string, ipaddr, integer, date
#

# Standard RADIUS attributes (RFC 2865/2866)
ATTRIBUTE   User-Name               1   string
ATTRIBUTE   Password                2   string
ATTRIBUTE   CHAP-Password           3   string
ATTRIBUTE   NAS-IP-Address          4   ipaddr
ATTRIBUTE   NAS-Port-Id             5   integer
ATTRIBUTE   Service-Type            6   integer
ATTRIBUTE   Framed-Protocol         7   integer
ATTRIBUTE   Framed-IP-Address       8   ipaddr
ATTRIBUTE   Framed-IP-Netmask       9   ipaddr
ATTRIBUTE   Framed-Routing          10  integer
ATTRIBUTE   Filter-Id               11  string
ATTRIBUTE   Framed-MTU              12  integer
ATTRIBUTE   Framed-Compression      13  integer
ATTRIBUTE   Login-IP-Host           14  ipaddr
ATTRIBUTE   Login-Service           15  integer
ATTRIBUTE   Login-TCP-Port          16  integer
ATTRIBUTE   Reply-Message           18  string
ATTRIBUTE   Callback-Number         19  string
ATTRIBUTE   Callback-Id             20  string
ATTRIBUTE   Session-Timeout         27  integer
ATTRIBUTE   Idle-Timeout            28  integer
ATTRIBUTE   Termination-Action      29  integer
ATTRIBUTE   Called-Station-Id       30  string
ATTRIBUTE   Calling-Station-Id      31  string
ATTRIBUTE   NAS-Identifier          32  string
ATTRIBUTE   Proxy-State             33  string
ATTRIBUTE   Acct-Status-Type        40  integer
ATTRIBUTE   Acct-Delay-Time         41  integer
ATTRIBUTE   Acct-Input-Octets       42  integer
ATTRIBUTE   Acct-Output-Octets      43  integer
ATTRIBUTE   Acct-Session-Id         44  string
ATTRIBUTE   Acct-Authentic          45  integer
ATTRIBUTE   Acct-Session-Time       46  integer
ATTRIBUTE   Acct-Input-Packets      47  integer
ATTRIBUTE   Acct-Output-Packets     48  integer
ATTRIBUTE   Acct-Terminate-Cause    49  integer
ATTRIBUTE   NAS-Port-Type           61  integer
ATTRIBUTE   Port-Limit              62  integer
ATTRIBUTE   Connect-Info            77  string
ATTRIBUTE   Vendor-Specific         26  string

# Standard values
VALUE   Service-Type        Login-User          1
VALUE   Service-Type        Framed-User         2
VALUE   Framed-Protocol     PPP                 1
VALUE   Framed-Routing      None                0
VALUE   Framed-Compression  Van-Jacobson-TCP-IP 1
VALUE   Acct-Status-Type    Start               1
VALUE   Acct-Status-Type    Stop                2
VALUE   Acct-Status-Type    Alive               3
VALUE   Acct-Terminate-Cause User-Request       1
VALUE   NAS-Port-Type       Virtual             5
VALUE   NAS-Port-Type       Async               0

# Microsoft vendor-specific attributes (Vendor ID 311)
# Required for MS-CHAPv2 authentication
VENDOR      Microsoft       311     Microsoft

ATTRIBUTE   MS-CHAP-Response        1   string  Microsoft
ATTRIBUTE   MS-CHAP-Error           2   string  Microsoft
ATTRIBUTE   MS-CHAP-CPW-1           3   string  Microsoft
ATTRIBUTE   MS-CHAP-CPW-2           4   string  Microsoft
ATTRIBUTE   MS-CHAP-LM-Enc-PW      5   string  Microsoft
ATTRIBUTE   MS-CHAP-NT-Enc-PW      6   string  Microsoft
ATTRIBUTE   MS-MPPE-Encryption-Policy 7 string  Microsoft
ATTRIBUTE   MS-MPPE-Encryption-Type 8   string  Microsoft
ATTRIBUTE   MS-RAS-Vendor           9   integer Microsoft
ATTRIBUTE   MS-CHAP-Domain          10  string  Microsoft
ATTRIBUTE   MS-CHAP-Challenge       11  string  Microsoft
ATTRIBUTE   MS-CHAP-MPPE-Keys      12  string  Microsoft
ATTRIBUTE   MS-BAP-Usage            13  integer Microsoft
ATTRIBUTE   MS-Link-Utilization-Threshold 14 integer Microsoft
ATTRIBUTE   MS-Link-Drop-Time-Limit 15  integer Microsoft
ATTRIBUTE   MS-MPPE-Send-Key       16  string  Microsoft
ATTRIBUTE   MS-MPPE-Recv-Key       17  string  Microsoft
ATTRIBUTE   MS-RAS-Version          18  string  Microsoft
ATTRIBUTE   MS-Old-ARAP-Password   19  string  Microsoft
ATTRIBUTE   MS-New-ARAP-Password   20  string  Microsoft
ATTRIBUTE   MS-CHAP2-Response       25  string  Microsoft
ATTRIBUTE   MS-CHAP2-Success        26  string  Microsoft
ATTRIBUTE   MS-CHAP2-CPW           27  string  Microsoft
ATTRIBUTE   MS-Primary-DNS-Server   28  ipaddr  Microsoft
ATTRIBUTE   MS-Secondary-DNS-Server 29  ipaddr  Microsoft
ATTRIBUTE   MS-Primary-NBNS-Server  30  ipaddr  Microsoft
ATTRIBUTE   MS-Secondary-NBNS-Server 31 ipaddr  Microsoft
DICTEOF
    info "RADIUS dictionary written (with Microsoft MS-CHAPv2 vendor attributes)."

    # ── port-id-map ──
    if [[ ! -f /etc/ppp/radius/port-id-map ]]; then
        touch /etc/ppp/radius/port-id-map
    fi

else
    warn "radius.so not found at $RADIUS_PLUGIN_DIR/radius.so"
    warn "PPP options written WITHOUT RADIUS — using local chap-secrets instead."
    info "Add users to /etc/ppp/chap-secrets: username * password *"
    # Create empty chap-secrets if not present
    if [[ ! -f /etc/ppp/chap-secrets ]]; then
        cat > /etc/ppp/chap-secrets << 'CHAPEOF'
# Secrets for authentication using CHAP
# client    server    secret    IP addresses
CHAPEOF
        chmod 600 /etc/ppp/chap-secrets
    fi
fi

###############################################################################
#  STEP 5: Networking (forwarding + NAT)
###############################################################################
step 5 "Networking (forwarding + NAT)"

# Ensure IP forwarding
if [[ $(cat /proc/sys/net/ipv4/ip_forward) -ne 1 ]]; then
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-vpn.conf
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    info "IP forwarding enabled."
else
    info "IP forwarding already enabled."
fi

# Also disable ICMP redirects (important for L2TP)
for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > "$f"; done
for f in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > "$f"; done
cat > /etc/sysctl.d/99-l2tp.conf << 'SYSEOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
SYSEOF
sysctl -p /etc/sysctl.d/99-l2tp.conf >/dev/null 2>&1
info "ICMP redirects disabled (required for L2TP)."

# Open IPsec + L2TP ports
for port_proto in "500:udp" "4500:udp" "1701:udp"; do
    port="${port_proto%%:*}"
    proto="${port_proto##*:}"
    if ! iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT &>/dev/null; then
        iptables -A INPUT -p "$proto" --dport "$port" -j ACCEPT
        info "Opened $proto port $port"
    fi
done

# Allow ESP protocol (IPsec)
if ! iptables -C INPUT -p esp -j ACCEPT &>/dev/null; then
    iptables -A INPUT -p esp -j ACCEPT
    info "Allowed ESP protocol"
fi

# NAT for L2TP subnet
if ! iptables -t nat -C POSTROUTING -s "$L2TP_SUBNET" -o "$IFACE" -j MASQUERADE &>/dev/null; then
    iptables -t nat -A POSTROUTING -s "$L2TP_SUBNET" -o "$IFACE" -j MASQUERADE
    info "NAT rule added for $L2TP_SUBNET"
fi

# FORWARD rules for ppp+ interfaces (L2TP creates ppp0, ppp1, etc.)
if ! iptables -C FORWARD -i ppp+ -j ACCEPT &>/dev/null; then
    iptables -I FORWARD -i ppp+ -j ACCEPT
    info "FORWARD rule added for ppp+ (inbound)"
fi
if ! iptables -C FORWARD -o ppp+ -j ACCEPT &>/dev/null; then
    iptables -I FORWARD -o ppp+ -j ACCEPT
    info "FORWARD rule added for ppp+ (outbound)"
fi

# Save firewall rules
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save &>/dev/null
    info "Firewall rules saved (netfilter-persistent)."
elif command -v iptables-save &>/dev/null; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    info "Firewall rules saved (iptables-save)."
else
    warn "Could not persist firewall rules. Rules are active but will be lost on reboot."
fi

###############################################################################
#  STEP 6: Online monitoring (optional — requires deploy.sh)
###############################################################################
step 6 "Online monitoring"

# ── PPP ip-up hook for session tracking ──
# When pppd assigns an IP, this hook writes username + metadata to a JSON cache
# that l2tp_online.py and sync_online.py read.
cat > /etc/ppp/ip-up.d/l2tp-session << 'HOOKEOF'
#!/usr/bin/env python3
"""PPP ip-up hook: write L2TP session info to /var/run/l2tp-sessions.json"""
import json, os, re, subprocess, sys

iface = sys.argv[1] if len(sys.argv) > 1 else ""
if not iface.startswith("ppp"):
    sys.exit(0)

local_ip = sys.argv[4] if len(sys.argv) > 4 else ""
remote_ip = sys.argv[5] if len(sys.argv) > 5 else ""
username = os.environ.get("PEERNAME", "")

# Get pppd PID from pidfile (not getppid — may be intermediate shell)
pppd_pid = ""
try:
    with open(f"/var/run/{iface}.pid") as f:
        pppd_pid = f.read().strip()
except Exception:
    pass

# Get tunnel_id from pppd's cmdline
tunnel_id = ""
if pppd_pid:
    try:
        with open(f"/proc/{pppd_pid}/cmdline", "rb") as f:
            args = f.read().decode("utf-8", errors="replace").split("\x00")
        for i, arg in enumerate(args):
            if arg == "pppol2tp_tunnel_id" and i + 1 < len(args):
                tunnel_id = args[i + 1]
                break
    except Exception:
        pass

# Look up client real IP from L2TP tunnel
real_ip = ""
if tunnel_id:
    try:
        out = subprocess.run(["ip", "l2tp", "show", "tunnel"],
                             capture_output=True, text=True, timeout=3).stdout
        tid = None
        for line in out.split("\n"):
            m = re.match(r"Tunnel\s+(\d+)", line)
            if m:
                tid = m.group(1)
            elif tid == tunnel_id:
                m = re.search(r"to\s+(\S+)", line)
                if m:
                    real_ip = m.group(1)
                    break
    except Exception:
        pass

# Read existing cache
cache_path = "/var/run/l2tp-sessions.json"
data = {}
if os.path.exists(cache_path):
    try:
        with open(cache_path) as f:
            data = json.load(f)
    except Exception:
        pass

# Update and write
data[iface] = {
    "username": username,
    "pid": int(pppd_pid) if pppd_pid else 0,
    "local_ip": local_ip,
    "remote_ip": remote_ip,
    "real_ip": real_ip,
}
with open(cache_path, "w") as f:
    json.dump(data, f)
HOOKEOF
chmod +x /etc/ppp/ip-up.d/l2tp-session
info "PPP ip-up hook installed (session tracking)."

# ── PPP ip-down hook to clean up session cache ──
cat > /etc/ppp/ip-down.d/l2tp-session << 'HOOKEOF'
#!/usr/bin/env python3
"""PPP ip-down hook: remove L2TP session from /var/run/l2tp-sessions.json"""
import json, os, sys

iface = sys.argv[1] if len(sys.argv) > 1 else ""
if not iface.startswith("ppp"):
    sys.exit(0)

cache_path = "/var/run/l2tp-sessions.json"
if not os.path.exists(cache_path):
    sys.exit(0)

try:
    with open(cache_path) as f:
        data = json.load(f)
    data.pop(iface, None)
    with open(cache_path, "w") as f:
        json.dump(data, f)
except Exception:
    pass
HOOKEOF
chmod +x /etc/ppp/ip-down.d/l2tp-session
info "PPP ip-down hook installed (session cleanup)."

# ── Install online scripts (only if vroute.conf exists) ──
if [[ -f /opt/vroute.conf ]]; then
    # Check/add L2TP server_id to vroute.conf
    L2TP_ID=$(python3 -c "
import json
c = json.load(open('/opt/vroute.conf'))
print(c.get('server_ids', {}).get('L2TP', ''))
" 2>/dev/null || true)

    if [[ -z "$L2TP_ID" ]]; then
        SERVER_NAME=$(python3 -c "import json; print(json.load(open('/opt/vroute.conf'))['server_name'])" 2>/dev/null || echo "")
        SERVER_NUM=$(echo "$SERVER_NAME" | grep -oP '\d+$' || true)
        if [[ -n "$SERVER_NUM" ]]; then
            L2TP_ID=$((400 + SERVER_NUM - 2))
        else
            L2TP_ID=401
        fi
        python3 << PYEOF
import json
with open("/opt/vroute.conf") as f:
    c = json.load(f)
c["server_ids"]["L2TP"] = $L2TP_ID
with open("/opt/vroute.conf", "w") as f:
    json.dump(c, f, indent=4)
print("Updated /opt/vroute.conf with L2TP server_id=$L2TP_ID")
PYEOF
        info "L2TP server_id=$L2TP_ID added to vroute.conf"
    else
        info "L2TP already in vroute.conf (id=$L2TP_ID)"
    fi

    # Install l2tp_online.py
    if [[ -f "$SCRIPT_DIR/l2tp_online.py" ]]; then
        cp "$SCRIPT_DIR/l2tp_online.py" /opt/l2tp_online.py
        chmod +x /opt/l2tp_online.py
        info "Installed /opt/l2tp_online.py"
    else
        warn "l2tp_online.py not found in package — skipping."
    fi

    # Update sync_online.py
    if [[ -f "$SCRIPT_DIR/sync_online.py" ]]; then
        cp "$SCRIPT_DIR/sync_online.py" /opt/sync_online.py
        chmod +x /opt/sync_online.py
        info "Updated /opt/sync_online.py"
        # Restart sync-online service if running
        if systemctl is-active --quiet sync-online 2>/dev/null; then
            systemctl restart sync-online
            info "sync-online service restarted."
        fi
    else
        warn "sync_online.py not found in package — skipping."
    fi
else
    info "No /opt/vroute.conf — skipping online monitoring setup."
    info "Run deploy.sh first if you want DB sync + online monitoring."
fi

###############################################################################
#  STEP 7: Start services
###############################################################################
step 7 "Start services"

# ── strongSwan (reload only — don't restart, IKEv2 sessions stay alive) ──
if systemctl list-unit-files strongswan-starter.service &>/dev/null 2>&1; then
    IPSEC_SVC="strongswan-starter"
else
    IPSEC_SVC="strongswan"
fi

systemctl enable "$IPSEC_SVC" &>/dev/null
ipsec reload 2>/dev/null || true
info "IPsec config reloaded (existing sessions preserved)."

# ── xl2tpd ──
systemctl enable xl2tpd &>/dev/null
if systemctl is-active --quiet xl2tpd; then
    systemctl restart xl2tpd
    info "xl2tpd restarted."
else
    systemctl start xl2tpd || { error "xl2tpd failed — check: journalctl -u xl2tpd"; ((ERRORS++)); }
    info "xl2tpd started."
fi

# Verify
sleep 2
if ipsec statusall 2>/dev/null | grep -q "l2tp-psk"; then
    info "IPsec: l2tp-psk connection loaded."
else
    error "IPsec: l2tp-psk NOT loaded. Check: ipsec statusall"
    ((ERRORS++))
fi

if systemctl is-active --quiet xl2tpd; then
    info "xl2tpd is running."
else
    error "xl2tpd is NOT running. Check: journalctl -u xl2tpd -n 50"
    ((ERRORS++))
fi

###############################################################################
#  DONE
###############################################################################
echo ""
echo "============================================================"
if [[ $ERRORS -eq 0 ]]; then
    info "L2TP/IPsec deploy complete! (0 errors)"
else
    warn "L2TP/IPsec deploy complete with $ERRORS error(s)"
fi
echo "============================================================"
echo ""
echo "  IPsec:         PSK (IKEv1 transport mode)"
echo "  L2TP:          xl2tpd on port 1701"
echo "  RADIUS:        $RADIUS_IP:$RADIUS_AUTH_PORT"
echo "  Interface:     $IFACE"
echo "  Server IP:     $SERVER_IP"
echo "  VPN subnet:    $L2TP_SUBNET"
echo "  Client pool:   $L2TP_POOL_START – $L2TP_POOL_END"
echo "  DNS:           $DNS1, $DNS2"
echo ""
echo "  Client setup:"
echo "    Type:        L2TP/IPsec PSK"
echo "    Server:      $SERVER_IP"
echo "    PSK:         $IPSEC_PSK"
echo "    Auth:        username + password (RADIUS)"
echo ""
echo "  Logs:"
echo "    journalctl -u $IPSEC_SVC -f        # IPsec log"
echo "    journalctl -u xl2tpd -f             # L2TP log"
echo "    tail -f /var/log/ppp-l2tp.log       # PPP log"
echo ""
echo "  Services:"
echo "    systemctl status $IPSEC_SVC"
echo "    systemctl status xl2tpd"
echo "    ipsec statusall                     # IPsec connections"
echo ""
echo "  Online users:"
echo "    python3 /opt/l2tp_online.py              # L2TP online users"
echo "    python3 /opt/l2tp_online.py -s username   # Sort by username"
echo "============================================================"

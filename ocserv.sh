#!/bin/bash
###############################################################################
#  VRoute ocserv (Cisco AnyConnect / OpenConnect) Deploy
#
#  Usage:  bash ocserv.sh
#
#  Installs and configures:
#    - ocserv (10.5.0.0/16, port 443 TCP+UDP/DTLS)
#    - Let's Encrypt certificate (reuses IKEv2 cert if available)
#    - RADIUS authentication via radcli
#    - NAT + forwarding rules
#    - ocserv_online.py monitoring script
#    - Updates vroute.conf with OCSERV server_id
#
#  Requires: deploy.sh must be run first (/opt/vroute.conf must exist)
#  Safe to re-run: skips completed steps.
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

SERVER_NAME=$(python3 -c "import json; print(json.load(open('/opt/vroute.conf'))['server_name'])")
info "Server: $SERVER_NAME | Interface: $IFACE"

ERRORS=0

###############################################################################
#  STEP 1: Domain + OCSERV server_id
###############################################################################
step 1 "ocserv configuration"

# Check if OCSERV already configured in vroute.conf
OCSERV_ID=$(python3 -c "
import json
c = json.load(open('/opt/vroute.conf'))
print(c.get('server_ids', {}).get('OCSERV', ''))
" 2>/dev/null || true)

OCSERV_DOMAIN=$(python3 -c "
import json
c = json.load(open('/opt/vroute.conf'))
print(c.get('ocserv_domain', ''))
" 2>/dev/null || true)

if [[ -n "$OCSERV_ID" && -n "$OCSERV_DOMAIN" ]]; then
    info "ocserv already configured: id=$OCSERV_ID domain=$OCSERV_DOMAIN"
    read -rp "Re-configure? [y/N]: " RECONF
    if [[ "$RECONF" != "y" && "$RECONF" != "Y" ]]; then
        info "Keeping existing config."
    else
        OCSERV_ID=""
        OCSERV_DOMAIN=""
    fi
fi

if [[ -z "$OCSERV_ID" || -z "$OCSERV_DOMAIN" ]]; then
    # Try to default to existing IKEv2 domain
    EXISTING_DOMAIN=$(python3 -c "
import json
c = json.load(open('/opt/vroute.conf'))
print(c.get('ikev2_domain', ''))
" 2>/dev/null || true)

    echo ""
    if [[ -n "$EXISTING_DOMAIN" ]]; then
        echo "  IKEv2 domain found: $EXISTING_DOMAIN"
        read -rp "Use same domain for ocserv? [Y/n]: " USE_EXISTING
        if [[ "$USE_EXISTING" == "n" || "$USE_EXISTING" == "N" ]]; then
            read -rp "Domain for ocserv (e.g. vs14.vroute.org): " OCSERV_DOMAIN
        else
            OCSERV_DOMAIN="$EXISTING_DOMAIN"
        fi
    else
        read -rp "Domain for this server (e.g. vs14.vroute.org): " OCSERV_DOMAIN
    fi
    [[ -z "$OCSERV_DOMAIN" ]] && fatal "Domain cannot be empty"

    # Auto-generate ID
    SERVER_NUM=$(echo "$SERVER_NAME" | grep -oP '\d+$' || true)
    if [[ -n "$SERVER_NUM" ]]; then
        DEFAULT_OCSERV=$((300 + SERVER_NUM - 2))
        echo "  Auto-generated ocserv server_id: $DEFAULT_OCSERV"
        read -rp "Use this ID? [Y/n]: " USE_DEFAULT
        if [[ "$USE_DEFAULT" == "n" || "$USE_DEFAULT" == "N" ]]; then
            read -rp "  ocserv server_id: " OCSERV_ID
        else
            OCSERV_ID=$DEFAULT_OCSERV
        fi
    else
        read -rp "  ocserv server_id: " OCSERV_ID
    fi

    [[ -z "$OCSERV_ID" ]] && fatal "Server ID cannot be empty"

    # Update vroute.conf — add OCSERV server_id and domain
    python3 << PYEOF
import json

with open("/opt/vroute.conf") as f:
    c = json.load(f)

c["server_ids"]["OCSERV"] = $OCSERV_ID
c["ocserv_domain"] = "$OCSERV_DOMAIN"

with open("/opt/vroute.conf", "w") as f:
    json.dump(c, f, indent=4)

print("Updated /opt/vroute.conf")
PYEOF

    info "Config updated: OCSERV id=$OCSERV_ID, domain=$OCSERV_DOMAIN"
fi

###############################################################################
#  STEP 2: Install packages
###############################################################################
step 2 "Packages"

NEED_INSTALL=0
for pkg in ocserv libradcli4 certbot; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        NEED_INSTALL=1
        break
    fi
done

if [[ $NEED_INSTALL -eq 1 ]]; then
    info "Installing ocserv + radcli + certbot..."
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    apt update -qq
    apt install -y ocserv libradcli4 certbot || {
        error "Package install failed"; ((ERRORS++))
    }
else
    info "All packages already installed."
fi

###############################################################################
#  STEP 3: Let's Encrypt certificate
###############################################################################
step 3 "Let's Encrypt certificate"

CERT_DIR="/etc/letsencrypt/live/$OCSERV_DOMAIN"

if [[ -d "$CERT_DIR" ]]; then
    info "Certificate already exists for $OCSERV_DOMAIN (reusing from IKEv2 or previous run)"
else
    info "Requesting Let's Encrypt certificate for $OCSERV_DOMAIN..."
    info "NOTE: Port 80 must be free for HTTP validation."

    certbot certonly --standalone -d "$OCSERV_DOMAIN" \
        --key-type rsa --rsa-key-size 2048 \
        --non-interactive --agree-tos --register-unsafely-without-email || {
        error "Certbot failed — ensure DNS A record points to this server and port 80 is free"
        ((ERRORS++))
    }
fi

###############################################################################
#  STEP 4: Configure radcli for RADIUS
###############################################################################
step 4 "RADIUS (radcli) configuration"

mkdir -p /etc/radcli

# radiusclient.conf
cat > /etc/radcli/radiusclient.conf << 'RADCLIEOF'
# radcli configuration for ocserv RADIUS auth
nas-identifier ocserv
authserver 185.141.168.2:1812
acctserver 185.141.168.2:1813
servers /etc/radcli/servers
dictionary /etc/radcli/dictionary
default_realm
radius_timeout 10
radius_retries 3
bindaddr *
RADCLIEOF
info "radcli config written."

# RADIUS server secret
cat > /etc/radcli/servers << 'SRVEOF'
185.141.168.2    11041104
SRVEOF
chmod 600 /etc/radcli/servers
info "radcli servers written."

# Ensure dictionary exists (symlink from radcli package)
if [[ ! -f /etc/radcli/dictionary ]]; then
    if [[ -f /usr/share/radcli/dictionary ]]; then
        ln -sf /usr/share/radcli/dictionary /etc/radcli/dictionary
        info "Symlinked dictionary."
    elif [[ -f /usr/share/freeradius/dictionary ]]; then
        ln -sf /usr/share/freeradius/dictionary /etc/radcli/dictionary
        info "Symlinked dictionary (freeradius)."
    else
        warn "No dictionary found — RADIUS may fail. Check radcli package."
    fi
else
    info "Dictionary already exists."
fi

###############################################################################
#  STEP 5: ocserv configuration
###############################################################################
step 5 "ocserv configuration"

cat > /etc/ocserv/ocserv.conf << OCEOF
# VRoute ocserv configuration
# Generated by ocserv.sh — $(date)

# Authentication via RADIUS
auth = "radius[config=/etc/radcli/radiusclient.conf,groupconfig=true]"

# Socket file for IPC (worker-main), will be appended with .PID
socket-file = /var/run/ocserv-socket

# Enable occtl control tool
use-occtl = true
pid-file = /var/run/ocserv.pid

# TCP and UDP (DTLS) on port 443
tcp-port = 443
udp-port = 443

# TLS certificate (Let's Encrypt)
server-cert = /etc/letsencrypt/live/$OCSERV_DOMAIN/fullchain.pem
server-key = /etc/letsencrypt/live/$OCSERV_DOMAIN/privkey.pem

# VPN subnet
ipv4-network = 10.5.0.0
ipv4-netmask = 255.255.0.0

# DNS
dns = 8.8.8.8
dns = 8.8.4.4

# Routing — push default route to clients
route = default

# Device prefix — creates vpns0, vpns1, etc.
device = vpns

# Limits
max-clients = 0
max-same-clients = 4

# Keepalive
keepalive = 300
dpd = 90
mobile-dpd = 1800

# Timeouts
cookie-timeout = 300
rekey-time = 172800

# Compression
compression = true

# Cisco AnyConnect compatibility
cisco-client-compat = true
dtls-legacy = true

# Logging
log-level = 1

# Try to be compatible with all clients
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-RSA:-VERS-SSL3.0:-ARCFOUR-128"

# Run as root (needed for tun/vpns device management + socket creation)
# Isolation is handled by systemd
OCEOF

info "ocserv.conf written."

###############################################################################
#  STEP 6: Certificate renewal hook
###############################################################################
step 6 "Certificate renewal hook"

mkdir -p /etc/letsencrypt/renewal-hooks/deploy

cat > /etc/letsencrypt/renewal-hooks/deploy/ocserv.sh << 'HOOKEOF'
#!/bin/bash
# Restart ocserv after Let's Encrypt renewal
systemctl restart ocserv 2>/dev/null || true
echo "[ocserv-hook] ocserv restarted after cert renewal"
HOOKEOF

chmod +x /etc/letsencrypt/renewal-hooks/deploy/ocserv.sh
info "Renewal hook installed — ocserv will restart on cert renewal."

###############################################################################
#  STEP 7: IP forwarding + NAT
###############################################################################
step 7 "Networking (forwarding + NAT)"

# Ensure IP forwarding
if [[ $(cat /proc/sys/net/ipv4/ip_forward) -ne 1 ]]; then
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-vpn.conf
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    info "IP forwarding enabled."
else
    info "IP forwarding already enabled."
fi

# NOTE: Mark-based tunnel routing is handled by IN.sh.
# Make sure 10.5.0.0/16 is in SOURCE_RANGES in IN.sh.

# Allow port 443 TCP + UDP
if ! iptables -C INPUT -p tcp --dport 443 -j ACCEPT &>/dev/null; then
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    info "Opened TCP port 443"
fi
if ! iptables -C INPUT -p udp --dport 443 -j ACCEPT &>/dev/null; then
    iptables -A INPUT -p udp --dport 443 -j ACCEPT
    info "Opened UDP port 443"
fi

# NAT for ocserv subnet
if ! iptables -t nat -C POSTROUTING -s 10.5.0.0/16 -o "$IFACE" -j MASQUERADE &>/dev/null; then
    iptables -t nat -A POSTROUTING -s 10.5.0.0/16 -o "$IFACE" -j MASQUERADE
    info "NAT rule added for 10.5.0.0/16"
fi

# FORWARD rules for vpns+ interfaces
if ! iptables -C FORWARD -i vpns+ -j ACCEPT &>/dev/null; then
    iptables -A FORWARD -i vpns+ -j ACCEPT
    info "FORWARD rule added for vpns+ (inbound)"
fi
if ! iptables -C FORWARD -o vpns+ -j ACCEPT &>/dev/null; then
    iptables -A FORWARD -o vpns+ -j ACCEPT
    info "FORWARD rule added for vpns+ (outbound)"
fi

netfilter-persistent save &>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null
info "Firewall rules saved."

echo ""
warn "REMINDER: Add 10.5.0.0/16 to SOURCE_RANGES in IN.sh on this server!"
echo ""

###############################################################################
#  STEP 8: Deploy monitoring scripts
###############################################################################
step 8 "Monitoring scripts"

if [[ -f "$SCRIPT_DIR/ocserv_online.py" ]]; then
    cp "$SCRIPT_DIR/ocserv_online.py" /opt/ocserv_online.py
    chmod +x /opt/ocserv_online.py
    info "Installed /opt/ocserv_online.py"
else
    warn "ocserv_online.py not found in package — skipping."
fi

if [[ -f "$SCRIPT_DIR/sync_online.py" ]]; then
    cp "$SCRIPT_DIR/sync_online.py" /opt/sync_online.py
    chmod +x /opt/sync_online.py
    info "Updated /opt/sync_online.py"

    # Restart sync-online service if running
    if systemctl is-active --quiet sync-online 2>/dev/null; then
        systemctl restart sync-online
        info "Restarted sync-online service."
    fi
else
    warn "sync_online.py not found in package — skipping."
fi

###############################################################################
#  STEP 9: Start ocserv
###############################################################################
step 9 "Start ocserv"

systemctl enable ocserv &>/dev/null
systemctl restart ocserv || { error "ocserv failed to start"; ((ERRORS++)); }

# Verify
sleep 2
if systemctl is-active --quiet ocserv; then
    info "ocserv is running."
else
    error "ocserv is NOT running. Check: journalctl -u ocserv -n 50"
    ((ERRORS++))
fi

###############################################################################
#  DONE
###############################################################################
echo ""
echo "============================================================"
if [[ $ERRORS -eq 0 ]]; then
    info "ocserv deploy complete! (0 errors)"
else
    warn "ocserv deploy complete with $ERRORS error(s)"
fi
echo "============================================================"
echo ""
echo "  Server:        $SERVER_NAME"
echo "  Domain:        $OCSERV_DOMAIN"
echo "  ocserv:        10.5.0.0/16 — port 443 TCP+UDP/DTLS"
echo "  RADIUS:        185.141.168.2:1812"
echo "  Certificate:   Let's Encrypt (auto-renews)"
echo "  Interface:     $IFACE"
echo ""
echo "  Client setup (Cisco AnyConnect):"
echo "    Server:      $OCSERV_DOMAIN:443"
echo "    Auth:        Username + Password"
echo ""
echo "  Client setup (OpenConnect CLI):"
echo "    openconnect $OCSERV_DOMAIN:443"
echo "    # Enter username + password when prompted"
echo ""
echo "  Client setup (iOS/Android AnyConnect app):"
echo "    Add connection → Server: $OCSERV_DOMAIN"
echo "    Auth: Username + Password"
echo ""
echo "  Monitoring:"
echo "    python3 /opt/ocserv_online.py              # ocserv online users"
echo "    python3 /opt/ocserv_online.py -s username   # Sort by username"
echo "    occtl show users                            # Active sessions"
echo "    occtl --json show users                     # JSON output"
echo ""
echo "  Logs:"
echo "    journalctl -u ocserv -f                     # ocserv log"
echo ""
echo "  Certificate renewal:"
echo "    certbot renew --dry-run                     # Test renewal"
echo "    # ocserv restarts automatically via deploy hook"
echo ""
echo "  IMPORTANT:"
echo "    Add 10.5.0.0/16 to SOURCE_RANGES in IN.sh!"
echo "============================================================"
